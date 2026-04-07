const operators = {
  "==": (a, b) => a == b,
  "!=": (a, b) => a != b,
  ">=": (a, b) => a >= b,
  ">": (a, b) => a > b,
  "<=": (a, b) => a <= b,
  "<": (a, b) => a < b,
};

const compare = (a, b, op) => (operators[op] || operators["=="])(a, b);

const getPacketKey = (p) => {
  const hostKey = Object.keys(p.Host)[0];
  const packet = p.Host[hostKey][0];
  return `${hostKey}-${packet["Packet Info"]["Packet Processed"]}`;
};

const unionBy = (arr, keyFn) => {
  const map = new Map();
  for (const item of arr) map.set(keyFn(item), item);
  return [...map.values()];
};

const intersectBy = (a, b, keyFn) => {
  const setB = new Set(b.map(keyFn));
  return a.filter((item) => setB.has(keyFn(item)));
};

function getDataType(data) {
  const isIPv4 = (ip) =>
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(
      ip,
    );
  const isHex = (str) => /^0x[0-9a-fA-F]+$/.test(str);
  const isMAC = (str) => /^([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}$/.test(str);
  if (isIPv4(data)) return "IP";
  if (isHex(data)) return "HEX";
  if (isMAC(data)) return "MAC";
  if (Number.isInteger(data)) return "INT";
  if (typeof data === "number") return "FLOAT";
  if (typeof data === "string" && /^[\x00-\x7F]*$/.test(data)) return "ASCII";
  return "BIN";
}

function searchFullKey(obj, targetKey) {
  for (const key in obj) {
    if (key === targetKey) return obj[key];
    const val = obj[key];
    if (val && typeof val === "object") {
      const res = searchFullKey(val, targetKey);
      if (res !== undefined) return res;
    }
  }
}

function getLeafKeys(obj) {
  const result = [];
  const walk = (o) => {
    for (const key in o) {
      const val = o[key];

      if (val && typeof val === "object" && !Array.isArray(val)) {
        walk(val);
      } else {
        result.push({
          [key]: key.toLowerCase().replace(/ /g, "-"),
          type: getDataType(val),
        });
      }
    }
  };

  walk(obj);
  return result;
}

function filterChunk(data, filter) {
  const hosts = typeof data === "string" ? JSON.parse(data) : data;
  const results = [];
  const modifiers = [">=", "<=", ">", "<", "==", "!="];

  for (const host in hosts.Host) {
    const packets = hosts.Host[host];
    const sample = packets[0];
    const leafKeys = getLeafKeys(sample);
    const keys = leafKeys.map((k) => Object.values(k)[0]);
    const rawKeys = leafKeys.map((k) => Object.keys(k)[0]);
    if (!filter || !filter.includes(":")) continue;
    const [key, valRaw] = filter.split(":").map((s) => s.trim());
    if (!keys.includes(key)) continue;
    const mod = modifiers.find((m) => valRaw.includes(m));
    const val = valRaw.replace(mod, "").trim();
    for (const packet of packets) {
      const packetVal = searchFullKey(packet, rawKeys[keys.indexOf(key)]);
      if (packetVal === undefined) continue;
      if (mod && compare(packetVal, val, mod)) {
        results.push({ Host: { [host]: [packet] } });
        continue;
      } else {
        if (compare(packetVal, val, "==")) {
          results.push({ Host: { [host]: [packet] } });
        }
      }
      const type = getDataType(packetVal);
      if (["ASCII", "HEX", "IP", "MAC"].includes(type)) {
        if (String(packetVal).toLowerCase() === val.toLowerCase()) {
          results.push({ Host: { [host]: [packet] } });
        }
      }
    }
  }
  return results;
}

function tokenizeQuery(query) {
  const tokens = [];
  let i = 0;
  while (i < query.length) {
    if (/\s/.test(query[i])) { i++; continue; }
    if (query[i] === "(") { tokens.push({ type: "LPAREN" }); i++; continue; }
    if (query[i] === ")") { tokens.push({ type: "RPAREN" }); i++; continue; }
    if (query.startsWith("||", i)) { tokens.push({ type: "OR" }); i += 2; continue; }
    if (query.startsWith("&&", i)) { tokens.push({ type: "AND" }); i += 2; continue; }
    let j = i;
    while (
      j < query.length &&
      !query.startsWith("||", j) &&
      !query.startsWith("&&", j) &&
      query[j] !== "(" &&
      query[j] !== ")"
    ) {
      j++;
    }
    const expr = query.slice(i, j).trim();
    if (expr) tokens.push({ type: "EXPR", value: expr });
    i = j;
  }
  return tokens;
}

function runQuery(data, query) {
  const tokens = tokenizeQuery(query);
  let pos = 0;

  function peek() { return tokens[pos]; }
  function consume(type) {
    const tok = tokens[pos];
    if (type && (!tok || tok.type !== type)) {
      throw new Error(`Expected ${type} but got ${tok ? tok.type : "EOF"}`);
    }
    pos++;
    return tok;
  }

  function parseOr() {
    let result = parseAnd();
    while (peek() && peek().type === "OR") {
      consume("OR");
      const right = parseAnd();
      result = unionBy([...result, ...right], getPacketKey);
    }
    return result;
  }

  function parseAnd() {
    let result = parseTerm();
    while (peek() && peek().type === "AND") {
      consume("AND");
      const right = parseTerm();
      result = intersectBy(result, right, getPacketKey);
    }
    return result;
  }

  function parseTerm() {
    const tok = peek();
    if (tok && tok.type === "LPAREN") {
      consume("LPAREN");
      const result = parseOr();
      consume("RPAREN");
      return result;
    }
    if (tok && tok.type === "EXPR") {
      consume("EXPR");
      return filterChunk(data, tok.value);
    }
    return [];
  }

  return parseOr();
}

function filterPackets(data, query) {
  let results;
  if (query.trim() === "") {
    // dummy funtion so we can return all packets in the right format
    results = runQuery(data, "wire-length:>=0"); // dummy filter that matches all packets
  } else {
    results = runQuery(data, query);
  }

  return results.map((p) => {
    const hostKey = Object.keys(p.Host)[0];
    return p.Host[hostKey][0];
  });
}

module.exports = { filterPackets };
