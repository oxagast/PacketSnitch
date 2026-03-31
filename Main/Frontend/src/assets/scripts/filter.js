function getLeafKeys(obj) {
  const result = [];
  function recurse(current) {
    for (const key in current) {
      const value = current[key];
      if (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
      ) {
        recurse(value);
      } else {
        const uKey = key.toLowerCase().replace(/ /g, "-");
        result.push({ [key]: uKey, ["type"]: getDataType(value) });
      }
    }
  }
  recurse(obj);
  return result;
}

function searchFullKey(obj, targetKey) {
  for (const key in obj) {
    const value = obj[key];

    if (key === targetKey) {
      return value;
    }

    if (value !== null && typeof value === "object") {
      const result = searchFullKey(value, targetKey);
      if (result !== undefined) return result;
    }
  }
}

function getDataType(data) {
  function isIPv4(ip) {
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    return ipv4Regex.test(ip);
  }
  function isHexIdentifier(str) {
    const hexRegex = /^0x[0-9a-fA-F]+$/;
    return hexRegex.test(str);
  }
  function isValidMAC(address) {
    const macRegex = /^([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}$/;
    return macRegex.test(address);
  }
  function isFloat(value) {
    return (
      typeof value === "number" &&
      !Number.isNaN(value) &&
      !Number.isInteger(value)
    );
  }
  function isInteger(value) {
    return Number.isInteger(value);
  }
  function isASCII(str) {
    return typeof str === "string" && /^[\x00-\x7F]*$/.test(str);
  }
  if (isIPv4(data)) {
    return "IP";
  }
  if (isHexIdentifier(data)) {
    return "HEX";
  }
  if (isValidMAC(data)) {
    return "MAC";
  }
  if (isFloat(data)) {
    return "FLOAT";
  }
  if (isInteger(data)) {
    return "INT";
  }
  if (isASCII(data)) {
    return "ASCII";
  } else {
    ("BIN");
  }
}

function filterPackets(packets, filter) {
  let hosts = JSON.parse(packets);
  let filteredPackets = [];
  for (const host in hosts["Host"]) {
    hostJson = hosts["Host"][host];
  }
  const filterKeys = getLeafKeys(hostJson);
  const keys = filterKeys.map((k) => Object.values(k)[0]);
  const uKeys = filterKeys.map((k) => Object.keys(k)[0]);
  console.log("Available filter keys:", keys, ":", uKeys);
  // leafs = getLeafKeys(hostkeys);
  //  console.log("Leaf keys in packets:", leafs[-1]);
  // need to lopp over each host in json data then get all leaf keys
  if (filter) {
    if (filter.includes(":")) {
      for (host in hosts["Host"]) {
        const [key, val] = filter.split(":").map((s) => s.trim());
        if (key != "" && val != "") {
          if (keys.includes(key)) {
            for (const packet in hosts["Host"][host]) {
              const packetVal = searchFullKey(
                hosts["Host"][host],
                uKeys[keys.indexOf(key)],
              );
              if (getDataType(packetVal) === "INT") {
                // change str to int
                fvalue = parseInt(val);
                cvalue = parseInt(packetVal);
              }
              if (getDataType(packetVal) === "FLOAT") {
                cvalue = parseFloat(packetVal);
                fvalue = parseFloat(val);
              }
              if (
                getDataType(packetVal) === "IP" ||
                getDataType(packetVal) === "MAC" ||
                getDataType(packetVal) === "HEX" ||
                getDataType(packetVal) === "ASCII"
              ) {
                cvalue = packetVal.toString().toLowerCase();
                fvalue = val.toString().toLowerCase();
              } else cvalue = packetVal;
              if (cvalue && fvalue) {
                if (cvalue === fvalue) {
                  console.log(`Filtering packets by ${key}:${cvalue}`);
                  filteredPackets.push(hosts["Host"][host]);
                }
              }
            }
          }
        } else {
          console.log(`Invalid filter key: ${key}`);
        }
      }
    }
  }
  console.log(`Filtered packets: ${filteredPackets.length}`);
  return filteredPackets;
}
module.exports = { filterPackets };
