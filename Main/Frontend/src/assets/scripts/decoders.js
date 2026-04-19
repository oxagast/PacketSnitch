// Protocol decoder render functions for the info panel side tables.
// Each function reads the relevant sub-object from transportData and appends
// a table to the "sidedatatable" container (or no-ops when the data is absent).

function createTable(data, headers, containerId) {
  const table = document.createElement("table");
  const headerRow = document.createElement("tr");
  headers.forEach((text) => {
    const th = document.createElement("th");
    th.textContent = text;
    headerRow.appendChild(th);
  });
  table.appendChild(headerRow);
  data.forEach((item) => {
    const row = document.createElement("tr");
    Object.values(item).forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      row.appendChild(td);
    });
    table.appendChild(row);
  });

  document.getElementById(containerId).appendChild(table);
}

function renderDnsTable(transportData) {
  const dnsData = transportData["DNS"];
  if (!dnsData) return;
  const dnsRows = [
    { name: "Transaction ID", value: dnsData["Transaction ID"] },
    {
      name: "Type",
      value: dnsData["Is Response"] ? "Response" : "Query",
    },
    {
      name: "Query Names",
      value: (dnsData["Query Names"] || []).join(", ") || "—",
    },
    {
      name: "Answer IPs",
      value: (dnsData["Answer IPs"] || []).join(", ") || "—",
    },
    { name: "Questions", value: dnsData["Question Count"] },
    { name: "Answers", value: dnsData["Answer Count"] },
  ];
  createTable(dnsRows, ["DNS Field", "Value"], "sidedatatable");
}

function renderIcmpTable(protocol, transportData) {
  if (protocol !== "ICMP") return;
  const icmpRows = [
    { name: "Type", value: transportData["Type"] ?? "—" },
    { name: "Code", value: transportData["Code"] ?? "—" },
    { name: "ID", value: transportData["ID"] ?? "—" },
    { name: "Sequence", value: transportData["Sequence"] ?? "—" },
  ];
  createTable(icmpRows, ["ICMP Field", "Value"], "sidedatatable");
}

function renderSnmpTable(transportData) {
  const snmpData = transportData["SNMP"];
  if (!snmpData) return;
  const snmpRows = [
    { name: "Version", value: snmpData["Version"] || "—" },
    { name: "Community", value: snmpData["Community"] || "—" },
    { name: "PDU Type", value: snmpData["PDU Type"] || "—" },
  ];
  createTable(snmpRows, ["SNMP Field", "Value"], "sidedatatable");
}

function renderDhcpTable(transportData) {
  const dhcpData = transportData["DHCP"];
  if (!dhcpData) return;
  const dhcpRows = [
    { name: "Message Type", value: dhcpData["Message Type"] || "—" },
    { name: "Transaction ID", value: dhcpData["Transaction ID"] || "—" },
    { name: "Client IP", value: dhcpData["Client IP"] || "—" },
    { name: "Your IP", value: dhcpData["Your IP"] || "—" },
    { name: "Server IP", value: dhcpData["Server IP"] || "—" },
  ];
  createTable(dhcpRows, ["DHCP Field", "Value"], "sidedatatable");
}

function renderNtpTable(transportData) {
  const ntpData = transportData["NTP"];
  if (!ntpData) return;
  const ntpRows = [
    { name: "Version", value: ntpData["Version"] ?? "—" },
    { name: "Mode", value: ntpData["Mode"] || "—" },
    { name: "Stratum", value: ntpData["Stratum"] ?? "—" },
    { name: "Reference ID", value: ntpData["Reference ID"] || "—" },
    { name: "Leap Indicator", value: ntpData["Leap Indicator"] ?? "—" },
  ];
  createTable(ntpRows, ["NTP Field", "Value"], "sidedatatable");
}

function renderSipTable(transportData) {
  const sipData = transportData["SIP"];
  if (!sipData) return;
  const sipRows = [
    { name: "Type", value: sipData["Type"] || "—" },
    {
      name: sipData["Type"] === "Request" ? "Method" : "Status Code",
      value: sipData["Method"] || sipData["Status Code"] || "—",
    },
    { name: "From", value: sipData["From"] || "—" },
    { name: "To", value: sipData["To"] || "—" },
    { name: "Call-ID", value: sipData["Call-ID"] || "—" },
  ];
  createTable(sipRows, ["SIP Field", "Value"], "sidedatatable");
}

function renderHttpTable(transportData) {
  const httpData = transportData["HTTP"];
  if (!httpData) return;
  const httpRows = [{ name: "Type", value: httpData["Type"] || "—" }];
  if (httpData["Type"] === "Request") {
    httpRows.push(
      { name: "Method", value: httpData["Method"] || "—" },
      { name: "URL", value: httpData["URL"] || "—" },
      { name: "HTTP Version", value: httpData["HTTP Version"] || "—" },
      { name: "Host", value: httpData["Host"] || "—" },
      { name: "User-Agent", value: httpData["User-Agent"] || "—" },
      { name: "Content-Type", value: httpData["Content-Type"] || "—" },
      { name: "Content-Length", value: httpData["Content-Length"] || "—" },
      { name: "Referer", value: httpData["Referer"] || "—" },
      { name: "Accept", value: httpData["Accept"] || "—" },
      { name: "Accept-Encoding", value: httpData["Accept-Encoding"] || "—" },
      { name: "Connection", value: httpData["Connection"] || "—" },
    );
  } else {
    httpRows.push(
      { name: "Status Code", value: httpData["Status Code"] || "—" },
      { name: "Status Message", value: httpData["Status Message"] || "—" },
      { name: "HTTP Version", value: httpData["HTTP Version"] || "—" },
      { name: "Server", value: httpData["Server"] || "—" },
      { name: "Content-Type", value: httpData["Content-Type"] || "—" },
      { name: "Content-Length", value: httpData["Content-Length"] || "—" },
      {
        name: "Content-Encoding",
        value: httpData["Content-Encoding"] || "—",
      },
      {
        name: "Transfer-Encoding",
        value: httpData["Transfer-Encoding"] || "—",
      },
      { name: "Connection", value: httpData["Connection"] || "—" },
      { name: "Location", value: httpData["Location"] || "—" },
    );
  }
  createTable(httpRows, ["HTTP Field", "Value"], "sidedatatable");
}

module.exports = {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderSnmpTable,
  renderDhcpTable,
  renderNtpTable,
  renderSipTable,
  renderHttpTable,
};
