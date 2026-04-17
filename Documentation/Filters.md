![PacketSnitch by oxasploits](https://raw.githubusercontent.com/oxasploits/PacketSnitch/main/Logo/packet-snitch-tag-transp-whitetext.png)

# Filter Reference

## Overview

PacketSnitch's filter bar lets you search and narrow down the packets displayed in the frontend. Filters are evaluated over the full loaded dataset (all hosts), not just the currently selected host. Results update immediately after pressing **Enter** in the filter bar, and the **Filtered Packets** counter in the left sidebar updates to reflect the number of matching packets.

---

## Syntax

### Basic equality

```
key:value
```

Matches packets where `key` equals `value`. String comparisons are **case-insensitive**.

```
ip.src.addr:192.168.1.1
tcp.dst.port:443
payload.mime:text/html
```

### Comparison operators

Prefix the value with a comparison operator to perform numeric or lexicographic comparisons.

```
key:==value    (explicit equality — same as key:value)
key:!=value    (not equal)
key:>value     (greater than)
key:>=value    (greater than or equal)
key:<value     (less than)
key:<=value    (less than or equal)
```

```
payload.entropy:>=7.0
ip.len:>100
tcp.dst.port:!=80
payload.len:<64
```

### Boolean combinators

Use `&&` (AND) and `||` (OR) to combine multiple conditions. AND has higher precedence than OR.

```
ip.src.addr:10.0.0.1 && tcp.dst.port:443
tcp.dst.port:80 || tcp.dst.port:443
```

### Grouping with parentheses

Use parentheses to override precedence and group sub-expressions.

```
(tcp.dst.port:80 || tcp.dst.port:443) && payload.entropy:>=6.0
(payload.mime:text/html || payload.mime:application/json) && ip.dst.addr:10.0.0.1
```

### Clearing the filter

Delete all text from the filter bar and press **Enter** to show all packets again.

---

## How Keys Work

Filter keys correspond directly to the dot-notation leaf-node names embedded in each packet's JSON. The filter engine normalizes keys to **lowercase** with **spaces replaced by hyphens**, so both the machine-readable dot-notation form (`wire.len`) and the normalized human-readable form (`wire-length`) are accepted interchangeably. This document uses the canonical dot-notation names throughout.

Protocol-specific keys (e.g., `dns.*`, `http.*`) are only present in packets where that protocol was detected, so filtering on them automatically scopes results to the relevant protocol traffic.

---

## Filter Key Reference

### Core Packet Fields

| Filter Key         | Type    | Description                                                  |
| ------------------ | ------- | ------------------------------------------------------------ |
| `packet.timestamp` | string  | Capture timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`)             |
| `packet.proto`     | string  | Transport protocol (`tcp`, `udp`, `icmp`)                    |
| `packet.hex`       | string  | Full raw packet as a hex string                              |

### Ethernet Fields

> Only populated when both source and destination IPs are on the local network.

| Filter Key             | Type   | Description                                 |
| ---------------------- | ------ | ------------------------------------------- |
| `ether.src.mac.addr`   | string | Source MAC address                          |
| `ether.dst.mac.addr`   | string | Destination MAC address                     |
| `ether.src.mac.vendor` | string | Hardware vendor of the source MAC           |
| `ether.dst.mac.vendor` | string | Hardware vendor of the destination MAC      |

### IP Fields

| Filter Key     | Type    | Description                                                       |
| -------------- | ------- | ----------------------------------------------------------------- |
| `ip.src.addr`  | string  | Source IP address                                                 |
| `ip.dst.addr`  | string  | Destination IP address                                            |
| `ip.chksum`    | string  | IP header checksum (hex, e.g. `0xd1ae`)                           |
| `ip.len`       | integer | IP layer length in bytes                                          |
| `ip.src.class` | string  | Network class of the source IP (`Localnet`, `A`, `B`, `C`)        |
| `ip.dst.class` | string  | Network class of the destination IP (`Localnet`, `A`, `B`, `C`)  |

### TCP Fields

| Filter Key     | Type    | Description                                              |
| -------------- | ------- | -------------------------------------------------------- |
| `tcp.src.port` | integer | TCP source port                                          |
| `tcp.dst.port` | integer | TCP destination port                                     |
| `tcp.chksum`   | string  | TCP checksum (hex)                                       |
| `tcp.urgptr`   | boolean | Whether the urgent pointer is set (`true` / `false`)     |
| `tcp.flags`    | string  | Active TCP flags (e.g. `SYN`, `ACK\|PSH`, `SYN\|ACK`)   |
| `tcp.len`      | integer | TCP header length in bytes                               |
| `tcp.proto`    | string  | IANA service name for the destination port (e.g. `https`) |
| `tcp.desc`     | string  | ICANN port description for the destination port          |

### UDP Fields

| Filter Key     | Type    | Description                   |
| -------------- | ------- | ----------------------------- |
| `udp.src.port` | integer | UDP source port               |
| `udp.dst.port` | integer | UDP destination port          |
| `udp.chksum`   | string  | UDP checksum (hex)            |
| `udp.len`      | integer | UDP datagram length in bytes  |

### ICMP Fields

| Filter Key    | Type    | Description                                                        |
| ------------- | ------- | ------------------------------------------------------------------ |
| `icmp.type`   | string  | ICMP message type (e.g. `Echo Request`, `Destination Unreachable`) |
| `icmp.code`   | integer | ICMP code value                                                    |
| `icmp.id`     | integer | ICMP identifier field                                              |
| `icmp.seq`    | integer | ICMP sequence number                                               |
| `icmp.chksum` | string  | ICMP checksum (hex)                                                |

### Wire / Payload Fields

| Filter Key                   | Type    | Description                                                                    |
| ---------------------------- | ------- | ------------------------------------------------------------------------------ |
| `wire.len`                   | integer | Total wire length of the segment in bytes                                      |
| `payload.hex`                | string  | Raw payload as a hex string                                                    |
| `payload.ascii`              | string  | Raw payload decoded as ASCII                                                   |
| `payload.len`                | integer | Payload length in bytes                                                        |
| `payload.mime`               | string  | MIME type (e.g. `text/html`, `application/octet-stream`)                       |
| `payload.entropy`            | float   | Shannon entropy of the payload (bits per byte, 0.0 – 8.0)                     |
| `payload.charset`            | string  | `ascii` if all bytes are printable ASCII, otherwise `binary`                   |
| `payload.encoding`           | string  | Detected character encoding (e.g. `utf-8`, `iso-8859-1`)                      |
| `payload.chars.used`         | integer | Number of distinct byte values present in the payload                          |
| `payload.decompressed.hex`   | string  | Decompressed payload as a hex string (only present if payload was compressed)  |
| `payload.decompressed.ascii` | string  | Decompressed payload as ASCII (only present if payload was compressed)         |

### GeoIP / Location Fields

> Only populated for routable (non-private) IP addresses.

| Filter Key         | Type   | Description                                  |
| ------------------ | ------ | -------------------------------------------- |
| `loc.src.country`  | string | Country of the source IP                     |
| `loc.src.city`     | string | City of the source IP                        |
| `loc.src.postal`   | string | Postal code of the source IP                 |
| `loc.src.tz`       | string | Time zone of the source IP (short alias)     |
| `loc.src.timezone` | string | Time zone of the source IP (full name)       |
| `loc.dst.country`  | string | Country of the destination IP                |
| `loc.dst.city`     | string | City of the destination IP                   |
| `loc.dst.postal`   | string | Postal code of the destination IP            |
| `loc.dst.tz`       | string | Time zone of the destination IP (short alias) |
| `loc.dst.timezone` | string | Time zone of the destination IP (full name)  |

### Active Recon Fields

> Only populated when the backend was run with `-a` (active recon).

| Filter Key    | Type   | Description                          |
| ------------- | ------ | ------------------------------------ |
| `host.banner` | string | Server banner retrieved via active recon |

### DNS Fields

> Only present on packets captured on UDP/TCP port 53.

| Filter Key       | Type    | Description                                      |
| ---------------- | ------- | ------------------------------------------------ |
| `dns.id`         | integer | DNS transaction ID                               |
| `dns.qr`         | boolean | `true` = response, `false` = query               |
| `dns.qname`      | string  | First queried domain name                        |
| `dns.aname`      | string  | First answer name                                |
| `dns.aip`        | string  | First resolved IP address from the response      |
| `dns.qdcount`    | integer | Number of questions in the message               |
| `dns.ancount`    | integer | Number of answer records in the message          |

### HTTP Fields

> Only present on packets captured on TCP port 80, 443, 8080, or 8443.

| Filter Key               | Type   | Description                                              |
| ------------------------ | ------ | -------------------------------------------------------- |
| `http.type`              | string | `Request` or `Response`                                  |
| `http.method`            | string | HTTP method (`GET`, `POST`, `PUT`, etc.) — requests only |
| `http.url`               | string | Request URL path — requests only                         |
| `http.version`           | string | HTTP version (e.g. `HTTP/1.1`)                           |
| `http.host`              | string | `Host` header — requests only                            |
| `http.user_agent`        | string | `User-Agent` header — requests only                      |
| `http.content_type`      | string | `Content-Type` header                                    |
| `http.content_length`    | string | `Content-Length` header                                  |
| `http.referer`           | string | `Referer` header — requests only                         |
| `http.accept`            | string | `Accept` header — requests only                          |
| `http.accept_encoding`   | string | `Accept-Encoding` header — requests only                 |
| `http.connection`        | string | `Connection` header                                      |
| `http.status_code`       | string | HTTP status code (e.g. `200`) — responses only           |
| `http.status_msg`        | string | HTTP status message (e.g. `OK`) — responses only         |
| `http.server`            | string | `Server` header — responses only                         |
| `http.content_encoding`  | string | `Content-Encoding` header — responses only               |
| `http.transfer_encoding` | string | `Transfer-Encoding` header — responses only              |
| `http.location`          | string | `Location` redirect header — responses only              |

### SNMP Fields

> Only present on packets captured on UDP/TCP port 161 or 162.

| Filter Key       | Type   | Description                                               |
| ---------------- | ------ | --------------------------------------------------------- |
| `snmp.version`   | string | SNMP version (`v1`, `v2c`, `v3`)                          |
| `snmp.community` | string | SNMP community string                                     |
| `snmp.pdu_type`  | string | PDU type (`GetRequest`, `GetResponse`, `Trap`, etc.)      |

### DHCP Fields

> Only present on packets captured on UDP port 67 or 68.

| Filter Key      | Type   | Description                                                    |
| --------------- | ------ | -------------------------------------------------------------- |
| `dhcp.msg_type` | string | DHCP message type (`DISCOVER`, `OFFER`, `REQUEST`, `ACK`, etc.) |
| `dhcp.xid`      | string | Transaction ID (hex)                                           |
| `dhcp.ciaddr`   | string | Client IP address                                              |
| `dhcp.yiaddr`   | string | Offered IP address                                             |
| `dhcp.siaddr`   | string | Server IP address                                              |

### NTP Fields

> Only present on packets captured on UDP port 123.

| Filter Key    | Type    | Description                                                        |
| ------------- | ------- | ------------------------------------------------------------------ |
| `ntp.leap`    | string  | Leap indicator (`no warning`, `last minute has 61s`, etc.)         |
| `ntp.version` | integer | NTP version number                                                 |
| `ntp.mode`    | string  | NTP mode (`client`, `server`, `broadcast`, etc.)                   |
| `ntp.stratum` | integer | Stratum level (0 = unspecified, 1 = primary, 2+ = secondary)       |
| `ntp.ref_id`  | string  | Reference ID (IP address or 4-character ASCII string)              |

### SIP Fields

> Only present on packets captured on UDP/TCP port 5060 or 5061.

| Filter Key        | Type   | Description                                                   |
| ----------------- | ------ | ------------------------------------------------------------- |
| `sip.type`        | string | `Request` or `Response`                                       |
| `sip.method`      | string | SIP method (`INVITE`, `REGISTER`, `BYE`, etc.) — requests only |
| `sip.uri`         | string | Request URI — requests only                                   |
| `sip.from`        | string | `From` header                                                 |
| `sip.to`          | string | `To` header                                                   |
| `sip.call_id`     | string | `Call-ID` header                                              |
| `sip.status_code` | string | SIP status code (e.g. `200`) — responses only                 |
| `sip.status_msg`  | string | SIP status message (e.g. `OK`) — responses only               |

---

## Examples

### IP and Port Filtering

```
# Packets from a specific source IP
ip.src.addr:192.168.1.10

# Packets going to a specific destination IP
ip.dst.addr:10.0.0.1

# Traffic on destination port 443
tcp.dst.port:443

# Traffic from a source port range (above 1024 — high ephemeral ports)
tcp.src.port:>1024

# Traffic between two specific hosts
ip.src.addr:10.0.0.5 && ip.dst.addr:10.0.0.1

# All HTTP and HTTPS traffic
tcp.dst.port:80 || tcp.dst.port:443

# Large IP packets
ip.len:>1000
```

### Payload and Entropy Filtering

```
# Payloads likely encrypted or compressed (high entropy)
payload.entropy:>=7.0

# Small payloads
payload.len:<64

# HTML responses
payload.mime:text/html

# JSON payloads
payload.mime:application/json

# Plain-text (ASCII) payloads only
payload.charset:ascii

# Payloads encoded as UTF-8
payload.encoding:utf-8

# Packets that contained a compressed payload
payload.decompressed.ascii:!=

# High-entropy HTML traffic — likely HTTPS with cleartext body
(tcp.dst.port:80 || tcp.dst.port:443) && payload.entropy:>=6.0

# JSON payloads from a specific host
payload.mime:application/json && ip.src.addr:10.0.0.5
```

### GeoIP / Location Filtering

```
# Packets originating from China (GeoIP)
loc.src.country:China

# Packets destined for Germany
loc.dst.country:Germany

# Packets from a specific city
loc.src.city:Hangzhou

# Traffic from China going to local network
loc.src.country:China && ip.dst.class:Localnet

# Outbound traffic to a foreign country
ip.src.class:Localnet && loc.dst.country:Russia
```

### Protocol-Specific Filtering

```
# DNS queries only (not responses)
dns.qr:false

# DNS queries for a specific domain
dns.qname:example.com

# All DNS responses
dns.qr:true

# HTTP POST requests
http.method:POST

# HTTP responses with a 404 status
http.status_code:404

# HTTP responses from a specific server
http.server:nginx

# HTTP requests to a specific host header
http.host:api.example.com

# HTTPS responses (port 443) with error status
tcp.dst.port:443 && http.status_code:>=400

# SNMP packets using the "public" community string
snmp.community:public

# SNMP traps
snmp.pdu_type:Trap

# DHCP DISCOVER messages
dhcp.msg_type:DISCOVER

# NTP client requests
ntp.mode:client

# NTP with a non-primary stratum
ntp.stratum:>1

# SIP INVITE requests
sip.method:INVITE

# SIP calls from a specific URI
sip.from:sip:alice@example.com
```

### TCP Flags

```
# SYN packets (connection initiation)
tcp.flags:SYN

# RST packets (connection reset)
tcp.flags:RST

# FIN packets (connection teardown)
tcp.flags:FIN

# Packets with both ACK and PSH set
tcp.flags:ACK|PSH
```

### Ethernet / MAC Filtering

```
# Packets from a specific MAC address
ether.src.mac.addr:08:9d:f4:84:e9:28

# Packets from a specific vendor
ether.src.mac.vendor:Intel

# Local traffic between two known MAC addresses
ether.src.mac.addr:08:9d:f4:84:e9:28 && ether.dst.mac.addr:b8:3a:08:bc:4e:70
```

### Active Recon

```
# Hosts running Apache
host.banner:Apache

# Hosts running nginx
host.banner:nginx

# Any host where a banner was retrieved
host.banner:!=Active recon not performed
```

### Complex Multi-Condition Queries

```
# High-entropy traffic from China to local network on common web ports
(tcp.dst.port:80 || tcp.dst.port:443) && loc.src.country:China && payload.entropy:>=6.0

# DNS queries from internal hosts
dns.qr:false && ip.src.class:Localnet

# All SNMP and DHCP management traffic
(snmp.community:public || snmp.pdu_type:Trap) || (dhcp.msg_type:DISCOVER || dhcp.msg_type:OFFER)

# Large encrypted TCP packets from external sources
tcp.dst.port:443 && payload.len:>500 && payload.entropy:>=7.0 && ip.src.class:!=Localnet

# HTTP POST requests carrying JSON payloads
http.method:POST && payload.mime:application/json

# SIP calls destined for a specific domain
sip.method:INVITE && sip.to:example.com
```

---

## Tips

- **Press Enter** to apply the filter after typing in the filter bar. The filter is not applied as you type.
- **String matching is case-insensitive.** `loc.dst.country:china` matches the same packets as `loc.dst.country:China`.
- **Protocol-specific keys only exist when that protocol was detected.** Filtering on `http.method:GET` will return only HTTP packets where the method field was parsed.
- **GeoIP keys are absent for private/local IPs.** Use `ip.src.class:Localnet` to identify local traffic instead of relying on `loc.src.*` fields.
- **Active recon keys require the `-a` flag** when running the backend. Without it, `host.banner` will contain `Active recon not performed` for all packets.
- **An empty filter bar shows all packets.** Clear the filter and press Enter to reset the view.

---

## License

GPL v3

## Author

Marshall Whittaker
