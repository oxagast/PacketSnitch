# PacketSnitch

![PacketSnitch Logo](https://raw.githubusercontent.com/oxagast/PacketSnitch/refs/heads/main/Logo/logo-packetsnitch.webp)

## Overview

PacketSnitch is a Python tool for extracting payloads and rich metadata from network packet capture (`.pcap`) files. It generates testcases for fuzzing, protocol analysis, and research by saving raw packet data and detailed information about each packet, including protocol, entropy, geoip, banners, and more. The tool optionally performs active reconnaissance to enrich output with server banners, SSL certificate info, and web page titles.

## Features

- Extracts TCP payloads from `.pcap` files and saves them as binary testcase files.
- Generates JSON info files for each testcase, containing:
  - Packet metadata (timestamps, MAC/IP addresses, ports, flags, checksums)
  - MIME type and magic description
  - Shannon entropy and character statistics
  - GeoIP lookup for source/destination IPs
  - Port descriptions (ICANN database)
  - MAC vendor lookup
  - Active recon: server banners, SSL certificate info, web page titles (optional)
- Consolidates all testcase info into `all_testcases_info.json`.
- Supports filtering by source/destination port.
- Handles compressed payloads (gzip/zlib).
- Verbose/debug output modes.

## Requirements

- Python 3.7+ (backend)
- NodeJS 16.4 / Electron Forge 7.11 (frontend) 
- Ollama LLM server (maxmind-m2.5:cloud)
- Dependencies:
  - electron forge
  - webpack
  - fs-extra
  - electron-squirrel-start
  - copy-webpack-plugin
  - ollama
  - scapy
  - numpy
  - requests
  - pyyaml
  - python-magic
  - chardet
  - geoip2
  - beautifulsoup4
  - scipy
- Databases:
  - GeoIP database (MaxMind `.mmdb`)
  - MAC vendor CSV
  - ICANN port description CSV


## Usage

(Dev)

```bash
python3 gen_testcase.py traffic.pcap -o output_dir [-s SRC_PORT] [-d DST_PORT] [-T TIMEOUT] [-a] [-c conf.yaml] [-v]
```

```bash
npm run make
npm start
```

### Arguments

- `traffic.pcap`: Path to the `.pcap` file to parse.
- `-o, --output`: Output directory for testcases (default: `testcases`)
- `-s, --source-port`: Only generate testcases from this source port.
- `-d, --dest-port`: Only generate testcases for this destination port.
- `-T, --timeout`: Timeout for network requests (default: 3 seconds)
- `-a, --active-recon`: Perform active recon (banners, SSL, titles)
- `-c, --conf`: Path to YAML config file (default: `conf.yaml`)
- `-v, --verbose`: Increase verbosity (repeat for more detail)

### Example

```bash
python3 gen_testcase.py traffic.pcap -o output_dir -T 5 -a -v
```

## Output Structure

- `output_dir/<dest_port>/pcap.data_packet.<index>.dat`: Raw payloads
- `output_dir/<dest_port>/pcap.info_packet.<index>.json`: Metadata for each testcase
- `all_testcases_info.json`: Consolidated info for all testcases

## Configuration

Edit `conf.yaml` to specify database locations:

```yaml
active_recon: true
output_dir: "testcases"
ollama:
  use_llm: true
#  model: "deepseek-r1:latest"
  model: "minimax-m2.5:cloud"
  response_length: 200
  pcap_percentage: 10
threads: 4
```

## Searchable Attributes

Each testcase JSON contains the following dot-notation keys as leaf nodes, which can be used to search, filter, or query testcase data in the frontend or via `all_testcases_info.json`:

| Attribute | Type | Description |
|---|---|---|
| `packet.timestamp` | string | Timestamp of the captured packet (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| `packet.hex` | string | Full raw packet bytes as a hex string |
| `ether.src.mac.addr` | string | Source MAC address |
| `ether.dst.mac.addr` | string | Destination MAC address |
| `ether.src.mac.vendor` | string | Vendor name for the source MAC address |
| `ether.dst.mac.vendor` | string | Vendor name for the destination MAC address |
| `ip.src.addr` | string | Source IP address |
| `ip.dst.addr` | string | Destination IP address |
| `ip.chksum` | string | IP header checksum (hex) |
| `ip.len` | integer | IP layer length in bytes |
| `ip.src.class` | string | Network class of the source IP (e.g. `Localnet`, `A`, `B`, `C`) |
| `ip.dst.class` | string | Network class of the destination IP |
| `tcp.src.port` | integer | TCP source port number |
| `tcp.dst.port` | integer | TCP destination port number |
| `tcp.chksum` | string | TCP checksum (hex) |
| `tcp.urgptr` | boolean | Whether the TCP urgent pointer is set |
| `tcp.flags` | string | Active TCP flags (e.g. `SYN\|ACK`) |
| `tcp.options` | list | TCP options list |
| `tcp.len` | integer | TCP header length in bytes |
| `tcp.proto` | string | Service/protocol name for the destination port |
| `tcp.desc` | string | ICANN port description for the destination port |
| `wire.len` | integer | Total wire length of the TCP segment in bytes |
| `payload.hex` | string | Raw TCP payload as a hex string |
| `payload.ascii` | string | Raw TCP payload decoded as ASCII (lossy) |
| `payload.len` | integer | Length of the TCP payload in bytes |
| `payload.mime` | string | MIME type of the payload (e.g. `text/html`, `application/octet-stream`) |
| `payload.entropy` | float | Shannon entropy of the payload (bits per byte) |
| `payload.charset` | string | `ascii` if all bytes are printable ASCII, otherwise `binary` |
| `payload.chars.used` | integer | Number of distinct byte values present in the payload |
| `payload.decompressed.hex` | string | Decompressed payload as a hex string (only present if payload was compressed) |
| `payload.decompressed.ascii` | string | Decompressed payload decoded as ASCII (only present if payload was compressed) |
| `host.banner` | string | Server banner retrieved via active recon (requires `-a`) |
| `loc.src.country` | string | Country of the source IP (GeoIP lookup) |
| `loc.src.city` | string | City of the source IP (GeoIP lookup) |
| `loc.src.postal` | string | Postal code of the source IP (GeoIP lookup) |
| `loc.src.tz` | string | Time zone of the source IP — alias for `loc.src.timezone` |
| `loc.src.timezone` | string | Time zone of the source IP (GeoIP lookup) |
| `loc.dst.country` | string | Country of the destination IP (GeoIP lookup) |
| `loc.dst.city` | string | City of the destination IP (GeoIP lookup) |
| `loc.dst.postal` | string | Postal code of the destination IP (GeoIP lookup) |
| `loc.dst.tz` | string | Time zone of the destination IP — alias for `loc.dst.timezone` |
| `loc.dst.timezone` | string | Time zone of the destination IP (GeoIP lookup) |

> **Note:** GeoIP attributes (`loc.*`) are only populated for non-private/routable IP addresses. Ethernet frame attributes (`ether.*`) are only populated when both source and destination IPs resolve to the local network. Active-recon attributes (`host.banner`, `dns.hostnames`) require the `-a` flag.

## Notes

- Active recon may take longer and requires network access.
- Ensure database files are present and paths are correct in `conf.yaml`.
- The tool will prompt before overwriting output directories.

## License

GPL v3

## Author

Marshall Whittaker
