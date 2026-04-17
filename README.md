![PacketSnitch](https://github.com/oxasploits/PacketSnitch/blob/main/Logo/packet-snitch-tag-transp-whitetext.png)

## Overview

PacketSnitch is a network packet analysis tool with two components that work together:

- **Frontend** — An Electron-based desktop application for loading, browsing, filtering, and visualizing captured network traffic. This is where you spend most of your time.
- **Backend** — A Python script (`snitch.py`) that parses `.pcap` files and extracts rich per-packet metadata into JSON, which the frontend then loads.

Point the backend at a `.pcap` file once, then explore and query the results interactively in the desktop app — no command line required after that.

---

## Getting Started

Install a pre-built release from the [releases](https://github.com/oxasploits/PacketSnitch/releases) page. Installers are available for Linux (`.deb`, `.rpm`) and Windows (`.exe`).

Once installed, launch the app by typing `packetsnitch` or clicking the desktop icon.

**Basic workflow:**

1. **Load PCAP** — Click **Load PCAP** in the app to run the backend on a `.pcap` file. The results are loaded automatically when processing finishes.
2. **Browse packets** — Use **Prev / Next** in the toolbar to step through packets, or pick a host from the **Target Host** dropdown in the left sidebar.
3. **Filter** — Type a filter expression in the filter bar and press **Enter** to narrow the view (e.g. `tcp.dst.port:443`, `loc.src.country:China`, `payload.entropy:>=7.0`).
4. **Summarize** — Click **Summary** in the toolbar to view an LLM-generated analysis of the capture (requires Ollama).

---

## The Desktop Interface

![PacketSnitch main view](https://private-user-images.githubusercontent.com/11489666/580219878-60ce31c8-008d-41e1-a911-5fec16d375e3.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NzY0NjkwMDUsIm5iZiI6MTc3NjQ2ODcwNSwicGF0aCI6Ii8xMTQ4OTY2Ni81ODAyMTk4NzgtNjBjZTMxYzgtMDA4ZC00MWUxLWE5MTEtNWZlYzE2ZDM3NWUzLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNjA0MTclMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjYwNDE3VDIzMzE0NVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPThkNWEzMWQwODdmMTFmMGExZWU0M2UxMTQ1NjU4ZjU0OGUyNGMwOWVkMWM1YmU5MzU1NDIwZGI5ZjQwMGI5MWEmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JnJlc3BvbnNlLWNvbnRlbnQtdHlwZT1pbWFnZSUyRnBuZyJ9.vs_J3_fL82KDOE19Mb9UjgnSGdRhVKrBS-vIP_eZEKY)

The UI is organized into panels that update in sync as you navigate packets.

### Left Sidebar

| Element              | Description |
| -------------------- | ----------- |
| **Target Host**      | Dropdown to select which IP stream to inspect. |
| **Bookmarks**        | Save and jump back to specific packets within a session. |
| **Save JSON**        | Export the currently loaded or filtered dataset. |
| **PCAP size**        | File size of the loaded capture in human-readable format. |
| **Load time**        | Time taken to parse and load the data. |
| **Total Packets**    | Total packets in the loaded dataset. |
| **Filtered Packets** | How many packets currently match the active filter. |
| **Timestamp**        | Capture timestamp of the packet currently on screen. |

### Toolbar

| Control         | Description |
| --------------- | ----------- |
| **Summary**     | Switch to the LLM analysis report view. |
| **Data**        | Return to the packet data view. |
| **Prev / Next** | Step backwards and forwards through the packet list. |
| **Filter bar**  | Enter a filter expression to narrow the displayed packets. |
| **Load JSON**   | Load a previously generated `hosts.json` file. |
| **Load PCAP**   | Run the backend on a `.pcap` file from within the app. |
| **Use LLM**     | Toggle Ollama-powered analysis summaries on or off. |

### Packet Info Pane

Displays structured metadata for the selected packet:

- **IP-to-IP Routing** — Source → destination addresses at a glance.
- **Network Information** — Source/destination ports with ICANN service names and descriptions.
- **Data Type List** — Detected MIME type, character set, content encoding, and magic-identified file type.
- **Active Recon** — SSL/TLS details, server banners, DNS hostnames, and the fetched web page title (only when the backend was run with `-a`).

### Packet Payload Pane

Shows the raw payload bytes for the current packet in two views:

- **ASCII View** — Printable character runs extracted from the payload, making it easy to spot readable strings embedded in binary data.
- **Hex Grid** — An interactive hex dump. Clicking a cell highlights the corresponding bytes and shows the printable ASCII sequence starting at that offset.

### Right Sidebar

| Panel                | Description |
| -------------------- | ----------- |
| **Datagram Frame**   | Protocol-specific low-level fields (checksums; DNS, HTTP, SNMP, DHCP, NTP, SIP details where applicable). |
| **Location**         | GeoIP table for source and destination IPs — country, city, postal code, and time zone. Local-network addresses are labelled `Localnet`. |
| **Payload Entropy**  | Shannon entropy of the payload displayed as a number and a graphical indicator. High entropy suggests encrypted or compressed content; low entropy suggests plain text. |

### Summary Frame

Click **Summary** in the toolbar to see an LLM-generated report for the entire capture. The report is produced by Ollama and is only available when the backend was run with LLM support enabled in `conf.yaml`.

---

## Filtering

The filter bar accepts expressions using dot-notation packet keys, comparison operators, and boolean combinators:

```
# Show only HTTPS traffic
tcp.dst.port:443

# Packets from China
loc.src.country:China

# High-entropy payloads (likely encrypted/compressed)
payload.entropy:>=7.0

# HTTP POST requests carrying JSON
http.method:POST && payload.mime:application/json

# HTTPS traffic with large, high-entropy payloads from external IPs
tcp.dst.port:443 && payload.len:>500 && payload.entropy:>=7.0 && ip.src.class:!=Localnet
```

String comparisons are case-insensitive. Press **Enter** to apply, and clear the bar and press **Enter** again to reset. For the full list of filter keys and syntax, see the [Filter Reference](https://github.com/oxasploits/PacketSnitch/blob/main/Documentation/Filters.md).

![PacketSnitch filter](https://raw.githubusercontent.com/oxasploits/PacketSnitch/main/Documentation/screenshots/comparison-operator-packetsnitch-ss21.png)

---

## Documentation

- [**Frontend Docs**](https://github.com/oxasploits/PacketSnitch/blob/main/Documentation/Frontend.md) — Full UI reference, installation, and developer setup.
- [**Backend Docs**](https://github.com/oxasploits/PacketSnitch/blob/main/Documentation/Backend.md) — `snitch.py` usage, arguments, output structure, and all searchable attributes.
- [**Filter Reference**](https://github.com/oxasploits/PacketSnitch/blob/main/Documentation/Filters.md) — Complete filter key reference with syntax, operators, and examples.

---

## Donate

Please donate to this project to keep it going!<br>
[Thanks.dev](https://thanks.dev/oxasploits)<br>

![Bitcoin](https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/Documentation/bitcoin-qr.png)
![PayPal](https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/Documentation/paypal-qr.png)
![Venmo](https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/Documentation/venmo-qr.png)

Thanks.dev, PayPal, Venmo, and Bitcoin are accepted forms of donation to the PacketSnitch project!

---

## License

GNU GPLv3

## Author

Marshall Whittaker
