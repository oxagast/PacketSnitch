![PacketSnitch by oxasploits](https://raw.githubusercontent.com/oxasploits/PacketSnitch/main/Logo/packet-snitch-tag-transp-whitetext.png)

# PacketSnitch Documentation

## Overview

PacketSnitch is a network packet analysis tool consisting of a Python backend for extracting payloads and rich metadata from `.pcap` files, and an Electron-based frontend for browsing, filtering, and visualizing the results.

## Documentation

- [**Backend Documentation**](Backend.md) — Python backend (`snitch.py`): usage, arguments, output structure, and the full list of searchable attributes produced in the JSON output.
- [**Frontend Documentation**](Frontend.md) — Electron frontend: installation, UI output frames, and the filter syntax for querying packet data.

## Quick Start

**Backend** — extract packet data from a pcap file:

```bash
python3 snitch.py traffic.pcap -o output_dir -a -v
```

**Frontend** — launch the desktop app:

```bash
# Development
npm install
(chown/chmod electron binary)
npm run make
npm start

# Or run the pre-built binary
./packetsnitch          # Linux
packetsnitch.exe        # Windows
```

## License

GPL v3

## Author

Marshall Whittaker
