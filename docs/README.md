<a href="https://oxasploits.github.io/PacketSnitch/" alt="PacketSnitch by oxasploits"><img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/ps-tagline.png"></a>

### Overview

PacketSnitch is a network packet analysis tool consisting of a Python backend for extracting payloads and rich metadata from `.pcap` files, and an Electron-based frontend for browsing, filtering, and visualizing the results.

### Documentation

- [**Backend Documentation**](Backend.md) — Python backend (`snitch.py`): usage, arguments, output structure, and the full list of searchable attributes produced in the JSON output.
- [**Frontend Documentation**](Frontend.md) — Electron frontend: installation, UI output frames, and the filter syntax for querying packet data.
- [**Filter Reference**](Filters.md) — Complete guide to the filter bar: all filter keys, search syntax, operators, boolean combinators, and examples.

### Quick Start

**Download** -- grab the latest prod release:

The latest reelase can be found on the [releases page](https://github.com/oxasploits/PacketSnitch/releases).

**Install** -- install the package:

Linux:
-- Redhat based: dnf install ./packetsnitch-_.rpm
-- Debian based: apt install ./packetsnitch-_.deb
Windows:
-- Windows 11: Click on PacketSnitchInstaller.exe

**Launch** — launch the desktop app:

```bash
packetsnitch          # Linux
packetsnitch.exe        # Windows
```

Load a pcap or pcapng file, and start analyzing!

### License

GPL v3

### Author

Marshall Whittaker <marshall@oxasploits.com>
