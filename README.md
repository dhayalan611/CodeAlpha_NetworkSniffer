# CodeAlpha Network Sniffer

A beginner-friendly terminal network sniffer built for the CodeAlpha Cybersecurity Internship (Task 1). It captures authorized IPv4 traffic with Scapy, identifies common protocols, displays safe packet metadata, and exports metadata to timestamped CSV files.

## Features

- IPv4 capture modes for all traffic, TCP, UDP, or ICMP
- Fully offline demo mode with deterministic TCP, UDP, and ICMP synthetic packets
- Source/destination IPs, ports, timestamps, sizes, and protocol classification
- Maximum packet count configuration and Ctrl+C early stopping
- Sixteen-byte hexadecimal payload preview for terminal learning only
- Calculated capture summary and unique CSV export under `captures/`
- No payloads or application data written to CSV
- Lightweight synthetic-packet tests that do not need Npcap or administrator access

HTTPS application traffic is normally encrypted, so this project cannot read it as plaintext. This is a metadata learning tool, not an attack detector or full intrusion detection system.

## Technology and requirements

- Windows 10/11
- Python 3.10 or newer
- Scapy
- Npcap with WinPcap-compatible mode enabled
- Administrator permission may be needed by the capture driver

## Windows setup

Install Python from [python.org](https://www.python.org/downloads/windows/) and Npcap from [npcap.com](https://npcap.com/#download). During Npcap setup, enable **Install Npcap in WinPcap API-compatible Mode**.

From PowerShell in this project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use `cmd.exe` and run `.venv\Scripts\activate.bat`, or invoke `.venv\Scripts\python.exe` directly.

## Running

```powershell
.\.venv\Scripts\Activate.ps1
python sniffer.py
```

Choose a capture mode, then enter a positive maximum packet count (press Enter for 30). Press **Ctrl+C** to stop early. The summary uses the packets actually received, and the CSV is written only after capture stops.

Example menu:

```text
========================================
       CODEALPHA NETWORK SNIFFER
========================================

1. Capture All IPv4 Packets
2. Capture TCP Packets
3. Capture UDP Packets
4. Capture ICMP Packets
5. Offline Demo (synthetic data)
6. Exit
```

### Privacy-safe screenshot demo

Choose **5. Offline Demo (synthetic data)** from the menu. The demo constructs
three packets in memory using only the documentation-only addresses
`192.0.2.10` and `203.0.113.20`; it never opens a capture interface, sends
traffic, or reads the network. It prints packet analysis and protocol
statistics, then exports the same metadata-only CSV format to `captures/`.

The output is explicitly marked **DEMO / SYNTHETIC DATA** so it is suitable
for internship screenshots. For clean screenshots:

1. Run `python sniffer.py` in a terminal sized to show the menu and output.
2. Select option `5` and capture the packet details plus summary.
3. Include the `DEMO / SYNTHETIC DATA` label in every screenshot.
4. Crop out your username, home-directory path, and unrelated terminal tabs.
5. Do not screenshot live-capture output or publish CSV files from real traffic.

Example output (fictional addresses):

```text
Packet Number : 1
Timestamp     : 2026-01-01 12:00:00
Source IP     : 192.0.2.10
Destination IP: 198.51.100.20
Protocol      : TCP
Source Port   : 51514
Dest Port     : 443
Packet Size   : 60 bytes
Payload (hex) : 16 03 01 00 2a
```

CSV files contain only the eight metadata columns shown below; payload previews are never persisted:

`Packet Number, Timestamp, Source IP, Destination IP, Protocol, Source Port, Destination Port, Packet Size`

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use synthetic Scapy packets and do not perform live capture.

## Screenshots / Project Demonstration

The `docs/screenshots/` directory can contain screenshots produced by the
offline demo above. Review each image before publishing and remove any local
username, path, unrelated terminal content, or accidental live-capture data.

## Project structure

```text
CodeAlpha_NetworkSniffer/
├── sniffer.py
├── requirements.txt
├── README.md
├── .gitignore
├── docs/screenshots/
├── tests/test_sniffer.py
├── captures/              # created automatically; ignored by Git
└── .venv/                 # local environment; ignored by Git
```

## Troubleshooting

- **Scapy is missing:** activate `.venv` and run `python -m pip install -r requirements.txt`.
- **Npcap/interface error:** reinstall Npcap with compatibility mode, check that a network adapter is enabled, and try an elevated PowerShell.
- **Permission denied:** packet capture requires an authorized interface and may require Administrator permission.
- **No packets appear:** generate ordinary authorized traffic on the selected adapter and verify the filter mode.
- **CSV error:** check that the project folder is writable and that security software is not locking `captures/`.

## Ethical use and limitations

Capture only traffic on systems and networks you own or have explicit permission to monitor. Do not commit captures, credentials, private addresses, or sensitive payloads. The tool provides basic observation and metadata export; it does not decrypt HTTPS, reconstruct sessions, detect attacks, or replace professional monitoring and incident-response systems.
