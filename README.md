# Port Scanner

A real, working multithreaded TCP port scanner written in pure Python (standard
library only — no extra installs required), plus an optional **simulated**
mode for demos or offline environments.

> ⚠️ **Legal / ethical use only.** Only scan hosts and networks you own or
> have explicit written permission to test. Unauthorized port scanning can
> violate laws (e.g. the U.S. Computer Fraud and Abuse Act) and most
> providers' acceptable-use policies.

## Features

- **Real TCP connect scanning** using raw sockets — no `nmap` or third-party
  binaries required.
- **Multithreaded** — scans hundreds of ports in parallel (configurable
  worker pool).
- **Banner grabbing** — reads the first bytes a service sends back (e.g. SSH
  version strings, HTTP headers).
- **Simulated mode** — generates realistic, deterministic fake results
  without touching the network at all. Great for demos, CI, or restricted
  sandboxes.
- **Flexible port specs** — single ports, ranges, comma-separated lists, or
  a curated "common ports" list (SSH, HTTP, HTTPS, databases, etc).
- **Export** results to JSON or CSV.
- **Live progress bar** in the terminal.
- Fully unit tested (`tests/test_scanner.py`), including mocked-socket tests
  for the real scanner's logic so tests don't require network access.

## Project structure

```
port-scanner/
├── app.py                       # Flask web app entry point
├── main.py                      # CLI entry point
├── templates/
│   └── index.html               # Web UI page
├── static/
│   ├── style.css                # Web UI styling
│   └── script.js                # Web UI behavior
├── scanner/
│   ├── __init__.py
│   ├── real_scanner.py          # Real TCP connect-scan implementation
│   └── simulated_scanner.py     # Network-free simulated scanner
├── tests/
│   └── test_scanner.py          # Unit tests
├── .vscode/
│   ├── launch.json              # Run/debug configs for VS Code
│   └── settings.json
├── requirements.txt
└── README.md
```

## Getting started (VS Code)

1. Unzip the project and open the `port-scanner` folder in VS Code
   (`File → Open Folder…`).
2. Make sure you have **Python 3.9+** installed and selected as the
   interpreter (`Ctrl/Cmd+Shift+P` → "Python: Select Interpreter").
3. Install Flask (only needed for the web app; the CLI needs nothing):
   ```bash
   pip install -r requirements.txt
   ```

## Web app (browser UI)

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser. You'll get:

- A host field, a port mode (common ports or a custom range/list), and a
  REAL / SIMULATED toggle.
- A live radar-style scanning animation while the scan runs.
- A port grid (every scanned port, color-coded by state) plus a detail
  table with service names, latency, and banners for open/filtered ports.

There's also a second, denser dashboard layout at **http://127.0.0.1:5000/netpulse**
(styled after a network-console mockup), with:

- Target input, **Run Scan**, and **Start Capture** controls in a top bar.
- An **Open Ports** panel, a **Scan Sweep** radar with an exposure-risk
  meter, and a **Live Packet Stream** panel.
- A bottom stats row: ports probed, open services, packets captured,
  flagged (risky) services.

Both routes call the same real scanning backend for open-port detection.
The **Live Packet Stream** on `/netpulse` is explicitly a **simulated**
feed (labeled as such in the UI) — a browser can't actually capture live
network packets; real packet capture needs raw sockets, admin/root
privileges, and platform-specific drivers (e.g. npcap on Windows), which
is out of scope for a browser-based tool.

The web app is a thin Flask wrapper (`app.py`) around the exact same
`PortScanner` / `SimulatedPortScanner` classes the CLI uses — no scanning
logic is duplicated. It runs entirely on your machine; nothing is sent
anywhere except the actual scan packets to whatever host you type in.

Stop it with `Ctrl+C` in the terminal when you're done.

## Command line (CLI)

If you'd rather use the terminal directly instead of the browser UI, the same functionality is available as a CLI:



```bash
# Real scan: top common ports on a host you own/administer
python main.py scan example.com --common

# Real scan: a custom port range with more worker threads
python main.py scan 192.168.1.10 --ports 1-1024 --workers 200

# Real scan: specific ports
python main.py scan 192.168.1.10 --ports 22,80,443,8080-8090

# Simulated scan — no real network traffic at all (good for demos)
python main.py scan example.com --common --simulate --seed 42

# Save results
python main.py scan example.com --common --output results.json
python main.py scan example.com --common --output results.csv

# Show closed/filtered ports too (by default only open ports are listed)
python main.py scan 127.0.0.1 --ports 1-100 --show-closed

# Full option list
python main.py scan --help
```

### Options

| Flag            | Description                                              |
|-----------------|------------------------------------------------------------|
| `--ports`       | Port spec: `80`, `1-1024`, or `22,80,443,8080-8090`        |
| `--common`      | Scan a curated list of ~25 common/well-known ports          |
| `--timeout`     | Per-port connection timeout in seconds (default `1.0`)      |
| `--workers`     | Number of concurrent threads (default `100`)                |
| `--no-banner`   | Disable banner grabbing                                     |
| `--show-closed` | Also print closed/filtered ports (default: open only)       |
| `--simulate`    | Use the network-free simulated scanner instead of a real one|
| `--seed`        | Random seed for reproducible simulated results               |
| `--output`      | Save results to a `.json` or `.csv` file                    |
| `--quiet`       | Hide the live progress bar                                   |

## Running the tests

```bash
python -m unittest discover -s tests -v
```

All real-scanner tests mock `socket.socket`, so the test suite runs fully
offline and never touches the network.

## Using it as a library

```python
from scanner import PortScanner, SimulatedPortScanner

scanner = PortScanner(timeout=0.75, max_workers=200)
result = scanner.scan("192.168.1.10", ports=range(1, 1025))

for p in result.open_ports:
    print(p.port, p.service, p.banner)

# Or, for a network-free demo:
demo_scanner = SimulatedPortScanner(seed=42)
demo_result = demo_scanner.scan_common_ports("example.com")
```

## How the real scanner works

For each port, it opens a raw TCP socket and calls `connect_ex()`:

- Return code `0` → the TCP three-way handshake succeeded → **open**.
- Non-zero (e.g. connection refused) → **closed**.
- A timeout with no response (common behind a firewall that silently drops
  packets) → **filtered**.

This is the same fundamental technique nmap calls a "TCP connect scan"
(`-sT`) — it doesn't require raw-socket/root privileges, unlike a SYN scan,
which makes it portable across Windows, macOS, and Linux out of the box.

## Why include a simulated mode?

Some environments (school networks, CI runners, sandboxes) block outbound
scanning, and some users just want to see how the tool behaves before
pointing it at a real target. `SimulatedPortScanner` has the exact same
interface as `PortScanner`, returns the same data structures, and can be
swapped in with a single flag (`--simulate`) — no real packets are ever
sent.
