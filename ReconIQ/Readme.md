# RECONIQ — Adaptive AI Reconnaissance Framework

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗ ██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║██╔═══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║██║   ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║██║▄▄ ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║╚██████╔╝
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚══▀▀═╝
```

> **Intelligent adaptive reconnaissance with AI-powered reasoning**

RECONIQ is a custom-built network reconnaissance tool that goes beyond simple port scanning. It intelligently adapts its scanning strategy, detects operating systems using multiple fingerprinting techniques, grabs service banners, and uses a local AI model (Llama 3) to analyze results and explain findings like a real penetration tester.

---

## Features

- **Custom Scanner Engine** — Built from scratch using Python sockets and Scapy. No Nmap dependency.
- **Adaptive Host Discovery** — Automatically tries ICMP → TCP Connect → SYN probe if previous method fails.
- **TCP & SYN Port Scanning** — Multi-threaded scanning with 150 concurrent threads for speed.
- **Service Detection** — Identifies 200+ services by port number and banner content.
- **Banner & Version Grabbing** — Extracts service banners and version numbers from open ports.
- **Nmap-Style OS Detection** — Uses TTL normalization, TCP window size, MSS, SACK, Timestamp options, port signatures, and banner analysis combined.
- **Risk Classification** — Every open port is rated: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`.
- **AI Reasoning Engine** — Powered by Llama 3 running locally via Ollama. Explains WHY findings are dangerous and recommends next steps.
- **Color-coded CLI** — Professional terminal UI built with Rich library.
- **JSON Report Export** — Full scan results saved as structured JSON.
- **100% Local & Private** — No internet required. No API costs. Everything runs on your machine.

---

## Screenshots

```
────────────────────── Scan Configuration ──────────────────────
  -t  Target       192.168.56.104
  -p  Ports        1024 ports (1–1024)
  -s  Scan Type    TCP
  -o  Output       report.json

────────────────────── Port Scan Results ───────────────────────
╭──────┬──────────┬─────────────┬──────────┬──────────────────╮
│ PORT │ STATE    │ SERVICE     │ RISK     │ INFO             │
├──────┼──────────┼─────────────┼──────────┼──────────────────┤
│ 21   │ OPEN     │ FTP         │ CRITICAL │ vsFTPd 2.3.4     │
│ 22   │ OPEN     │ SSH         │ MEDIUM   │ OpenSSH 4.7p1    │
│ 80   │ OPEN     │ HTTP        │ MEDIUM   │ Apache 2.2.8     │
│ 445  │ OPEN     │ SMB         │ HIGH     │ Samba smbd 3.x   │
╰──────┴──────────┴─────────────┴──────────┴──────────────────╯

────────────────────── OS Detection ────────────────────────────
  OS Detected     Linux / macOS / FreeBSD
  Confidence      HIGH (95%)
  TTL             64  (initial: 64)
  Window Size     5840
  Evidence        • TTL=64, • Window=5840 → Linux 2.4
```

---

## Requirements

- Python 3.8 or higher
- Windows 10/11 or Linux
- [Npcap](https://npcap.com/#download) (Windows only — required for Scapy)
- [Ollama](https://ollama.com/download) + Llama 3 model (for AI analysis)

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/yourusername/RECONIQ.git
cd RECONIQ
```

### Step 2 — Install Python dependencies

```bash
pip install scapy fastapi uvicorn rich requests
```

### Step 3 — Install Npcap (Windows only)

Download and install from: https://npcap.com/#download

During installation, check **"Install Npcap in WinPcap API-compatible Mode"**

### Step 4 — Install Ollama and Llama 3

Download Ollama: https://ollama.com/download

Then pull the Llama 3 model:

```bash
ollama pull llama3
```

### Step 5 — Verify everything works

```bash
python -c "import scapy; print('Scapy OK')"
ollama list
```

---

## Usage

### Basic syntax

```bash
python reconiq.py -t <target> -p <ports> [options]
```

### All flags

| Flag | Long Flag | Description | Example |
|------|-----------|-------------|---------|
| `-t` | `--target` | Target IP or hostname | `-t 192.168.1.1` |
| `-p` | `--ports` | Port range or list | `-p 1-1024` or `-p 22,80,443` |
| `-s` | `--scan` | Scan type: tcp or syn | `-s syn` |
| `-o` | `--output` | Save report to JSON | `-o report.json` |
| `-v` | `--verbose` | Show closed ports too | `-v` |
| | `--no-ai` | Disable AI analysis (faster) | `--no-ai` |
| | `--no-banner` | Disable banner grabbing | `--no-banner` |
| | `--no-os` | Disable OS detection | `--no-os` |
| `-h` | `--help` | Show help | `-h` |

### Examples

```bash
# Quick scan without AI
python reconiq.py -t 192.168.1.1 -p 1-1024 --no-ai

# Full scan with AI and save report
python reconiq.py -t 192.168.1.1 -p 1-1024 -o report.json

# SYN stealth scan (requires Administrator/root)
python reconiq.py -t 192.168.1.1 -p 1-1024 -s syn

# Scan specific ports only
python reconiq.py -t 192.168.1.1 -p 21,22,80,135,443,445,3306,3389

# Scan your own machine
python reconiq.py -t 127.0.0.1 -p 1-1024 --no-ai

# Scan Metasploitable 2 lab
python reconiq.py -t 192.168.56.104 -p 1-1024 -o metasploitable.json
```

---

## Project Structure

```
RECONIQ/
├── reconiq.py                  ← Main entry point
├── README.md
│
├── scanner/
│   ├── tcp_scanner.py          ← TCP connect port scanner
│   ├── syn_scanner.py          ← SYN stealth scanner (Scapy)
│   ├── icmp_discovery.py       ← Host discovery (ICMP + TCP fallback)
│   ├── banner_grabber.py       ← Service banner & version detection
│   └── os_fingerprint.py       ← OS detection (TTL + TCP + ports + banners)
│
├── ai/
   └── reasoning_engine.py     ← Llama 3 AI analysis engine

```

---

## How It Works

```
User runs RECONIQ
        │
        ▼
┌─────────────────┐
│  Host Discovery │  ICMP ping → TCP connect → SYN probe (adaptive)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Port Scanner  │  Multi-threaded TCP/SYN scan (150 threads)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Banner Grabber │  Service-specific probes → version extraction
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  OS Fingerprint │  TTL + Window + MSS + Ports + Banners combined
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AI Reasoning   │  Llama 3 analyzes all data → explains findings
└────────┬────────┘
         │
         ▼
   Results + JSON Report
```

---

## OS Detection Methods

RECONIQ uses 5 combined methods for OS detection:

| Method | How |
|--------|-----|
| ICMP TTL | Linux=64, Windows=128, Cisco=255 |
| TCP Window Size | Different OS use different window sizes |
| TCP Options | MSS, SACK, Timestamp, WScale patterns |
| Port Signatures | Windows ports (135,445,3389) vs Linux (22,111,2049) |
| Banner Analysis | IIS/Microsoft = Windows, Apache/OpenSSH = Linux |

---

## Important Notes

- **Run as Administrator** on Windows for ICMP and SYN scanning
- **For educational and authorized use only**
- Only scan networks and systems you have permission to scan
- Tested on Windows 10/11 and Metasploitable 2

---

## Legal Disclaimer

RECONIQ is intended for **authorized penetration testing and educational purposes only**.

Scanning networks without permission is **illegal**. The developer is not responsible for any misuse of this tool. Always get written permission before scanning any network or system.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.8+ |
| Packet Crafting | Scapy |
| CLI Interface | Rich |
| AI Engine | Ollama + Llama 3 |
| Concurrency | concurrent.futures |
| Report Format | JSON |

---

## Future Plans

- CVE correlation for detected services
- Exploit suggestions based on findings
- Web UI dashboard
- Historical scan comparison
- Stealth mode optimization
- Vulnerability scoring (CVSS)

---

## Author

**Sumit Kumar Singh**
Cybersecurity Student — Siliguri Institute of Technology
Specialization: Penetration Testing

---

## License

This project is licensed under the MIT License.

```
MIT License — Free to use, modify, and distribute with attribution.
```
