# Web Attack Traffic Analyzer

A network-layer web attack detection tool that captures HTTP traffic from live interfaces or .pcap files and detects common web attacks in real time.

## Features
- SQL Injection detection (error-based and response size analysis)
- Cross-Site Scripting (XSS) detection
- Directory Traversal detection
- Brute Force detection (rate-based, sliding window)
- JSON report generation
- Flask web dashboard with auto-refresh

## Integration with Pen Toolkit
This tool is designed to work alongside the [Pen Testing Toolkit](https://github.com/AryanSasane/pen-toolkit):
1. Run pen-toolkit against a target
2. Capture traffic with tcpdump
3. Feed the pcap into this analyzer
4. View detected attacks on the dashboard

## System Dependencies
```bash
sudo apt install libpcap-dev tcpdump -y
```

## Installation
```bash
git clone https://github.com/AryanSasane/web-attack-analyzer.git
cd web-attack-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Analyze a pcap file
```bash
python main.py --pcap attack_traffic.pcap --report report.json
```

### Live capture
```bash
sudo venv/bin/python main.py --live --port 80 --iface docker0
```

### Launch dashboard
```bash
python main.py --dashboard
```

## Project Structure
- `rules/` — attack detection rules (SQLi, XSS, traversal, brute force)
- `core/` — packet parsing and analysis engine
- `utils/` — alert and report generation
- `dashboard/` — Flask web dashboard
- `tests/` — unit tests (9/9 passing)

## Tech Stack
Python, Scapy, Flask, pytest