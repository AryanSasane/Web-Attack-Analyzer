# Web Attack Traffic Analyzer

A network-layer web attack detection tool that captures HTTP traffic from live interfaces or .pcap files and detects common web attacks.


## Features
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Directory Traversal detection
- Brute Force detection
- JSON report generation
- Flask Web dashboard


## Installation
```bash 
git clone https://github.com/yourusername/web-attack-analyzer.git
cd web-attack-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


## Usage

### Analyze a pcap file
```bash
python main.py --live --port -80 -face eth0
```
### Launch Dashboard
```bash
python main.py --dashboard
```


## Project Structure
- 'rules/' - attack detection rules
- 'core/' - packet parsing and analysis engine
- 'utils/' - alert and report generation
- 'dashboard/' - Flask web dashboard
- 'test/' - unit tests (9/9 passing)


## Tech Stack
Python, Scapy, Flask, pytest

## System Dependencies
Required for live packet capture.
```bash
sudo apt install libpcap-dev tcpdump -y
```
- `libpcap-dev` — required for live packet capture with Scapy
- `tcpdump` — required for capturing attack traffic to pcap files