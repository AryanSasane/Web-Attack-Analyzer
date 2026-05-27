from scapy.all import rdpcap, TCP, IP, Raw

def parse_http_from_packet(pkt) -> dict | None:
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return None
    try:
        raw = pkt[Raw].load.decode("utf-8", errors="replace")
    except Exception:
        return None
    if not raw.startswith(("GET", "POST", "PUT", "DELETE", "HEAD ")):
        return None
    
    lines = raw.split("\r\n")
    first_line = lines[0].split(" ")
    if len(first_line) < 2:
        return None
    
    method = first_line[0]
    path = first_line[1]
    body_start = raw.find("\r\n\r\n")
    body = raw[body_start + 4:] if body_start != -1 else ""

    return {
        "src_ip":       pkt[IP].src if pkt.haslayer(IP) else "",
        "dst_ip":       pkt[IP].dst if pkt.haslayer(IP) else "",
        "src_port":     pkt[TCP].sport,
        "dst_port":    pkt[TCP].dport,
        "method":       method,
        "path":         path,
        "raw_payload":  raw,
        "body":         body,
    }

def read_pcap(filepath: str) -> list:
    packets = rdpcap(filepath)
    requests = []
    for pkt in packets:
        parsed = parse_http_from_packet(pkt)
        if parsed:
            requests.append(parsed)
    print(f"[+] Parsed {len(requests)} HTTP requests from {filepath}")
    return requests