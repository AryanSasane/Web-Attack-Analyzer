from scapy.all import wrpcap, IP, TCP, Raw

def make_http_packets(src_ip, dst_ip, method, path, body=""):
    payload = f"{method} {path} HTTP/1.1\r\nHost: testsite.com\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=54321, dport=80, flags="PA") / 
        Raw(load=payload.encode())
    )
    return pkt

packets = [
    #SQL Injection 
    make_http_packets("192.168.1.10", "10.0.0.1", "GET", "/search?q=1 UNION SELECT * FROM users"),
    make_http_packets("192.168.1.10", "10.0.0.1", "POST", "/login", "user=' OR '1'='1&pass=test"),

    #XSS 
    make_http_packets("192.168.1.20", "10.0.0.1", "GET", "/search?q=<script>alert(1)</script>"),
    make_http_packets("192.168.1.20", "10.0.0.1", "GET", '/profile?name=<img src=x onerror="alert(1)">'),

    #Directory Traversal
    make_http_packets("192.168.1.30", "10.0.0.1", "GET", "/files?name=../../etc/passwd"),
    make_http_packets("192.168.1.30", "10.0.0.1", "GET", "/page?file=%2e%2e%2fetc%2fshadow"),

    #Clean Traffic
    make_http_packets("192.168.1.99", "10.0.0.1", "GET", "/index.html"),
    make_http_packets("192.168.1.99", "10.0.0.1", "POST", "/api/data", "name=John&age=25"),
]

wrpcap("samples/test.pcap", packets)
print("[+] test.pcap created with", len(packets), "packets")