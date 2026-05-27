from scapy.all import sniff
from core.pcap_reader import parse_http_from_packet
from core.analyzer import analyze_request
from utils.alert import Alert

_all_alerts = []

def _packet_callback(pkt):
    parsed = parse_http_from_packet(pkt)
    if parsed:
        alerts = analyze_request(parsed)
        for a in alerts:
            a.pretty_print()
            _all_alerts.append(a)

def start_capture(interface=None, port=80, count=0) -> list:
    filter_str = f"tcp port {port}"
    print(f"[*] Starting live capture on port {port} (ctrl+c to stop) ... ")
    sniff(
        iface= interface,
        filter= filter_str,
        prn= _packet_callback, 
        count= count,
        store= False,
    )
    return _all_alerts