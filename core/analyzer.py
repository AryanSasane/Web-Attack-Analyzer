from rules import sqli, xss, traversal, bruteforce
from utils.alert import Alert

def analyze_request(pkt_meta: dict) -> list:
    alerts = []
    full_payload = pkt_meta.get("raw_payload", "")
    src_ip = pkt_meta.get("src_ip", "")
    method = pkt_meta.get("method", "")
    path = pkt_meta.get("path", "")

    rule_results = (
        sqli.detect(full_payload)
        + xss.detect(full_payload)
        + traversal.detect(full_payload)
        + bruteforce.detect(src_ip, path, method)
    ) 

    for r in rule_results:
        alerts.append(Alert(
            src_ip= src_ip,
            dst_ip= pkt_meta.get("dst_ip", ""),
            src_port= pkt_meta.get("src_port", 0),
            dst_port= pkt_meta.get("dst_port", 0),
            method= method,
            path= path,
            attack_type= r["type"],
            severity= r["severity"],
            match= r["match"],
            payload_snippet= r["payload_snippet"],
        ))
    return alerts
