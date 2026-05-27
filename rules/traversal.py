import re

TRAVERSAL_PATTERNS = [
    r"(\.\./){2,}",            
    r"(\.\.\\){2,}",            
    r"(?i)%2e%2e%2f",           
    r"(?i)/etc/passwd",         
    r"(?i)/etc/shadow",         
    r"(?i)/windows/system32",
]

def detect(payload: str) -> list:
    alerts = []
    for pattern in TRAVERSAL_PATTERNS:
        match = re.search(pattern, payload)
        if match:
            alerts.append({
                "type": "Directory Traversal",
                "severity": "MEDIUM",
                "match": match.group(),
                "payload_snippet": payload[:200],
            })
    return alerts
