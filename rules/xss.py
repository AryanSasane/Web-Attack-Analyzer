import re

XSS_PATTERNS = [
    r"(?i)<script.*?>",                 
    r"(?i)</script>",                   
    r"(?i)on\w+\s*=\s*['\"].*?['\"]",   
    r"(?i)javascript\s*:",              
    r"(?i)eval\s*\(",                   
    r"(?i)document\.cookie",            
]

def detect(payload: str) -> list:
    alerts = []
    for pattern in XSS_PATTERNS:
        match = re.search(pattern, payload)
        if match:
            alerts.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "match": match.group(),
                "payload_snippet": payload[:200],
            })
    return alerts
