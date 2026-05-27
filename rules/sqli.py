import re

SQLI_PATTERNS = [
    r"(?i)(union\s+select)",    
    r"(?i)(or\s+'1'='1)",       
    r"(?i)(drop\s+table)",      
    r"(?i)(sleep\s*\(\d+\))",   
]

def detect(payload: str) -> list:      
    alerts = []
    for pattern in SQLI_PATTERNS:
        match = re.search(pattern, payload)
        if match: 
            alerts.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "match": match.group(),
                "payload_snippet": payload[:200],
            })
    return alerts
