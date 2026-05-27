from collections import defaultdict
import time

_login_attempts = defaultdict(list)
THRESHOLD = 10
WINDOW_SECONDS = 60
LOGIN_PATHS = ["/login", "/admin", "wp-login.php", "/signin", "/auth"]  

def detect(src_ip: str, path: str, method: str) -> list:
    alerts = []
    path_lower = path.lower()
    is_login = method == "POST" and any(p in path_lower for p in LOGIN_PATHS)

    if is_login:
        now = time.time()                       
        _login_attempts[src_ip].append(now)
        _login_attempts[src_ip] = [             
            t for t in _login_attempts[src_ip] if now - t < WINDOW_SECONDS
        ]
        count = len(_login_attempts[src_ip])
        if count >= THRESHOLD:
            alerts.append({
                "type": "Brute Force",
                "severity": "MEDIUM",
                "match": f"{src_ip} -> {path}",
                "payload_snippet": f"{count} attempts from {src_ip}",   
            })
    return alerts