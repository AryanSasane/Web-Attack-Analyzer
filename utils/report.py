import json
from datetime import datetime
from utils.alert import Alert

def save_json(alerts: list, path: str = "report.json"):
    data = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_alerts": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Report saved to {path}")

def print_summary(alerts: list):
    from collections import Counter
    print("\n" + "="*50)
    print(f"   SCAN SUMMARY - {len(alerts)} alerts")
    print("="*50)
    by_type = Counter(a.attack_type for a in alerts)
    for attack, count in by_type.most_common():
        print(f"   {attack:<35} {count}")
    print("="*50 + "\n")
    
