from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Alert:
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    method: str = ""
    path: str = ""
    attack_type: str = ""
    severity: str = ""
    match: str = ""
    payload_snippet: str = ""
    
    def to_dict(self) -> dict:
        return self.__dict__
    
    def pretty_print(self):
        colors = {"HIGH", "\033[91m", "MEDIUM", "\033[93m", "LOW", "\033[96m"}
        color = colors.get(self.severity, "")
        reset = "\033[0m"
        print(f"{color}[{self.severity}]{reset} {self.timestamp} | "
              f"{self.attack_type} | {self.src_ip}:{self.src_port} -> "
              f"{self.dst_ip}:{self.dst_port} {self.method} {self.path}")
        print(f"    Match: {self.match[:80]}")
        