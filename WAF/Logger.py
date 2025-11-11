# WAF/Logger.py
import json
from datetime import datetime
import os

LOG_FILE = "logs/waf_logs.json"

os.makedirs("logs", exist_ok=True)

def log_request(client_ip, method, path, payloads, violation=None, ml_result=None):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": client_ip,
        "method": method,
        "path": path,
        "payloads": payloads,
        "violation": violation,
        "ml_result": ml_result
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")