# analyzer.py
import sys
sys.stdout.reconfigure(encoding='utf-8')
import json, os
from datetime import datetime

LOG_FILE = "logs/waf.log"
RULES_FILE = "rules.json"

# Demo / production switches
DEMO_MODE = True

if DEMO_MODE:
    THRESHOLD_OCCURRENCES = 2   # demo: chỉ cần 2 lần
    THRESHOLD_IPS = 1           # demo: 1 IP là đủ
else:
    THRESHOLD_OCCURRENCES = 3   # production example
    THRESHOLD_IPS = 2

AUTO_ENABLE = True  # nếu True -> tự bật rule (demo). Trong prod có thể False (require review).

def analyze_logs():
    if not os.path.exists(LOG_FILE):
        print("⚠️ Không có log để phân tích.")
        return

    # đọc từng dòng JSON trong log (mỗi dòng json là 1 entry)
    lines = []
    with open(LOG_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # chỉ parse các dòng bắt đầu bằng '{' (chỉ JSON structured logs)
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    lines.append(obj)
                except Exception as e:
                    # có thể có human-readable log lines mixed in -> bỏ qua
                    print(f"Bỏ qua log không parse được: {e}")

    # thống kê: key = (type, pattern) -> count + set(ips)
    stats = {}
    for entry in lines:
        if entry.get("event") != "BLOCKED":
            continue
        rule = entry.get("matched_rule", {})
        ptype = rule.get("type")
        patt = rule.get("pattern")
        if not ptype or not patt:
            continue
        key = (ptype, patt)
        if key not in stats:
            stats[key] = {"count": 0, "ips": set()}
        stats[key]["count"] += 1
        if entry.get("src_ip"):
            stats[key]["ips"].add(entry.get("src_ip"))

    # đọc rules hiện có
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                rules = json.load(f)
        except Exception:
            rules = []
    else:
        rules = []

    existing = {(r.get("type"), r.get("pattern")) for r in rules if "type" in r and "pattern" in r}
    next_id = max((r.get("id", 0) for r in rules), default=0) + 1

    new_rules = []
    for (ptype, patt), data in stats.items():
        if (ptype, patt) in existing:
            continue
        if data["count"] >= THRESHOLD_OCCURRENCES and len(data["ips"]) >= THRESHOLD_IPS:
            new_rule = {
                "id": next_id,
                "type": ptype,
                "pattern": patt,
                "enabled": AUTO_ENABLE,
                "source": "auto_analyzer",
                "comment": f"Tự sinh từ logs ({data['count']} lần / {len(data['ips'])} IP)"
            }
            new_rules.append(new_rule)
            next_id += 1

    if new_rules:
        rules.extend(new_rules)
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2, ensure_ascii=False)
        print(f"✅ Đã thêm {len(new_rules)} rule mới vào {RULES_FILE}:")
        for r in new_rules:
            print(f"   - id={r['id']} type={r['type']} pattern={r['pattern']}")
    else:
        print("Không có rule mới đạt ngưỡng.")

if __name__ == "__main__":
    analyze_logs()
