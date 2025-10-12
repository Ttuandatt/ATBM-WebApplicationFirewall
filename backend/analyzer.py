import json, os, re
from datetime import datetime, timedelta

LOG_FILE = "logs/waf.log"
RULES_FILE = "rules.json"

# Ngưỡng sinh rule tự động
THRESHOLDS = {
    "XSS": {"occurrences": 3, "ips": 2},
    "SQLi": {"occurrences": 2, "ips": 1},
    "LFI": {"occurrences": 2, "ips": 1},
    "default": {"occurrences": 3, "ips": 2}
}
AUTO_ENABLE = True

def analyze_logs():
    if not os.path.exists(LOG_FILE):
        print("⚠️ Không có log để phân tích.")
        return

    with open(LOG_FILE, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip().startswith("{")]

    # Gom nhóm theo pattern + type (bao gồm cả BLOCKED và ALERT)
    stats = {}
    for entry in lines:
        if entry.get("event") not in [ "BLOCKED", "ALERT" ]:
            continue
        rule = entry.get("matched_rule", {})
        ptype = rule.get("type")
        patt = rule.get("pattern")
        if not ptype or not patt:
            continue

        key = (ptype, patt)
        stats.setdefault(key, {"count": 0, "ips": set()})
        stats[key]["count"] += 1
        if "src_ip" in entry:
            stats[key]["ips"].add(entry["src_ip"])

    # Đọc rules cũ
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                rules = json.load(f)
        except Exception:
            rules = []
    else:
        rules = []

    existing = {(r["type"], r["pattern"]): i for i, r in enumerate(rules)}  # Index để cập nhật
    next_id = max((r.get("id", 0) for r in rules), default=0) + 1

    new_rules = []
    updated_rules = 0
    threshold_default = THRESHOLDS["default"]
    # Kiểm tra cập nhật rule cũ (bật lại nếu disabled và đạt ngưỡng)
    for i, rule in enumerate(rules):
        key = (rule["type"], rule["pattern"])
        if key in stats and not rule.get("enabled", False):
            ptype = rule["type"]
            threshold = THRESHOLDS.get(ptype, threshold_default)
            if stats[key]["count"] >= threshold["occurrences"] and len(stats[key]["ips"]) >= threshold["ips"]:
                rules[i]["enabled"] = True
                if "comment" in rules[i]:
                    rules[i]["comment"] += f" | Bật lại do phát hiện {stats[key]['count']} lần từ {len(stats[key]['ips'])} IP."
                updated_rules += 1


    for (ptype, patt), data in stats.items():
        if (ptype, patt) in existing:
            continue
        THRESHOLD= THRESHOLDS.get(ptype, threshold_default)
        if data["count"] >= THRESHOLD['occurrences'] and len(data["ips"]) >= THRESHOLD['ips']:
            new_rules.append({
                "id": next_id,
                "type": ptype,
                "pattern": patt,
                "enabled": AUTO_ENABLE,
                "source": "auto_analyzer",
                "apply_to": ["path", "query", "body"],  # Mặc định
                "severity": "medium",  # Mặc định
                "action": "block",  # Mặc định
                "comment": f"Tự sinh từ logs ({data['count']} lần / {len(data['ips'])} IP)"
            })
            next_id += 1

    if new_rules:
        rules.extend(new_rules)
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2, ensure_ascii=False)
        print(f"✅ Đã thêm {len(new_rules)} rule mới vào rules.json.")
    else:
        print("Không có rule mới đạt ngưỡng.")


if __name__ == "__main__":
    analyze_logs()
