# backend/analyzer.py
"""
analyzer.py: phân tích logs.json (structured JSON per-line logs).
- Hiện tại đọc logs.json (mỗi dòng 1 JSON)
- Gom nhóm BLOCKED events (bao gồm ML_BLOCKED)
- Nếu thấy pattern/substring lặp nhiều lần -> sinh rule tự động thêm vào rules.json
"""

import sys
sys.stdout.reconfigure(encoding='utf-8')
import json
import os
import re
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "waf.log")      # human logs (kept for backwards)
JSON_LOG = os.path.join(BASE_DIR, "logs", "logs.json")    # structured JSON logs
RULES_FILE = os.path.join(BASE_DIR, "rules.json")

# thresholds
DEMO_MODE = True
if DEMO_MODE:
    THRESH_OCCURRENCES = 2
    THRESH_IPS = 1
else:
    THRESH_OCCURRENCES = 5
    THRESH_IPS = 2

AUTO_ENABLE = True  # tự bật rule khi tạo (demo)


def load_json_logs(path=JSON_LOG):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                out.append(obj)
            except Exception:
                # skip non-json lines
                continue
    return out


def read_rules():
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_rules(rules):
    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)


def candidate_pattern_from_snippet(snippet: str, max_len=80):
    """
    Generate a regex pattern candidate from a payload snippet:
    - Trim, escape special regex chars
    - Replace sequences of digits/hex with \d+ optionally
    - Return a safe pattern string.
    """
    if not snippet:
        return None
    s = snippet.strip()
    # shorten if long
    if len(s) > max_len:
        s = s[:max_len]
    # remove leading/trailing whitespace
    s = s.strip()
    # escape regex special chars
    esc = re.escape(s)
    # optionally generalize numbers
    esc = re.sub(r"\\\d\+", r"\\d+", esc)
    # make minimal anchor: search anywhere
    return esc


def analyze_logs():
    logs = load_json_logs(JSON_LOG)
    if not logs:
        print("⚠️ No structured logs.json found to analyze.")
        return

    # collect blocked events, including ML_BLOCKED
    # key by (type, pattern) where pattern may be from matched_rule.pattern or derived from snippet
    stats = {}  # key -> {count, ips, examples}
    for entry in logs:
        ev = entry.get("event", "").upper()
        if ev not in ("BLOCKED", "ML_BLOCKED"):
            continue
        matched = entry.get("matched_rule", {})
        ptype = matched.get("type") or entry.get("type") or "unknown"
        patt = matched.get("pattern")
        snippet = entry.get("payload_snippet") or entry.get("url") or entry.get("path") or ""
        src_ip = entry.get("src_ip")

        # prefer existing pattern from matched_rule if present
        if patt:
            key = (ptype, patt)
        else:
            # derive candidate pattern from snippet
            cand = candidate_pattern_from_snippet(snippet)
            if not cand:
                continue
            key = (ptype if ptype else "ML_CANDIDATE", cand)

        if key not in stats:
            stats[key] = {"count": 0, "ips": set(), "examples": []}
        stats[key]["count"] += 1
        if src_ip:
            stats[key]["ips"].add(src_ip)
        if len(stats[key]["examples"]) < 5 and snippet:
            stats[key]["examples"].append(snippet)

    # load existing rules to avoid duplicates
    rules = read_rules()
    existing = {(r.get("type"), r.get("pattern")) for r in rules if "type" in r and "pattern" in r}
    next_id = max((r.get("id", 0) for r in rules), default=0) + 1

    new_rules = []
    for (ptype, patt), data in stats.items():
        if (ptype, patt) in existing:
            continue
        if data["count"] >= THRESH_OCCURRENCES and len(data["ips"]) >= THRESH_IPS:
            rule = {
                "id": next_id,
                "type": ptype if ptype else "auto",
                "pattern": patt,
                "enabled": AUTO_ENABLE,
                "source": "auto_analyzer",
                "comment": f"Auto-derived from logs ({data['count']} events / {len(data['ips'])} IPs). examples={data['examples']}"
            }
            new_rules.append(rule)
            next_id += 1

    if new_rules:
        rules.extend(new_rules)
        save_rules(rules)
        print(f"✅ Added {len(new_rules)} new rules to {RULES_FILE}:")
        for r in new_rules:
            print(f" - id={r['id']} type={r['type']} pattern={r['pattern']}")
    else:
        print("No new rules reached threshold.")
