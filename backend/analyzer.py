import re, json

def analyze_logs(log_file="logs/waf.log", rules_file="rules.json"):
    with open(log_file) as f:
        logs = f.readlines()

    suspicious_payloads = [line for line in logs if "BLOCKED" in line]

    new_rules = []
    for entry in suspicious_payloads:
        # ví dụ: phát hiện SQLi
        if "UNION" in entry.upper() or "SELECT" in entry.upper():
            new_rules.append({"type": "regex", "pattern": r"(UNION|SELECT).*FROM"})

        # ví dụ: phát hiện XSS
        if "<script>" in entry.lower():
            new_rules.append({"type": "regex", "pattern": r"<script.*?>.*?</script>"})

    if new_rules:
        with open(rules_file) as f:
            rules = json.load(f)

        rules.extend(new_rules)

        with open(rules_file, "w") as f:
            json.dump(rules, f, indent=2)

        print(f"Added {len(new_rules)} new rules")
    else:
        print("No new rules found.")

if __name__ == "__main__":
    analyze_logs()
