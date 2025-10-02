import json, re

def load_rules(file):
    try:
        with open(file) as f:
            return json.load(f)
    except:
        return []

def check_request(rules, path, query, body):
    data = f"{path} {query} {body}"
    for rule in rules:
        if rule["type"] == "regex":
            if re.search(rule["pattern"], data, re.IGNORECASE):
                return True
    return False
