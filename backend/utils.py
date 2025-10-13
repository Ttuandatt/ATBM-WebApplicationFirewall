import json, re
from urllib.parse import unquote, unquote_plus
from html import unescape

def load_rules(file):
    try:
        with open(file) as f:
            return json.load(f)
    except:
        return []

def normalize_content(s: str) -> str:  # Di chuyển vào utils để tái sử dụng
    try:
        s2 = unquote(unquote_plus(s))
        s2 = unescape(s2)
    except Exception:
        s2 = s
    return s2.strip()

def check_request(rules, path, query, body, headers="", cookies=""):
    for rule in rules:
        if not rule.get("enabled", False):
            continue
        apply_to = rule.get("apply_to", ["path", "query", "body"])
        content = ""
        if "path" in apply_to:
            content += normalize_content(path) + " "
        if "query" in apply_to:
            content += normalize_content(query) + " "
        if "body" in apply_to:
            content += normalize_content(body) + " "
        if "headers" in apply_to:
            content += normalize_content(headers) + " "
        if "cookie" in apply_to:
            content += normalize_content(cookies) + " "
        if rule.get("_re") and rule["_re"].search(content):
            return True, rule
    return False, None
