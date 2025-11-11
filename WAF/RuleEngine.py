# WAF/RuleEngine.py
import re

# Danh sách rule (regex) riêng
RULES = [
    r"<script>.*</script>",       # XSS
    r"UNION\s+SELECT",            # SQL injection union
    r"OR\s+'1'='1",               # SQL injection bypass
]

def is_malicious_rule(payload: str):
    """
    Check payload against simple regex rules.
    Returns (True, pattern) if matched, else (False, None)
    """
    for pattern in RULES:
        if re.search(pattern, payload, re.IGNORECASE):
            return True, pattern
    return False, None
