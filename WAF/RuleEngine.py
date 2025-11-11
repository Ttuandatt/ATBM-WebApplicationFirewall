# WAF/RuleEngine.py
import re

class RuleEngine:
    def __init__(self):
        self.rules = {
            'SQLInjection': [
                r"(?i)(\bselect\b.*\bfrom\b|\bunion\b.*\bselect\b|\binsert\b.*\binto\b|\bdrop\b.*\btable\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b|\bexec\b.*\bsp_|\bexecute\b|\bor\b.*\b1=1\b|\bor\b.*\b'a'='a\b|--|#|\/\*|\*\*|;|\bwaitfor delay\b)",
                r"(\b'\s*or\s*|\b\"\s*or\s*|\b'\s*=\s*'|\b\"\s*=\s*\")",
            ],
            'XSS': [
                r"(?i)<script.*?>.*?</script>",
                r"(?i)javascript\s*:",
                r"onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=",
                r"eval\s*\(|alert\s*\(|document\.cookie|<img.*src=.*javascript:",
                r"<\s*iframe|<svg.*onload=|<[^>]*on\w+\s*=",
            ],
            'PathTraversal': [
                r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f",
            ],
            'CommandInjection': [
                r";\s*(whoami|id|cat|ls|dir|wget|curl|nc|netcat|bash|sh)",
                r"\|.*(whoami|id|cat|ls)",
            ]
        }

    def detect(self, payload: str, attack_type: str = None) -> tuple[bool, str]:
        payload_lower = payload.lower()
        if attack_type:
            for rule in self.rules.get(attack_type, []):
                if re.search(rule, payload_lower):
                    return True, attack_type
            return False, ""
        else:
            for atk, rules in self.rules.items():
                for rule in rules:
                    if re.search(rule, payload_lower):
                        return True, atk
            return False, ""