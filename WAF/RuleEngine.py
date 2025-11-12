# WAF/RuleEngine.py
import re
import html
from urllib.parse import unquote


# Helper: canonicalize input (multi-decode + HTML unescape)
def canonicalize_input(s: str, max_rounds: int = 3) -> str:
    if s is None:
        return ""
    t = s
    for _ in range(max_rounds):
        try:
            decoded = unquote(t)
        except Exception:
            decoded = t
        try:
            unescaped = html.unescape(decoded)
        except Exception:
            unescaped = decoded
        # if nothing changed, break early
        if unescaped == t:
            break
        t = unescaped
    return t


# RULES: list of tuples (compiled_regex, rule_name)
# Order matters: put higher-confidence / cheap checks first.
RULES = [
    # script tags
    (re.compile(r"<\s*script\b", re.IGNORECASE), "TAG_SCRIPT_OPEN"),
    (re.compile(r"</\s*script\s*>", re.IGNORECASE), "TAG_SCRIPT_CLOSE"),

    # common inline event handler attributes (onclick=, onerror=, ...)
    (re.compile(r"\bon\w+\s*=", re.IGNORECASE), "EVENT_HANDLER_ATTR"),

    # javascript: URIs
    (re.compile(r"javascript\s*:", re.IGNORECASE), "JS_SCHEME"),

    # data:text/html and vbscript:
    (re.compile(r"data\s*:\s*text\/html", re.IGNORECASE), "DATA_TEXT_HTML"),
    (re.compile(r"vbscript\s*:", re.IGNORECASE), "VBS_SCHEME"),

    # inline JS functions often used in XSS
    (re.compile(r"\b(alert|prompt|confirm)\s*\(", re.IGNORECASE), "JS_ALERT_PROMPT"),
    (re.compile(r"\beval\s*\(", re.IGNORECASE), "JS_EVAL"),
    (re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE), "JS_SETTIMEOUT"),
    (re.compile(r"\bsetInterval\s*\(", re.IGNORECASE), "JS_SETINTERVAL"),

    # DOM-access / cookies
    (re.compile(r"document\.cookie", re.IGNORECASE), "DOC_COOKIE"),
    (re.compile(r"(document|window)\.(location|location\.href)", re.IGNORECASE), "DOC_LOCATION"),

    # iframe / embed / object
    (re.compile(r"<\s*(iframe|object|embed)\b", re.IGNORECASE), "EMBED_TAG"),

    # srcdoc attribute
    (re.compile(r"\bsrcdoc\s*=", re.IGNORECASE), "SRC_DOC_ATTR"),

    # attribute values that contain < or > (suspicious inline HTML)
    (re.compile(r"=[^>]*<[^>]*>", re.IGNORECASE), "ATTR_CONTAINS_TAG"),

    # encoded forms of <script> (entities)
    (re.compile(r"(&#x?3c;|&lt;)\s*script", re.IGNORECASE), "ENCODED_SCRIPT"),

    # SQLi-ish patterns (simple)
    (re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE), "SQLI_UNION_SELECT"),
    (re.compile(r"\bOR\s+'1'\s*=\s*'1'\b", re.IGNORECASE), "SQLI_OR_TRUE"),
]


def is_malicious_rule(payload: str):
    """
    Check payload against ordered regex rules.
    Returns (True, rule_name) if matched, else (False, None)
    """
    try:
        if not payload:
            return False, None

        # canonicalize (URL-decode + HTML-unescape) to reveal obfuscated attempts
        normalized = canonicalize_input(payload)

        # small heuristic: ignore very short payloads
        if len(normalized.strip()) < 2:
            return False, None

        # run rules in order
        for regex, name in RULES:
            try:
                if regex.search(normalized):
                    return True, name
            except re.error:
                # if a regex is malformed, skip it (shouldn't happen)
                continue

        return False, None
    except Exception:
        # On unexpected errors, fail closed? Here we choose fail-safe: not malicious
        # but you can change to (True, "ERROR") if you prefer blocking.
        return False, None
