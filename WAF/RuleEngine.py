# WAF/RuleEngine.py
import re
import html
import json
import os
from urllib.parse import unquote
from threading import RLock  # <--- THAY ĐỔI QUAN TRỌNG: Dùng RLock thay vì Lock
from datetime import datetime

# ====== PATHS ======
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(CURRENT_DIR, "rule.json")
RULES_BACKUP = os.path.join(CURRENT_DIR, "rule_backup.json")

# Thread-safe lock (RLock cho phép 1 thread acquire khóa nhiều lần -> Tránh Deadlock)
_RULES_LOCK = RLock()


# ====== HELPER FUNCTIONS ======
def canonicalize_input(s: str, max_rounds: int = 3) -> str:
    """Canonicalize input (multi-decode + HTML unescape)"""
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
        if unescaped == t:
            break
        t = unescaped
    return t


def extract_patterns_from_payload(payload: str, min_length: int = 4):
    patterns = []
    normalized = canonicalize_input(payload)

    # 1. Tìm SQL keywords
    sql_keywords = ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'DECLARE']
    for kw in sql_keywords:
        if re.search(r'\b' + kw + r'\b', normalized, re.IGNORECASE):
            patterns.append((r'\b' + kw + r'\b', f"SQLI_{kw.upper()}"))

    # 2. SQL patterns
    sql_patterns = [
        (r"'\s*(OR|AND)\s*'?\d+'?\s*=\s*'?\d+'?", "SQLI_LOGIC_TRUE"),
        (r"--\s*", "SQLI_COMMENT"),
        (r"/\*.*?\*/", "SQLI_BLOCK_COMMENT"),
        (r";\s*DROP\s+", "SQLI_DROP_TABLE"),
        (r"'\s*OR\s+1\s*=\s*1", "SQLI_OR_TRUE_VARIANT"),
    ]
    for pattern, name in sql_patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            patterns.append((pattern, name))

    # 3. XSS patterns
    xss_patterns = [
        (r"<\s*script\b", "XSS_SCRIPT_TAG"),
        (r"\bon\w+\s*=", "XSS_EVENT_HANDLER"),
        (r"javascript\s*:", "XSS_JS_SCHEME"),
        (r"<\s*(iframe|embed|object)\b", "XSS_EMBED_TAG"),
        (r"\b(alert|prompt|confirm|eval)\s*\(", "XSS_JS_FUNCTION"),
        (r"document\.(cookie|location)", "XSS_DOM_ACCESS"),
    ]
    for pattern, name in xss_patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            patterns.append((pattern, name))

    # 4. Command Injection patterns
    cmd_patterns = [
        (r"[;&|]\s*(cat|ls|pwd|whoami|id|uname)", "CMD_UNIX_BASIC"),
        (r"[;&|]\s*(curl|wget|nc|netcat)", "CMD_NETWORK"),
        (r"\$\(.*?\)", "CMD_SUBSTITUTION"),
        (r"`.*?`", "CMD_BACKTICK"),
        (r"[;&|]\s*(rm|mv|cp|chmod)", "CMD_FILE_OPS"),
    ]
    for pattern, name in cmd_patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            patterns.append((pattern, name))

    return patterns


# ====== RULE STORAGE & LOADING ======
def load_rules_from_json():
    """Load rules từ rule.json"""
    try:
        if not os.path.exists(RULES_FILE):
            init_default_rules()
            return load_rules_from_json()

        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)

        rules = []
        for item in data.get('rules', []):
            try:
                pattern = item['pattern']
                name = item['name']
                regex = re.compile(pattern, re.IGNORECASE)
                rules.append((regex, name))
            except re.error as e:
                print(f"[RuleEngine] Invalid regex pattern '{pattern}': {e}")
                continue
            except KeyError:
                continue

        print(f"[RuleEngine] Loaded {len(rules)} rules from {RULES_FILE}")
        return rules

    except Exception as e:
        print(f"[RuleEngine] Error loading rules: {e}")
        return []


def save_rules_to_json(rules_data):
    """Lưu rules vào rule.json với backup"""
    try:
        # Backup file cũ
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            with open(RULES_BACKUP, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)

        # Ghi file mới
        with open(RULES_FILE, 'w', encoding='utf-8') as f:
            json.dump(rules_data, f, indent=2, ensure_ascii=False)

        print(f"[RuleEngine] Rules saved to {RULES_FILE}")
        return True

    except Exception as e:
        print(f"[RuleEngine] Error saving rules: {e}")
        return False


def init_default_rules():
    """Khởi tạo file rule.json với default rules"""
    default_rules = {
        "version": "1.0",
        "last_updated": datetime.now().isoformat(),
        "rules": [
            {"pattern": r"<\s*script\b", "name": "TAG_SCRIPT_OPEN", "source": "default"},
            {"pattern": r"</\s*script\s*>", "name": "TAG_SCRIPT_CLOSE", "source": "default"},
            {"pattern": r"\bon\w+\s*=", "name": "EVENT_HANDLER_ATTR", "source": "default"},
            {"pattern": r"javascript\s*:", "name": "JS_SCHEME", "source": "default"},
            {"pattern": r"data\s*:\s*text\/html", "name": "DATA_TEXT_HTML", "source": "default"},
            {"pattern": r"vbscript\s*:", "name": "VBS_SCHEME", "source": "default"},
            {"pattern": r"\b(alert|prompt|confirm)\s*\(", "name": "JS_ALERT_PROMPT", "source": "default"},
            {"pattern": r"\beval\s*\(", "name": "JS_EVAL", "source": "default"},
            {"pattern": r"\bsetTimeout\s*\(", "name": "JS_SETTIMEOUT", "source": "default"},
            {"pattern": r"\bsetInterval\s*\(", "name": "JS_SETINTERVAL", "source": "default"},
            {"pattern": r"document\.cookie", "name": "DOC_COOKIE", "source": "default"},
            {"pattern": r"(document|window)\.(location|location\.href)", "name": "DOC_LOCATION", "source": "default"},
            {"pattern": r"<\s*(iframe|object|embed)\b", "name": "EMBED_TAG", "source": "default"},
            {"pattern": r"\bsrcdoc\s*=", "name": "SRC_DOC_ATTR", "source": "default"},
            {"pattern": r"=[^>]*<[^>]*>", "name": "ATTR_CONTAINS_TAG", "source": "default"},
            {"pattern": r"(&#x?3c;|&lt;)\s*script", "name": "ENCODED_SCRIPT", "source": "default"},
            {"pattern": r"\bUNION\s+SELECT\b", "name": "SQLI_UNION_SELECT", "source": "default"},
            {"pattern": r"\bOR\s+'1'\s*=\s*'1'\b", "name": "SQLI_OR_TRUE", "source": "default"},
        ]
    }
    save_rules_to_json(default_rules)


# Load rules khi import module
RULES = load_rules_from_json()


# ====== DETECTION FUNCTION ======
def is_malicious_rule(payload: str):
    """
    Check payload against ordered regex rules.
    Returns (True, rule_name) if matched, else (False, None)
    """
    try:
        if not payload:
            return False, None

        normalized = canonicalize_input(payload)

        if len(normalized.strip()) < 2:
            return False, None

        with _RULES_LOCK:
            current_rules = RULES

        for regex, name in current_rules:
            try:
                if regex.search(normalized):
                    return True, name
            except re.error:
                continue

        return False, None

    except Exception:
        return False, None


# ====== AUTO-UPDATE FROM ML ======
def update_rules_from_ml_detection(payload: str, attack_type: str = "UNKNOWN"):
    try:
        new_patterns = extract_patterns_from_payload(payload)
        if not new_patterns:
            return False

        with _RULES_LOCK:
            if not os.path.exists(RULES_FILE):
                init_default_rules()

            with open(RULES_FILE, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)

            existing_patterns = {r['pattern'] for r in rules_data['rules']}
            added_count = 0

            for pattern, rule_name in new_patterns:
                if pattern not in existing_patterns:
                    new_rule = {
                        "pattern": pattern,
                        "name": f"ML_{rule_name}",
                        "source": "ml_detection",
                        "attack_type": attack_type,
                        "created_at": datetime.now().isoformat(),
                        "sample_payload": payload[:100]
                    }
                    rules_data['rules'].append(new_rule)
                    existing_patterns.add(pattern)
                    added_count += 1
                    print(f"[RuleEngine] Added new rule: {rule_name}")

            if added_count > 0:
                rules_data['last_updated'] = datetime.now().isoformat()
                rules_data['version'] = str(float(rules_data.get('version', '1.0')) + 0.1)

                if save_rules_to_json(rules_data):
                    reload_rules() # RLock allows re-entry here
                    return True
            else:
                return False

    except Exception as e:
        print(f"[RuleEngine] Error updating rules from ML: {e}")
        return False


def reload_rules():
    """Manually reload rules từ file (dùng cho hot-reload)"""
    global RULES
    with _RULES_LOCK:
        RULES = load_rules_from_json()
    print(f"[RuleEngine] Rules reloaded: {len(RULES)} rules active")


# ====== RULE MANAGEMENT API ======
def get_all_rules():
    """Lấy danh sách tất cả rules"""
    try:
        # Không cần lock khi chỉ đọc file json (OS handle việc này),
        # hoặc có thể dùng lock nếu muốn đồng bộ tuyệt đối.
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {"rules": []}


# Cập nhật thêm tham số description, severity, source
def add_manual_rule(pattern: str, name: str, attack_type: str = "MANUAL",
                    description: str = "", severity: str = "medium", source: str = "manual"):
    try:
        re.compile(pattern, re.IGNORECASE)

        with _RULES_LOCK:
            rules_data = get_all_rules()

            for r in rules_data['rules']:
                if r['pattern'] == pattern:
                    print(f"[RuleEngine] Rule already exists: {pattern}")
                    return False

            new_rule = {
                "pattern": pattern,
                "name": name,
                "source": source,          # <--- Lưu source từ tham số
                "attack_type": attack_type,
                "severity": severity,      # <--- Lưu severity
                "description": description,# <--- Lưu description
                "created_at": datetime.now().isoformat()
            }
            rules_data['rules'].append(new_rule)
            rules_data['last_updated'] = datetime.now().isoformat()

            if save_rules_to_json(rules_data):
                reload_rules()
                print(f"[RuleEngine] Successfully added rule: {name}")
                return True

            print(f"[RuleEngine] Failed to save rule: {name}")
            return False

    except re.error as e:
        print(f"[RuleEngine] Invalid regex: {e}")
        return False
    except Exception as e:
        print(f"[RuleEngine] Error adding manual rule: {e}")
        return False

def delete_rule(pattern: str):
    """Xóa rule theo pattern"""
    try:
        with _RULES_LOCK:
            rules_data = get_all_rules()
            original_count = len(rules_data['rules'])

            rules_data['rules'] = [r for r in rules_data['rules'] if r['pattern'] != pattern]

            if len(rules_data['rules']) < original_count:
                rules_data['last_updated'] = datetime.now().isoformat()
                if save_rules_to_json(rules_data):
                    reload_rules()
                    print(f"[RuleEngine] Rule deleted: {pattern}")
                    return True

            print(f"[RuleEngine] Rule not found: {pattern}")
            return False

    except Exception as e:
        print(f"[RuleEngine] Error deleting rule: {e}")
        return False