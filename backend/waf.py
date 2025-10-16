# waf.py — Web Application Firewall (finalized)
from flask import Flask, request, Response, jsonify
import requests, json, logging, os, re, threading, subprocess, time
from datetime import datetime, timezone
from urllib.parse import unquote_plus

app = Flask(__name__)

BACKEND_URL = "http://localhost:5001"
RULES_FILE = "rules.json"
LOG_DIR = "logs"
TEXT_LOG = os.path.join(LOG_DIR, "waf.log")      # log text / debug
JSON_LOG = os.path.join(LOG_DIR, "logs.json")    # log JSON cho analyzer
ANALYZER_SCRIPT = os.path.join(os.path.dirname(__file__), "analyzer.py")
ANALYZER_OUT = os.path.join(LOG_DIR, "analyzer.out")

# ========= Cấu hình logging =========
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(filename=TEXT_LOG, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# ========= Tham số debounce cho analyzer =========
DEBOUNCE_SEC = 10
_last_analyzer_trigger = 0
_analyzer_lock = threading.Lock()

# ========= Tiện ích =========
def load_rules_file(path=RULES_FILE):
    """Đọc và compile các rule regex."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load rules: {e}")
        return []

    compiled = []
    for r in rules:
        try:
            patt = r.get("pattern", "")
            r["_re"] = re.compile(patt, re.I | re.S)
        except Exception as e:
            logging.error(f"Regex compile error for pattern '{r.get('pattern')}': {e}")
            r["_re"] = None
        compiled.append(r)
    return compiled


def normalize_content(s: str) -> str:
    """Giải mã URL encoding và loại bỏ khoảng trắng."""
    try:
        s2 = unquote_plus(s)
    except Exception:
        s2 = s
    return s2.strip()


def safe_matched_rule_for_log(rule):
    """Loại bỏ các object không serialize được như Pattern."""
    if not rule:
        return {}
    allowed = ["id", "type", "pattern", "source"]
    return {k: rule[k] for k in allowed if k in rule}


def append_json_log(entry: dict):
    """Append 1 event JSON vào logs.json (mỗi dòng 1 object JSON)."""
    try:
        with open(JSON_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logging.error(f"Write json log error: {e}")


# ========= Analyzer trigger (debounced) =========
def trigger_analyzer_async():
    """Gọi analyzer.py nền, tránh spam (debounce)."""
    global _last_analyzer_trigger
    now = time.time()
    with _analyzer_lock:
        if now - _last_analyzer_trigger < DEBOUNCE_SEC:
            logging.info("Analyzer trigger skipped (debounce).")
            return
        _last_analyzer_trigger = now

    try:
        with open(ANALYZER_OUT, "a", encoding="utf-8") as out:
            subprocess.Popen(
                ["python", ANALYZER_SCRIPT],
                cwd=os.path.dirname(ANALYZER_SCRIPT),
                stdout=out,
                stderr=out
            )
        logging.info("Analyzer triggered (background).")
    except Exception as e:
        logging.error(f"Failed to trigger analyzer: {e}")


# ========= Heuristic Attack Detection =========
def detect_suspicious_payload(content):
    """Phát hiện tấn công chưa có rule (live detection)."""
    patterns = [
        (r"(?:'|\")?\s*(UNION|SELECT|INSERT|UPDATE|DELETE)\s+.*\s+FROM", "SQLI_LIVE"),
        (r"(?i)(?:\bor\b|\bor\b).{0,10}?[\d'\"`]+\s*=\s*[\d'\"`]+", "SQL_TAUTOLOGY"),
        (r"<script.*?>.*?</script>", "XSS_LIVE"),
        (r"onerror\s*=", "XSS_LIVE"),
        (r"javascript:", "XSS_LIVE"),
        (r"\.\./", "PATH_TRAVERSAL"),
        (r"\.(php|phtml|jsp|asp|aspx)\b", "SUSPICIOUS_FILE")
    ]
    for patt, ptype in patterns:
        try:
            if re.search(patt, content, re.I | re.S):
                return ptype, patt
        except re.error:
            continue
    return None, None


# ========= WAF core =========
@app.before_request
def waf_filter():
    rules = load_rules_file(RULES_FILE)
    path = request.path or ""
    query = request.query_string.decode() or ""
    body = request.get_data(as_text=True) or ""
    src_ip = request.remote_addr or ""
    url = path + (("?" + query) if query else "")
    content = normalize_content(f"{path} {query} {body}")

    # (1) Kiểm tra rule có sẵn
    for rule in rules:
        if not rule.get("enabled", False):
            continue
        reobj = rule.get("_re")
        if reobj and reobj.search(content):
            timestamp = datetime.now(timezone.utc).isoformat()
            logging.warning(f"BLOCKED [{rule['type']}] (id={rule.get('id')}) : {rule.get('pattern')} -- {url}")

            append_json_log({
                "timestamp": timestamp,
                "event": "BLOCKED",
                "src_ip": src_ip,
                "url": url,
                "payload_snippet": content[:300],
                "matched_rule": safe_matched_rule_for_log(rule)
            })

            trigger_analyzer_async()

            return jsonify({
                "message": f"Blocked by WAF (rule {rule.get('id')})",
                "rule": {"id": rule.get('id'), "type": rule.get('type')}
            }), 403

    # (2) Phát hiện tấn công mới (live detection)
    attack_type, patt = detect_suspicious_payload(content)
    if attack_type:
        timestamp = datetime.now(timezone.utc).isoformat()
        logging.warning(f"BLOCKED [NEW_{attack_type}]: pattern={patt} -- url={url}")

        matched = {
            "id": None,
            "type": attack_type,
            "pattern": patt,
            "source": "live_detection"
        }

        append_json_log({
            "timestamp": timestamp,
            "event": "BLOCKED",
            "src_ip": src_ip,
            "url": url,
            "payload_snippet": content[:300],
            "matched_rule": matched
        })

        trigger_analyzer_async()

        return jsonify({
            "message": f"Blocked instantly (detected {attack_type})",
            "rule": {"type": attack_type, "pattern": patt}
        }), 403

    # (3) Nếu hợp lệ -> forward (proxy)
    timestamp = datetime.now(timezone.utc).isoformat()
    append_json_log({
        "timestamp": timestamp,
        "event": "ALLOWED",
        "src_ip": src_ip,
        "url": url,
        "payload_snippet": (body or "")[:300]
    })
    logging.info(f"ALLOWED {src_ip} {url}")
    return None


# ========= Proxy handler =========
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    try:
        resp = requests.request(
            method=request.method,
            url=f"{BACKEND_URL}/{path}",
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10
        )
    except requests.RequestException:
        return Response("Backend error", status=502)

    excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    response_headers = [
        (name, value)
        for (name, value) in resp.headers.items()
        if name.lower() not in excluded_headers
    ]
    return Response(resp.content, status=resp.status_code, headers=response_headers)


if __name__ == "__main__":
    app.run(port=5000, debug=True)
