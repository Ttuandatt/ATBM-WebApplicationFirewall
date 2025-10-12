from flask import Flask, request, Response, jsonify
import requests, json, logging, os, re
from datetime import datetime, timezone
from urllib.parse import unquote, unquote_plus
from html import unescape
from utils import check_request

app = Flask(__name__)

BACKEND_URL = "http://localhost:5001"
RULES_FILE = "rules.json"
LOGFILE = os.path.join("logs", "waf.log")

# cấu hình log
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename=LOGFILE, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")


# ==================== Tiện ích ====================
def load_rules_file(path=RULES_FILE):
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
            logging.error(f"Regex compile error: {e}")
            r["_re"] = None
        compiled.append(r)
    return compiled


def normalize_content(s: str) -> str:
    try:
        s2 = unquote(unquote_plus(s)) # decode URL encoding
        s2 = unescape(s2)  # decode HTML entities
    except Exception:
        s2 = s
    return s2.strip()


def append_json_log(entry: dict):
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logging.error(f"Write json log error: {e}")


# ==================== Heuristic Attack Detection ====================
# dùng để chặn tấn công mới chưa có rule
def detect_suspicious_payload(content):
    patterns = [
        # SQLi
        (r"(?:'|\")?\s*(UNION|SELECT|INSERT|UPDATE|DELETE)\s+.*\s+FROM", "SQLI_LIVE"),
        # XSS
        (r"<script.*?>.*?</script>", "XSS_LIVE"),
        (r"onerror\s*=", "XSS_LIVE"),
        (r"javascript:", "XSS_LIVE"),
        # LFI / RFI
        (r"\.\./", "PATH_TRAVERSAL"),
        # Dangerous file upload
        (r"\.(php|phtml|jsp|asp|aspx)\b", "SUSPICIOUS_FILE")
    ]

    for patt, ptype in patterns:
        if re.search(patt, content, re.I | re.S):
            return ptype, patt
    return None, None


# ==================== WAF core ====================
@app.before_request
def waf_filter():
    rules = load_rules_file(RULES_FILE)

    path = request.path or ""
    query = request.query_string.decode() if request.query_string else ""
    body = request.get_data(as_text=True) or ""
    src_ip = request.remote_addr or ""
    headers = " ".join(f"{k}:{v}" for k, v in request.headers.items())
    cookies = "; ".join(f"{k}={v}" for k, v in request.cookies.items())
    url = path + (("?" + query) if query else "")
    content = normalize_content(f"{path} {query} {body}")
# ================ Xử lý action: Nếu "alert", chỉ log mà không block =======================
    # Sử dụng check_request từ utils.py
    is_matched, matched_rule = check_request(rules, path, query, body, headers, cookies)

    if is_matched:
        timestamp = datetime.now(timezone.utc).isoformat()
        action = matched_rule.get("action", "block")
        event = "BLOCKED" if action == "block" else "ALERT"
        content = normalize_content(f"{path} {query} {body} {headers} {cookies}")  # For log
        log_entry = {
            "timestamp": timestamp,
            "event": event,
            "src_ip": src_ip,
            "url": url,
            "payload_snippet": content[:300],
            "matched_rule": matched_rule
        }
        logging.warning(f"{event} [{matched_rule['type']}] (id={matched_rule['id']}): {matched_rule['pattern']} -- {url}")
        append_json_log(log_entry)
        
        if action == "block":
            return jsonify({
                "message": f"Blocked by WAF (rule {matched_rule['id']})",
                "rule": {"id": matched_rule["id"], "type": matched_rule["type"], "severity": matched_rule.get("severity", "unknown")}
            }), 403
        # Nếu action="alert" hoặc "log", chỉ ghi log và tiếp tục

    # Log allowed requests
    timestamp = datetime.now(timezone.utc).isoformat()
    append_json_log({
        "timestamp": timestamp,
        "event": "ALLOWED",
        "src_ip": src_ip,
        "url": url,
        "payload_snippet": body[:300]
    })
    logging.info(f"ALLOWED {src_ip} {url}")
    return None

#=======================================
    # # (1) Kiểm tra rule có sẵn
    # for rule in rules:
    #     if not rule.get("enabled", False):
    #         continue
    #     reobj = rule.get("_re")
    #     if reobj and reobj.search(content):
    #         timestamp = datetime.now(timezone.utc).isoformat()
    #         logging.warning(f"BLOCKED [{rule['type']}] (id={rule['id']}): {rule['pattern']} -- {url}")
    #         append_json_log({
    #             "timestamp": timestamp,
    #             "event": "BLOCKED",
    #             "src_ip": src_ip,
    #             "url": url,
    #             "payload_snippet": content[:300],
    #             "matched_rule": rule
    #         })
    #         return jsonify({
    #             "message": f"Blocked by WAF (rule {rule['id']})",
    #             "rule": {"id": rule["id"], "type": rule["type"]}
    #         }), 403

    # # (2) Phát hiện tấn công mới chưa có rule
    # attack_type, patt = detect_suspicious_payload(content)
    # if attack_type:
    #     timestamp = datetime.now(timezone.utc).isoformat()
    #     logging.warning(f"BLOCKED [NEW_{attack_type}]: pattern={patt} -- url={url}")

    #     append_json_log({
    #         "timestamp": timestamp,
    #         "event": "BLOCKED",
    #         "src_ip": src_ip,
    #         "url": url,
    #         "payload_snippet": content[:300],
    #         "matched_rule": {
    #             "id": None,
    #             "type": attack_type,
    #             "pattern": patt,
    #             "source": "live_detection"
    #         }
    #     })
    #     return jsonify({
    #         "message": f"Blocked instantly (detected {attack_type})",
    #         "rule": {"type": attack_type, "pattern": patt}
    #     }), 403

    # # (3) Nếu hợp lệ -> forward
    # timestamp = datetime.utcnow().isoformat() + "Z"
    # append_json_log({
    #     "timestamp": timestamp,
    #     "event": "ALLOWED",
    #     "src_ip": src_ip,
    #     "url": url,
    #     "payload_snippet": (body or "")[:300]
    # })
    # logging.info(f"ALLOWED {src_ip} {url}")
    # return None


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    try:
        resp = requests.request(
            method=request.method,
            url=f"{BACKEND_URL}/{path}",
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            params=request.args,
            data=request.get_data(),
            allow_redirects=False,
            timeout=10
        )
    except requests.RequestException:
        return Response("Backend error", status=502)

    return Response(resp.content, status=resp.status_code, headers=resp.headers.items())


if __name__ == "__main__":
    app.run(port=5000, debug=True)
