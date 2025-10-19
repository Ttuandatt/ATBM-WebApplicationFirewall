# waf.py
import os
import re
import json
import time
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from ml_model import predict

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "waf.log")

# Setup logging (text-based)
logging.basicConfig(
    filename=os.path.join(BASE_DIR, "logs", "backend.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# =========================================================
# Utilities
# =========================================================
def load_rules():
    """Load rules.json into memory"""
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load rules.json: {e}")
            return []

def log_event(event_type, src_ip, path, details):
    """Append event to waf.log (both plain and JSON format)"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event_type,
        "src_ip": src_ip,
        "path": path,
        **details
    }
    # log JSON
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")
    # human-readable line
    logging.info(f"{event_type} from {src_ip} at {path}: {details}")

def block_response():
    """Return a 403 block message"""
    return jsonify({
        "status": "blocked",
        "message": "Request blocked by Web Application Firewall."
    }), 403

# =========================================================
# Detection
# =========================================================
def match_rules(text, rules):
    """Kiểm tra text có match rule nào không"""
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        ptype = rule.get("type")
        patt = rule.get("pattern")
        if not ptype or not patt:
            continue
        try:
            if re.search(patt, text, re.IGNORECASE):
                return rule
        except re.error as e:
            logging.error(f"Invalid regex in rule {rule.get('id')}: {e}")
    return None

def inspect_request(req):
    """Phân tích nội dung request (URL + body)"""
    text_parts = [req.path, req.query_string.decode("utf-8", errors="ignore")]
    try:
        if req.data:
            text_parts.append(req.data.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    full_text = " ".join(text_parts)
    return full_text

# =========================================================
# Flask routes
# =========================================================
@app.before_request
def waf_filter():
    """Middleware kiểm tra tất cả request"""
    src_ip = request.remote_addr
    path = request.path
    rules = load_rules()
    text = inspect_request(request)

    # --- Rule-based detection ---
    matched_rule = match_rules(text, rules)
    if matched_rule:
        log_event("BLOCKED", src_ip, path, {"matched_rule": matched_rule})
        return block_response()

    # --- ML-based detection ---
    try:
        pred, prob = predict(text)
        if pred == 1:
            ml_rule = {
                "type": "ML_MODEL",
                "pattern": f"prob={prob:.2f}",
                "enabled": True,
                "source": "ml_model"
            }
            log_event("ML_BLOCKED", src_ip, path, {"matched_rule": ml_rule})
            return block_response()
    except FileNotFoundError:
        # Model chưa train -> bỏ qua
        pass
    except Exception as e:
        logging.error(f"ML detection error: {e}")

    # nếu không bị chặn
    log_event("ALLOWED", src_ip, path, {"info": "passed"})
    return None  # cho phép tiếp tục

@app.route("/")
def index():
    return jsonify({
        "message": "WAF is active and monitoring traffic",
        "status": "running"
    })

@app.route("/test", methods=["GET", "POST"])
def test_page():
    return jsonify({
        "message": "This is a test page.",
        "method": request.method,
        "args": request.args,
        "data": request.data.decode("utf-8", errors="ignore")
    })

# =========================================================
# Run
# =========================================================
if __name__ == "__main__":
    app.run(port=5000, debug=True)
