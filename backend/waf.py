# waf.py
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import os
import re
import json
import time
import logging
import threading
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from machine_learning.ml_model import predict_request, train_model

app = Flask(__name__)

# =========================================================
# Đường dẫn và cấu hình
# =========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "waf.log")
ANALYZER_FILE = os.path.join(BASE_DIR, "analyzer.py")
LOGS_JSON = os.path.join(BASE_DIR, "logs.json")

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "backend.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# =========================================================
# Utilities
# =========================================================
def load_rules():
    """Load rules.json vào bộ nhớ"""
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception as e:
            logging.error(f"Không thể load rules.json: {e}")
            return []

def log_event(event_type, src_ip, path, details):
    """Ghi log event ra waf.log và logs.json (để ML train)"""
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()

    data = {
        "timestamp": timestamp,
        "event": event_type,
        "src_ip": src_ip,
        "path": path,
        **details
    }

    # ghi log file dạng JSON dòng
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")

    # log train cho ML
    save_to_logs_json(event_type, path)

    logging.info(f"{event_type} from {src_ip} at {path}: {details}")

def save_to_logs_json(event_type, path):
    """Lưu mẫu request để ML training"""
    text = path
    label = 1 if "BLOCKED" in event_type else 0
    record = {"text": text, "label": label}

    data = []
    if os.path.exists(LOGS_JSON):
        try:
            with open(LOGS_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = []

    data.append(record)
    with open(LOGS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def block_response():
    """Trả về phản hồi 403"""
    return jsonify({
        "status": "blocked",
        "message": "Request blocked by Web Application Firewall."
    }), 403

# =========================================================
# Detection logic
# =========================================================
def match_rules(text, rules):
    """Kiểm tra text có match rule nào không"""
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        pattern = rule.get("pattern")
        if not pattern:
            continue
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return rule
        except re.error as e:
            logging.error(f"Lỗi regex ở rule {rule.get('id')}: {e}")
    return None

def inspect_request(req):
    """Gộp nội dung request để phân tích"""
    text_parts = [req.path, req.query_string.decode("utf-8", errors="ignore")]
    try:
        if req.data:
            text_parts.append(req.data.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    return " ".join(text_parts)

def trigger_analyzer():
    """Gọi analyzer.py để tự học rule mới"""
    def run_async():
        os.system(f"python \"{ANALYZER_FILE}\"")
    t = threading.Thread(target=run_async, daemon=True)
    t.start()

def retrain_ml_async():
    """Huấn luyện lại ML model khi có dữ liệu mới"""
    def run_train():
        try:
            train_model()
            logging.info("✅ ML model retrained successfully")
        except Exception as e:
            logging.error(f"❌ ML retrain failed: {e}")
    t = threading.Thread(target=run_train, daemon=True)
    t.start()

# =========================================================
# Flask middleware
# =========================================================
@app.before_request
def waf_filter():
    src_ip = request.remote_addr
    path = request.path
    rules = load_rules()
    text = inspect_request(request)

    # --- Rule-based detection ---
    matched_rule = match_rules(text, rules)
    if matched_rule:
        log_event("BLOCKED", src_ip, path, {"matched_rule": matched_rule})
        trigger_analyzer()
        retrain_ml_async()
        return block_response()

    # --- ML-based detection ---
    try:
        pred, prob = predict_request(text)
        if pred == 1 and prob > 0.7:
            ml_rule = {
                "type": "ML_MODEL",
                "pattern": f"prob={prob:.2f}",
                "enabled": True,
                "source": "xgboost"
            }
            log_event("ML_BLOCKED", src_ip, path, {"matched_rule": ml_rule})
            retrain_ml_async()
            return block_response()
    except FileNotFoundError:
        logging.warning("⚠️ ML model chưa được huấn luyện — bỏ qua kiểm tra ML.")
    except Exception as e:
        logging.error(f"Lỗi ML detection: {e}")

    # --- Nếu không bị chặn ---
    log_event("ALLOWED", src_ip, path, {"info": "passed"})
    return None

# =========================================================
# Flask routes
# =========================================================
@app.route("/")
def index():
    return jsonify({
        "message": "✅ WAF is active and monitoring traffic",
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
