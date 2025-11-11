# WAF/FlaskSimpleTest.py
from WAF.RuleEngine import is_malicious_rule  # import hàm từ RuleEngine.py
from flask import Flask, request, render_template, render_template_string
import os, json, time, re, pandas as pd, joblib
from WAF import RetrainModule

# === Load ML model ===
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "TrainingModels", "BinaryClassification", "saved_models", "AdaptiveWAF")
MODEL_PATH = os.path.join(MODEL_DIR, "waf_model.pkl")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

waf_pipeline = joblib.load(MODEL_PATH)

# === Log file ===
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "waf_logs.json")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# === Prediction function ===
def predict_payload_ml(payload):
    df = pd.DataFrame([{
        "payload": payload,
        "payload_length": len(payload),
        "special_chars_ratio": len(re.findall(r"[^a-zA-Z0-9\s]", payload)) / (len(payload)+1)
    }])
    try:
        pred = waf_pipeline.predict(df)[0]
        prob = waf_pipeline.predict_proba(df)[0]
        malicious_prob = prob[1] if len(prob) > 1 else prob[0]
        return {
            "is_malicious": bool(pred),
            "probability": float(malicious_prob),
            "label": "MALICIOUS" if pred else "LEGAL"
        }
    except Exception as e:
        return {"is_malicious": False, "probability": 0.0, "label": "ERROR"}

# === Logging ===
def log_request(payload, ip, method, detection_type, label, probability, rule_pattern=None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "method": method,
        "payload": payload,
        "detection_type": detection_type,
        "rule_pattern": rule_pattern,
        "label": label,
        "probability": probability
    }
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except:
            logs = []
    logs.append(entry)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

# === Flask app ===
app = Flask(__name__)
HTML_TEMPLATE = open(os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")).read()

@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route("/test")
def test_payload():
    payload = request.args.get("payload", "").strip()
    ip = request.remote_addr or "unknown"
    if not payload:
        return render_template_string(HTML_TEMPLATE, result=None)

    # 1️⃣ Rule check
    rule_hit, pattern = is_malicious_rule(payload)
    if rule_hit:
        result = {"payload": payload, "is_malicious": True, "probability": 1.0, "label": "MALICIOUS (Rule-Based)"}
        log_request(payload, ip, "GET", "rule", result["label"], result["probability"], rule_pattern=pattern)
    else:
        # 2️⃣ ML prediction
        result_ml = predict_payload_ml(payload)
        result = {**result_ml, "payload": payload}
        log_request(payload, ip, "GET", "ml", result["label"], result["probability"])

    return render_template_string(HTML_TEMPLATE, result=result)

@app.route("/user/<path:payload>")
def user_payload(payload):
    ip = request.remote_addr or "unknown"
    rule_hit, pattern = is_malicious_rule(payload)
    if rule_hit:
        result = {"payload": payload, "is_malicious": True, "probability": 1.0, "label": "MALICIOUS (Rule-Based)"}
        log_request(payload, ip, "GET", "rule", result["label"], result["probability"], rule_pattern=pattern)
    else:
        result_ml = predict_payload_ml(payload)
        result = {**result_ml, "payload": payload}
        log_request(payload, ip, "GET", "ml", result["label"], result["probability"])

    return render_template_string(HTML_TEMPLATE, result=result)

# ====== Retrain Dashboard ======
@app.route("/retrain")
def retrain_dashboard():
    # 1️⃣ Đọc logs
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    # 2️⃣ Tách payload và ghi vào access_log.txt
    payload_count = RetrainModule.extract_payloads_to_raw()

    # Chỉ lấy 50 log gần nhất
    logs = list(reversed(logs[-50:]))

    return render_template(
        "retrain.html",
        payload_count=payload_count,
        logs=logs
    )

@app.route("/retrain/start", methods=["POST"])
def retrain_start():
    import io
    import sys

    # Capture stdout
    buffer = io.StringIO()
    sys_stdout = sys.stdout
    sys.stdout = buffer

    try:
        RetrainModule.retrain_models()
        output = buffer.getvalue()
    finally:
        sys.stdout = sys_stdout

    return f"""
    <html>
    <head><title>Retrain Output</title></head>
    <body>
        <h1>Retrain Finished</h1>
        <pre>{output}</pre>
        <a href="/retrain">Back to Retrain Dashboard</a> | <a href="/">Back to Main Dashboard</a>
    </body>
    </html>
    """

# ====== Run Flask server ======
if __name__ == "__main__":
    print("==============================================================================================")
    print("                     AdaptiveWAF Demo Dashboard running on http://127.0.0.1:5000")
    print("==============================================================================================")

    print("Available endpoints:")
    for rule in app.url_map.iter_rules():
        methods = ",".join(rule.methods - {"HEAD", "OPTIONS"})
        print(f"  [{methods}] {rule}")

    print("\nTry some examples:")
    print("  → http://127.0.0.1:5000/")
    print("  → http://127.0.0.1:5000/test?payload=SELECT%20*%20FROM%20users")
    print("  → http://127.0.0.1:5000/user/normal%20input")
    print("  → http://127.0.0.1:5000/retrain")
    print("==============================================================================================")

    app.run(host="127.0.0.1", port=5000, debug=True)
