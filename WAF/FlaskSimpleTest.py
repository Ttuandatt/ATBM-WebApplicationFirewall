from RuleEngine import is_malicious_rule
import RuleEngine
from flask import Flask, request, render_template, render_template_string, jsonify, make_response
import os, json, time, re, pandas as pd, joblib
import RetrainModule
from RuleManager import register_rule_api, rule_api

# === Load ML model ===
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "TrainingModels", "BinaryClassification", "saved_models",
                         "AdaptiveWAF")
MODEL_PATH = os.path.join(MODEL_DIR, "waf_model.pkl")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

waf_pipeline = joblib.load(MODEL_PATH)

# === Log file ===
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "waf_logs.json")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


# ✅ THÊM: Helper function để xác định loại tấn công
def determine_attack_type(payload: str) -> str:
    """
    Xác định loại tấn công cụ thể dựa trên payload
    """
    payload_lower = payload.lower()

    # XSS patterns
    if any(kw in payload_lower for kw in ['<script', 'onerror', 'onclick', 'javascript:', 'alert(', 'prompt(']):
        return "XSS"

    # SQLi patterns
    if any(kw in payload_lower for kw in
           ['union', 'select', 'insert', 'update', 'delete', 'drop', "' or '", '" or "', '--']):
        return "SQLi"

    # Command Injection patterns
    if any(kw in payload_lower for kw in ['&&', '||', ';cat', ';ls', ';whoami', '`', '$(', '|cat', '|ls']):
        return "CMDi"

    # Path Traversal
    if '../' in payload or '..\\' in payload:
        return "PathTraversal"

    # Default
    return "UNKNOWN"


# === Prediction function ===
def predict_payload_ml(payload):
    df = pd.DataFrame([{
        "payload": payload,
        "payload_length": len(payload),
        "special_chars_ratio": len(re.findall(r"[^a-zA-Z0-9\s]", payload)) / (len(payload) + 1)
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


# ✅ UPDATE: Thêm param rules_updated
def log_request(payload, ip, method, detection_type, label, probability, rule_pattern=None, rules_updated=False):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "method": method,
        "payload": payload,
        "detection_type": detection_type,
        "rule_pattern": rule_pattern,
        "label": label,
        "probability": probability,
        "rules_updated": rules_updated  # ✅ THÊM field này
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

# ✅ ENABLE Rule Management API
register_rule_api(app)

HTML_TEMPLATE = open(
    os.path.join(os.path.dirname(__file__), "templates", "dashboard.html"),
    encoding="utf-8"
).read()


# ✅ UPDATE: Thêm param rules_updated
def respond_blocked(original_payload, ip, detection_source, reason, rules_updated=False):
    """
    Helper to build a blocked response.
    """
    result = {
        "payload": original_payload,
        "is_malicious": True,
        "probability": 1.0,
        "label": f"MALICIOUS ({detection_source})",
        "rule": reason,
        "rules_updated": rules_updated  # ✅ THÊM field này
    }

    accept = request.headers.get("Accept", "")
    headers = {
        "X-WAF-Blocked": "true",
        "X-WAF-Reason": str(reason),
        "X-WAF-Rules-Updated": str(rules_updated)  # ✅ THÊM header này
    }

    if "application/json" in accept:
        resp = make_response(jsonify({
            "blocked": True,
            "reason": reason,
            "payload": original_payload,
            "rules_updated": rules_updated
        }), 403)
        for k, v in headers.items():
            resp.headers[k] = v
        return resp
    else:
        resp = make_response(render_template_string(HTML_TEMPLATE, result=result), 403)
        for k, v in headers.items():
            resp.headers[k] = v
        return resp


@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)


@app.route("/test")
def test_payload():
    payload = request.args.get("payload", "").strip()
    ip = request.remote_addr or "unknown"
    if not payload:
        return render_template_string(HTML_TEMPLATE, result=None)

    # 1️⃣ Rule check (fast, deterministic)
    rule_hit, pattern = is_malicious_rule(payload)
    if rule_hit:
        log_request(payload, ip, "GET", "rule", f"MALICIOUS (Rule-Based)", 1.0,
                    rule_pattern=pattern, rules_updated=False)
        return respond_blocked(payload, ip, "Rule-Based", pattern, rules_updated=False)

    # 2️⃣ ML prediction (only if no rule hit)
    result_ml = predict_payload_ml(payload)

    # ✅ THÊM LOGIC AUTO-UPDATE RULES
    if result_ml.get("is_malicious"):
        print(f"\n[WAF] ML detected malicious payload: {payload[:100]}")

        # Xác định loại tấn công
        attack_type = determine_attack_type(payload)
        print(f"[WAF] Attack type: {attack_type}")

        # TỰ ĐỘNG CẬP NHẬT RULES
        print(f"[WAF] Attempting to update rules...")
        rules_updated = RuleEngine.update_rules_from_ml_detection(
            payload=payload,
            attack_type=attack_type
        )

        if rules_updated:
            print(f"[WAF] ✅ Rules updated successfully!")
        else:
            print(f"[WAF] ⚠️ Rules update skipped (no new patterns or error)")

        # Log với thông tin rules_updated
        log_request(payload, ip, "GET", "ml", "MALICIOUS (ML)",
                    result_ml.get("probability"), rules_updated=rules_updated)

        return respond_blocked(payload, ip, "ML", "ML-Predicted", rules_updated=rules_updated)

    # If not malicious, proceed and render result normally
    result = {**result_ml, "payload": payload, "rules_updated": False}
    log_request(payload, ip, "GET", "ml", result["label"], result["probability"],
                rules_updated=False)
    return render_template_string(HTML_TEMPLATE, result=result)


@app.route("/user/<path:payload>")
def user_payload(payload):
    ip = request.remote_addr or "unknown"

    # 1️⃣ Rule check
    rule_hit, pattern = is_malicious_rule(payload)
    if rule_hit:
        log_request(payload, ip, "GET", "rule", f"MALICIOUS (Rule-Based)", 1.0,
                    rule_pattern=pattern, rules_updated=False)
        return respond_blocked(payload, ip, "Rule-Based", pattern, rules_updated=False)

    # 2️⃣ ML check + Auto-update
    result_ml = predict_payload_ml(payload)

    # ✅ THÊM LOGIC AUTO-UPDATE RULES
    if result_ml.get("is_malicious"):
        print(f"\n[WAF] ML detected malicious payload: {payload[:100]}")

        attack_type = determine_attack_type(payload)
        print(f"[WAF] Attack type: {attack_type}")

        # AUTO-UPDATE RULES
        print(f"[WAF] Attempting to update rules...")
        rules_updated = RuleEngine.update_rules_from_ml_detection(
            payload=payload,
            attack_type=attack_type
        )

        if rules_updated:
            print(f"[WAF] ✅ Rules updated successfully!")
        else:
            print(f"[WAF] ⚠️ Rules update skipped")

        log_request(payload, ip, "GET", "ml", "MALICIOUS (ML)",
                    result_ml.get("probability"), rules_updated=rules_updated)

        return respond_blocked(payload, ip, "ML", "ML-Predicted", rules_updated=rules_updated)

    result = {**result_ml, "payload": payload, "rules_updated": False}
    log_request(payload, ip, "GET", "ml", result["label"], result["probability"],
                rules_updated=False)
    return render_template_string(HTML_TEMPLATE, result=result)


# ====== Retrain Dashboard ======
@app.route("/retrain")
def retrain_dashboard():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    payload_count = RetrainModule.extract_payloads_to_raw()
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

@app.route("/rules")
def rule_dashboard():
    return render_template("rule_dashboard.html")



# ====== Run Flask server ======
if __name__ == "__main__":
    print("=" * 90)
    print("         AdaptiveWAF Demo Dashboard running on http://127.0.0.1:5000")
    print("=" * 90)

    print("\n🔧 Available endpoints:")

    for rule in app.url_map.iter_rules():
        # Loại bỏ methods mặc định không cần hiển thị
        methods = ",".join(sorted(rule.methods - {"HEAD", "OPTIONS"}))
        endpoint = rule.endpoint
        url = str(rule)
        print(f"[{methods}] {url} → {endpoint}")

    print("\n📋 Try some examples:")
    print("  → http://127.0.0.1:5000/")
    print("  → http://127.0.0.1:5000/test?payload='SELECT*From+users+WHERE+username='admin'--'")
    print("  → http://127.0.0.1:5000/user/normal%20input")
    print("  → http://127.0.0.1:5000/retrain")

    print("\n🛡️ Rule Management API:")
    print("  → http://127.0.0.1:5000/api/rules/")
    print("  → http://127.0.0.1:5000/api/rules/stats")


    print("=" * 90)

    app.run(host="127.0.0.1", port=5000, debug=True)
