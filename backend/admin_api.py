# backend/admin_api.py
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import subprocess
import json
import os
import threading
import time
import logging

# Nếu analyzer.py có hàm analyze_logs() export, ta sẽ import nó để gọi trực tiếp
USE_SUBPROCESS = False

try:
    if not USE_SUBPROCESS:
        import analyzer  # expects analyzer.py with analyze_logs()
        import ml_model
except Exception as e:
    # fallback to subprocess mode
    USE_SUBPROCESS = True
    logging.warning(f"Failed to import analyzer or ml_model modules, will use subprocess: {e}")

app = Flask(__name__, static_folder="../admin-ui", static_url_path="/admin-ui")
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "waf.log")
JSON_LOG = os.path.join(BASE_DIR, "logs", "logs.json")
ANALYZER_FILE = os.path.join(BASE_DIR, "analyzer.py")
ML_TRAIN_SCRIPT = os.path.join(BASE_DIR, "train_ml.py")

# Background analyzer config (seconds)
ANALYZE_INTERVAL_SECONDS = int(os.environ.get("ANALYZE_INTERVAL_SECONDS", "30"))
AUTO_ANALYZE_ENABLED = os.environ.get("AUTO_ANALYZE_ENABLED", "1") not in ("0", "false", "False")

# Setup logging for this service (stdout)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


@app.route("/api/rules", methods=["GET"])
def get_rules():
    if not os.path.exists(RULES_FILE):
        return jsonify({"error": "rules.json not found"}), 404
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        rules = json.load(f)
    return jsonify(rules)


@app.route("/api/logs", methods=["GET"])
def get_logs():
    # return last 200 lines from waf.log (text)
    if not os.path.exists(LOG_FILE):
        return jsonify({"error": "waf.log not found"}), 404
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-200:]  # giới hạn
    return jsonify({"logs": [l.rstrip("\n") for l in lines]})


@app.route("/api/jsonlogs", methods=["GET"])
def get_json_logs():
    if not os.path.exists(JSON_LOG):
        return jsonify({"error": "logs.json not found"}), 404
    with open(JSON_LOG, "r", encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    return jsonify({"logs": lines})


@app.route("/api/analyze", methods=["GET", "POST"])
def run_analyzer_endpoint():
    """
    Gọi analyzer thủ công (POST từ UI), hoặc GET để test.
    Returns analyzer stdout (or message).
    """
    try:
        if USE_SUBPROCESS:
            result = subprocess.run(
                ["python", ANALYZER_FILE],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                return jsonify({"error": "Analyzer failed", "details": result.stderr}), 500
            return jsonify({"message": "Analyzer executed (subprocess)", "output": result.stdout}), 200
        else:
            try:
                analyzer.analyze_logs()
                return jsonify({"message": "Analyzer executed (inline)"}), 200
            except Exception as ex:
                return jsonify({"error": "Analyzer inline failed", "details": str(ex)}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Analyzer subprocess timeout"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/train", methods=["POST", "GET"])
def trigger_train():
    """
    POST to trigger training from logs (no body needed)
    GET returns current training report if available.
    """
    # GET -> return last training report if exists
    if request.method == "GET":
        report_path = os.path.join(BASE_DIR, "ml_training_report.json")
        if not os.path.exists(report_path):
            return jsonify({"error": "No training report found"}), 404
        with open(report_path, "r", encoding="utf-8") as f:
            rep = json.load(f)
        return jsonify({"report": rep}), 200

    # POST -> trigger training from logs.json (inline if possible)
    try:
        if USE_SUBPROCESS:
            # spawn training script
            result = subprocess.run(
                ["python", ML_TRAIN_SCRIPT, "logs"],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode != 0:
                return jsonify({"error": "Training failed", "details": result.stderr}), 500
            # read report file if exists
            report_path = os.path.join(BASE_DIR, "ml_training_report.json")
            rep = None
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8") as f:
                    rep = json.load(f)
            return jsonify({"message": "Training (subprocess) finished", "report": rep, "stdout": result.stdout}), 200
        else:
            # inline: use ml_model.train_from_logs
            try:
                metrics = ml_model.train_from_logs(JSON_LOG)
                return jsonify({"message": "Training (inline) finished", "report": metrics}), 200
            except FileNotFoundError as fe:
                return jsonify({"error": str(fe)}), 400
            except Exception as ex:
                return jsonify({"error": "Training failed", "details": str(ex)}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Training subprocess timeout"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def index():
    """Trang gốc: trả về API description"""
    return jsonify({
        "message": "RuleForge Admin API is running",
        "endpoints": ["/api/rules", "/api/logs", "/api/jsonlogs", "/api/analyze", "/api/train"],
        "auto_analyze": AUTO_ANALYZE_ENABLED,
        "analyze_interval_seconds": ANALYZE_INTERVAL_SECONDS
    })


# Serve admin UI static (optional) - assumes admin-ui is one level up
@app.route("/admin-ui/<path:filename>")
def admin_ui(filename):
    root = os.path.join(BASE_DIR, "..", "admin-ui")
    return send_from_directory(root, filename)


def background_analyzer_loop():
    """
    Background thread: run analyzer periodically.
    """
    logging.info("Background analyzer thread started (every %s seconds). Auto enabled=%s",
                 ANALYZE_INTERVAL_SECONDS, AUTO_ANALYZE_ENABLED)
    while True:
        try:
            if AUTO_ANALYZE_ENABLED:
                logging.info("Running analyzer (background)...")
                if USE_SUBPROCESS:
                    try:
                        out = subprocess.run(
                            ["python", ANALYZER_FILE],
                            cwd=BASE_DIR,
                            capture_output=True,
                            text=True,
                            timeout=90
                        )
                        if out.returncode != 0:
                            logging.error("Analyzer subprocess error: %s", out.stderr.strip())
                        else:
                            logging.info("Analyzer subprocess finished: %s", out.stdout.strip())
                    except Exception as e:
                        logging.exception("Analyzer subprocess run failed: %s", e)
                else:
                    try:
                        analyzer.analyze_logs()
                        logging.info("Analyzer inline executed.")
                    except Exception as e:
                        logging.exception("Analyzer inline execution failed: %s", e)
            else:
                logging.debug("Auto-analyze disabled; skipping this run.")
        except Exception as e:
            logging.exception("Background analyzer loop exception: %s", e)
        time.sleep(ANALYZE_INTERVAL_SECONDS)


def start_background_thread():
    t = threading.Thread(target=background_analyzer_loop, daemon=True, name="analyzer-loop")
    t.start()


if __name__ == "__main__":
    start_background_thread()
    app.run(port=5002, debug=True)
