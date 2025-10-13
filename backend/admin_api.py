# admin_api.py
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import subprocess
import json
import os
import threading
import time
import logging

# Nếu analyzer.py có hàm analyze_logs() export, ta sẽ import nó để gọi trực tiếp
# (thích hợp, nhanh, không cần spawn process). Nếu bạn muốn spawn subprocess thay vì import,
# đặt USE_SUBPROCESS = True.
USE_SUBPROCESS = False

try:
    if not USE_SUBPROCESS:
        import analyzer  # expects analyzer.py with analyze_logs()
except Exception as e:
    # fallback to subprocess mode
    USE_SUBPROCESS = True
    logging.warning(f"Failed to import analyzer module, will use subprocess: {e}")

app = Flask(__name__, static_folder="../admin-ui", static_url_path="/admin-ui")
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "waf.log")
ANALYZER_FILE = os.path.join(BASE_DIR, "analyzer.py")

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
    if not os.path.exists(LOG_FILE):
        return jsonify({"error": "waf.log not found"}), 404
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-200:]  # giới hạn trả về (mặc định 200 dòng cuối)
    return jsonify({"logs": [l.rstrip("\n") for l in lines]})


@app.route("/api/analyze", methods=["GET", "POST"])
def run_analyzer_endpoint():
    """
    Gọi analyzer thủ công (POST từ UI), hoặc GET để test.
    Returns analyzer stdout (or message).
    """
    try:
        if USE_SUBPROCESS:
            # gọi subprocess (độc lập)
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
            # gọi trực tiếp hàm analyze_logs() (nên trả về string hoặc None)
            try:
                analyzer.analyze_logs()
                return jsonify({"message": "Analyzer executed (inline)"}), 200
            except Exception as ex:
                return jsonify({"error": "Analyzer inline failed", "details": str(ex)}), 500

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Analyzer subprocess timeout"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def index():
    """Trang gốc: trả về API description"""
    return jsonify({
        "message": "RuleForge Admin API is running",
        "endpoints": ["/api/rules", "/api/logs", "/api/analyze"],
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
    Uses USE_SUBPROCESS flag or inline import call.
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
        # sleep until next run
        time.sleep(ANALYZE_INTERVAL_SECONDS)


def start_background_thread():
    t = threading.Thread(target=background_analyzer_loop, daemon=True, name="analyzer-loop")
    t.start()


if __name__ == "__main__":
    # Start background analyzer when running as main
    start_background_thread()
    app.run(port=5002, debug=True)
