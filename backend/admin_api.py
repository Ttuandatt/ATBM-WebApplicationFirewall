from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os

app = Flask(__name__)
CORS(app)  # Cho phép gọi API từ admin-ui

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, "rules.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "waf.log")
ANALYZER_FILE = os.path.join(BASE_DIR, "analyzer.py")


@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Trả về danh sách rules hiện tại"""
    if not os.path.exists(RULES_FILE):
        return jsonify({"error": "rules.json not found"}), 404
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        rules = json.load(f)
    return jsonify(rules)


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Trả về nội dung log (50 dòng cuối)"""
    if not os.path.exists(LOG_FILE):
        return jsonify({"error": "Log file not found"}), 404

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-50:]  # lấy 50 dòng cuối
    return jsonify({"logs": [l.strip() for l in lines]})


@app.route("/api/analyze", methods=["GET", "POST"])
def run_analyzer():
    """
    Chạy analyzer.py để sinh rules mới hoặc phân tích log.
    Gọi bằng POST (từ frontend) hoặc GET (thử nghiệm thủ công).
    """
    try:
        result = subprocess.run(
            ["python", ANALYZER_FILE],
            cwd=BASE_DIR,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return jsonify({
                "error": "Analyzer failed",
                "details": result.stderr
            }), 500

        return jsonify({
            "message": "Analyzer executed successfully",
            "output": result.stdout
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET"])
def index():
    """Trang gốc thông báo API hoạt động"""
    return jsonify({
        "message": "RuleForge Admin API is running",
        "endpoints": ["/api/rules", "/api/logs", "/api/analyze"]
    })


if __name__ == "__main__":
    app.run(port=5002, debug=True)
