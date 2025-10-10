from flask import Flask, jsonify, request
from flask_cors import CORS   # thêm dòng này
import subprocess
import json
import os

app = Flask(__name__)
CORS(app)  # Cho phép tất cả origin gọi API

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
    """Trả về nội dung log"""
    if not os.path.exists(LOG_FILE):
        return jsonify({"error": "waf.log not found"}), 404
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return jsonify({"logs": lines})


@app.route("/api/analyze", methods=["GET"])
def run_analyzer():
    """Chạy analyzer.py để sinh rules mới"""
    try:
        result = subprocess.run(
            ["python", ANALYZER_FILE],
            cwd=BASE_DIR,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return jsonify({"error": "Analyzer failed", "details": result.stderr}), 500
        return jsonify({"message": "Analyzer executed", "output": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5002, debug=True)
