from flask import Flask, request, Response
import requests, json, logging
from utils import load_rules, check_request

app = Flask(__name__)

BACKEND_URL = "http://localhost:5001"
RULES = load_rules("rules.json")

logging.basicConfig(filename="logs/waf.log", level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

@app.before_request
def waf_filter():
    path = request.path
    query = request.query_string.decode()
    body = request.get_data(as_text=True)
    src_ip = request.remote_addr

    if check_request(RULES, path, query, body):
        logging.warning(f"BLOCKED: {src_ip} {path}?{query} {body}")
        return Response("Blocked by RuleForge WAF", status=403)

    logging.info(f"ALLOWED: {src_ip} {path}?{query} {body}")

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def proxy(path):
    resp = requests.request(
        method=request.method,
        url=f"{BACKEND_URL}/{path}",
        headers={key: value for key, value in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )
    return (resp.content, resp.status_code, resp.headers.items())

if __name__ == "__main__":
    app.run(port=5000, debug=True)
