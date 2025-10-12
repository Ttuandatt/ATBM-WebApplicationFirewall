from flask import Flask, request, render_template_string
import logging, os

app = Flask(__name__)

# Cấu hình log backend
os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename="logs/backend.log", level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

@app.route("/")
def index():
    return "<h1>Welcome to RuleForge Demo App</h1><p>Try /search?q= or /login</p>, or /file?path=</p>"

@app.route("/search")
def search():
    query = request.args.get("q", "")
    logging.info(f"Search query: {query}")
    return f"<h2>Search Results for: {query}</h2>"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")
        logging.info(f"Login attempt: user={user}")
        return f"<p>Login attempt: {user} / {pw}</p>"
    return '''
        <form method="POST">
            <input name="username" placeholder="Username">
            <input name="password" type="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''

@app.route("/file")
def file_access():
    path = request.args.get("path", "")
    logging.info(f"File access attempt: path={path}")
    if ".." in path or path.startswith("/"):
        logging.warning(f"Suspicious file access: {path}")
        return "<h2>Invalid file path</h2>", 403
    if path:
        return f"<h2>Attempting to access file: {path}</h2>"
    return "<h2>Please provide a file path using ?path=</h2>"


if __name__ == "__main__":
    app.run(port=5001, debug=True)
