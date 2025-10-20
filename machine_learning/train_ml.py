# backend/train_ml.py
from ml_model import train_model

train_samples = [
    ("normal", "GET /index.html"),
    ("normal", "GET /login?username=admin"),
    ("normal", "POST /submit-feedback message=hello"),
    ("attack", "GET /search?q=' OR '1'='1"),
    ("attack", "<script>alert('xss')</script>"),
    ("attack", "../../etc/passwd"),
    ("attack", "UNION SELECT password FROM users"),
    ("normal", "GET /about-us"),
    ("attack", "GET /product?id=1; DROP TABLE users"),
    ("normal", "GET /static/js/main.js")
]

if __name__ == "__main__":
    train_model(train_samples)
