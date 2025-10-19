# backend/train_ml.py
from ml_model import train_model

if __name__ == "__main__":
    # Demo dataset (có thể mở rộng)
    train_data = [
        ("SELECT * FROM users WHERE id=1", 1),
        ("<script>alert('xss')</script>", 1),
        ("../../etc/passwd", 1),
        ("login?user=admin&password=1234", 0),
        ("search?q=iphone", 0),
        ("view?id=10", 0),
    ]

    train_model(train_data)
