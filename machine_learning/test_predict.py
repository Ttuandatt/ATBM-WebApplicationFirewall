import joblib
import re
import json
from sklearn.feature_extraction.text import TfidfVectorizer

# ============================
# 1. Load mô hình đã huấn luyện
# ============================
model = joblib.load("model_xgb.pkl")

# ============================
# 2. Load vectorizer (nếu bạn đã lưu)
# ============================
try:
    vectorizer = joblib.load("vectorizer.pkl")
except:
    # fallback: nếu bạn chưa lưu vectorizer, tạo tạm bằng regex pattern cơ bản
    vectorizer = TfidfVectorizer(token_pattern=r"(?u)\b\w+\b")

# ============================
# 3. Hàm dự đoán request
# ============================
def predict_request(req: str):
    X = vectorizer.transform([req])
    y_pred = model.predict(X)[0]
    label = "BLOCKED" if y_pred == 1 else "ALLOWED"
    return label

# ============================
# 4. Test thử
# ============================
if __name__ == "__main__":
    test_requests = [
        "GET /index.html",
        "GET /search?q=' OR '1'='1",
        "<script>alert('XSS')</script>",
        "POST /login username=admin&password=123",
        "GET /products?id=1; show database;"
    ]

    for req in test_requests:
        result = predict_request(req)
        print(f"[+] Request: {req}\n    => {result}\n")
