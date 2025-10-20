# machine_learning/ml_model.py
import os
import json
import joblib
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "machine_learning")
LOGS_FILE = os.path.join(BASE_DIR, "logs.json")

MODEL_PATH = os.path.join(MODEL_DIR, "model_xgb.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

logging.basicConfig(
    filename=os.path.join(BASE_DIR, "logs", "ml_train.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# =========================================================
# Utility
# =========================================================
def load_logs():
    """Load dữ liệu huấn luyện từ logs.json"""
    if not os.path.exists(LOGS_FILE):
        raise FileNotFoundError(f"{LOGS_FILE} not found.")
    with open(LOGS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    texts = [x["text"] for x in data]
    labels = [x["label"] for x in data]
    return texts, labels

# =========================================================
# Train Model
# =========================================================
def train_model():
    """Huấn luyện XGBoost model từ logs.json"""
    logging.info("🚀 Bắt đầu huấn luyện mô hình XGBoost...")
    texts, labels = load_logs()

    vectorizer = TfidfVectorizer(max_features=500)
    X = vectorizer.fit_transform(texts)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = XGBClassifier(
        n_estimators=120,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        eval_metric="logloss",
        use_label_encoder=False
    )

    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    logging.info(f"✅ Huấn luyện hoàn tất — Độ chính xác: {acc:.2f}")
    print(f"[ML] Model trained — Accuracy: {acc:.2f}")

# =========================================================
# Predict
# =========================================================
def predict_request(text: str):
    """Dự đoán xem request có tấn công không (1 = Attack, 0 = Safe)"""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        raise FileNotFoundError("Model chưa được huấn luyện. Hãy chạy train_model().")

    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]
    pred = int(prob > 0.5)
    return pred, float(prob)
