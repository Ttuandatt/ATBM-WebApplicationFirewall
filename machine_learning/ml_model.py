# machine_learning/ml_model.py
import os
import joblib
import logging
import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "machine_learning")
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
LOGS_DIR = os.path.join(BACKEND_DIR, "logs")

LOGS_CSV = os.path.join(LOGS_DIR, "log2.csv")

MODEL_PATH = os.path.join(MODEL_DIR, "model_xgb.pkl")

os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOGS_DIR, "ml_train.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


# =========================================================
# Utility
# =========================================================
def load_logs_csv():
    """Đọc backend/logs/log2.csv và trả về X (features), y (labels)."""
    if not os.path.exists(LOGS_CSV):
        raise FileNotFoundError(f"{LOGS_CSV} not found.")

    df = pd.read_csv(LOGS_CSV)
    if "Action" not in df.columns:
        raise ValueError("CSV file must contain 'Action' column.")

    # Gán nhãn 1 = deny, 0 = allow
    df["Action"] = (
        df["Action"].astype(str)
        .str.lower()
        .map({"allow": 0, "deny": 1, "drop": 1})
    )
    df["Action"] = df["Action"].fillna(0)
    df["Action"] = df["Action"].astype(int)

    y = df["Action"]
    X = df.drop(columns=["Action"])  # dùng các cột số còn lại

    # Ép các cột còn lại thành kiểu số
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)
    return X, y


# =========================================================
# Train Model
# =========================================================
def train_model():
    """Huấn luyện XGBoost từ log2.csv"""
    logging.info("🚀 Bắt đầu huấn luyện mô hình XGBoost (từ log2.csv)...")

    X, y = load_logs_csv()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
    )

    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)

    joblib.dump(model, MODEL_PATH)
    logging.info(f"✅ Huấn luyện hoàn tất — Độ chính xác: {acc:.2f}")
    print(f"[ML] Model trained — Accuracy: {acc:.2f}")


# =========================================================
# Predict
# =========================================================
def predict_request(features: dict):
    """
    Dự đoán xem một request có phải tấn công không.
    Input: dict gồm các trường giống log2.csv
    Output: (label, prob)
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model chưa được huấn luyện. Hãy chạy train_model().")

    model = joblib.load(MODEL_PATH)

    # Chuyển dict thành dataframe 1 dòng
    df = pd.DataFrame([features])

    # Đảm bảo các cột khớp với dữ liệu huấn luyện
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

    prob = model.predict_proba(df)[0][1]
    pred = int(prob > 0.5)
    return pred, float(prob)
