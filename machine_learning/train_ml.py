# backend/train_ml.py
import os
from ml_model import train_model

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_CSV = os.path.join(BASE_DIR, "backend", "logs", "log2.csv")

if __name__ == "__main__":
    if not os.path.exists(LOGS_CSV):
        raise FileNotFoundError(f"{LOGS_CSV} not found.")

    print(f"[INFO] Đang đọc dữ liệu từ {LOGS_CSV} ...")
    train_model()
