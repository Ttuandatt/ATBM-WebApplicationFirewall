# WAF/RetrainModule.py
import os
import json
import time
import subprocess

# ====== Đường dẫn ======
CURRENT_DIR = os.path.dirname(__file__)
LOG_FILE = os.path.join(CURRENT_DIR, "logs", "waf_logs.json")
RAW_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "TrainingModels", "data", "raw"))
RAW_FILE = os.path.join(RAW_DIR, "access_log.txt")

LIGHTGBM_SCRIPT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "TrainingModels", "BinaryClassification", "LightGBM.py"))
RF_SCRIPT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "TrainingModels", "BinaryClassification", "RandomForest.py"))

os.makedirs(RAW_DIR, exist_ok=True)

# ====== 1️⃣ Tách payload từ log ======
def extract_payloads_to_raw():
    payloads = set()

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except:
                logs = []

        for entry in logs:
            payload = entry.get("payload", "").strip()
            if payload:
                payloads.add(payload)

    # Ghi vào access_log.txt
    with open(RAW_FILE, "w", encoding="utf-8") as f:
        for p in payloads:
            f.write(p + "\n")

    print(f"[INFO] {len(payloads)} payloads exported to {RAW_FILE}")
    return len(payloads)

# ====== 2️⃣ Gọi script train ======
def retrain_models():
    # LightGBM
    if os.path.exists(LIGHTGBM_SCRIPT):
        print("[INFO] Running LightGBM training...")
        subprocess.run(["python", LIGHTGBM_SCRIPT], check=True)
    else:
        print(f"[WARN] LightGBM script not found: {LIGHTGBM_SCRIPT}")

    # RandomForest
    if os.path.exists(RF_SCRIPT):
        print("[INFO] Running RandomForest training...")
        subprocess.run(["python", RF_SCRIPT], check=True)
    else:
        print(f"[WARN] RandomForest script not found: {RF_SCRIPT}")

# ====== 3️⃣ Hàm chính retrain định kỳ ======
def periodic_retrain(threshold=100):
    print(f"[INFO] Starting retrain check at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    count = extract_payloads_to_raw()
    if count >= threshold:
        print(f"[INFO] {count} payloads detected, retraining models...")
        retrain_models()
    else:
        print(f"[INFO] Only {count} payloads detected. Threshold is {threshold}. Skipping retrain.")

# ====== 4️⃣ Nếu chạy trực tiếp ======
if __name__ == "__main__":
    periodic_retrain()
