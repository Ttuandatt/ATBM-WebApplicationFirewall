# FlaskSimpleTest.py
import joblib
import pandas as pd
import os
import re

# Đường dẫn đúng tới model
MODEL_DIR = os.path.join(
    os.path.dirname(__file__),
    "..", "TrainingModels", "BinaryClassification", "saved_models", "AdaptiveWAF"
)

# Chỉ load 1 file: waf_model.pkl (chứa toàn bộ pipeline)
model_path = os.path.join(MODEL_DIR, "waf_model.pkl")

print(f"[WAF] Loading AdaptiveWAF model: {model_path}")

if not os.path.exists(model_path):
    print(f"[ERROR] Model file not found: {model_path}")
    exit(1)

try:
    # Load toàn bộ pipeline (preprocessor + model)
    waf_pipeline = joblib.load(model_path)
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    exit(1)

# === HÀM DỰ ĐOÁN MỚI (DỰA TRÊN PIPELINE) ===
def predict_payload(payload: str):
    """
    Dự đoán payload sử dụng pipeline đã load.
    Không cần vectorizer riêng.
    """
    # Tạo DataFrame đúng cấu trúc như khi train
    df = pd.DataFrame([{
        'payload': payload,
        'payload_length': len(payload),
        'special_chars_ratio': len(re.findall(r'[^a-zA-Z0-9\s]', payload)) / (len(payload) + 1)
    }])

    try:
        pred = waf_pipeline.predict(df)[0]
        prob = waf_pipeline.predict_proba(df)[0]
        malicious_prob = prob[1] if len(prob) > 1 else prob[0]
        return {
            "is_malicious": bool(pred),
            "probability": float(malicious_prob),
            "label": "MALICIOUS" if pred else "LEGAL"
        }
    except Exception as e:
        print(f"Prediction error: {e}")
        return {"is_malicious": False, "probability": 0.0, "label": "ERROR"}

# === TEST NHANH ===
if __name__ == "__main__":
    test_payloads = [
        "SELECT * FROM users",
        "<script>alert(1)</script>",
        "admin' OR '1'='1",
        "normal page request",
        "id=5 UNION SELECT password FROM users--"
    ]

    print("\n" + "="*50)
    print("BẮT ĐẦU TEST WAF")
    print("="*50)
    for p in test_payloads:
        result = predict_payload(p)
        print(f"Payload: {p}")
        print(f"  → {result['label']} (prob: {result['probability']:.4f})")
        print()