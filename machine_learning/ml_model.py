# machine_learning/ml_model.py
import os
import json
import joblib
import logging
import re
from urllib.parse import unquote
from html import unescape
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Primary ML file (preferred). This is the file format used by the original ML code:
# [{"text":"...","label":0|1}, ...]
LOGS_FILE = os.path.join(BASE_DIR, "backend", "logs", "dataset.csv")


MODEL_DIR = os.path.join(BASE_DIR, "machine_learning")
MODEL_PATH = os.path.join(MODEL_DIR, "model_xgb.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

os.makedirs(os.path.join(BASE_DIR, "backend", "logs"), exist_ok=True)
logging.basicConfig(
    filename=os.path.join(BASE_DIR, "backend", "logs", "ml_train.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -------------------------
# Utilities / preprocessing
# -------------------------
HTTP_METHODS = {"GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"}

def normalize_request_text(raw_request: str) -> str:
    """Take raw request value and normalize it to a stable text for ML:
       - If it's 'GET /path HTTP/1.1' or 'GET /path', keep '/path'
       - URL-decode percent-encoding
       - unescape HTML entities
       - lower-case
    """
    if not raw_request:
        return ""
    text = raw_request.strip()

    # If the log stores the entire request-line like "GET /index.html HTTP/1.1"
    parts = text.split()
    if parts and parts[0].upper() in HTTP_METHODS and len(parts) >= 2:
        text = parts[1]

    # Some logs might include the verb inside the string or just the body
    # URL-decode and unescape basic html entities
    try:
        text = unquote(text)
    except Exception:
        pass

    try:
        text = unescape(text)
    except Exception:
        pass

    # Remove multiple whitespace, normalize
    text = re.sub(r'\s+', ' ', text).strip()
    # lower-case to reduce feature dim
    text = text.lower()
    return text

def event_to_label(event: str) -> int:
    """Map WAF event string to label. BLOCKED/ML_BLOCKED => 1, else 0.
       You can customize this mapping if you have CONFIRMED_ATTACK vs BLOCKED flags.
    """
    if not event:
        return 0
    e = event.strip().upper()
    if "BLOCKED" in e or "ML_BLOCKED" in e or "ATTACK" in e:
        return 1
    return 0

# -------------------------
# Load logs (flexible)
# -------------------------
def load_logs():
    """
    Load training data. Supports two file formats:
    1) Preferred ML format (LOGS_FILE): [{"text": "...", "label": 0|1}, ...]
    Returns:
        texts: list[str], labels: list[int]
    """
    # First try preferred ML file
    if os.path.exists(LOGS_FILE):
        try:
            with open(LOGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # detect format
            if isinstance(data, list) and data and isinstance(data[0], dict) and 'text' in data[0] and 'label' in data[0]:
                texts = [normalize_request_text(x.get('text','')) for x in data]
                labels = [int(x.get('label',0)) for x in data]
                logging.info(f"Loaded {len(texts)} records from {LOGS_FILE} (ML format).")
                return texts, labels
        except Exception as e:
            logging.warning(f"Failed to load {LOGS_FILE} as ML format: {e}")


# -------------------------
# Train model
# -------------------------
def train_model(balance_attacks: bool = False):
    """
    Train XGBoost model from available logs.
    If balance_attacks=True, oversample attack class to reduce class imbalance (simple duplication).
    """
    logging.info("🚀 Start ML training...")
    texts, labels = load_logs()
    if not texts:
        raise ValueError("No training data available.")

    # Optional simple balancing
    X_texts = list(texts)
    y = np.array(labels, dtype=int)
    if balance_attacks:
        # naive oversample minority class (attack) to match majority
        from collections import Counter
        cnt = Counter(y)
        if cnt[1] > 0 and cnt[1] < cnt[0]:
            factor = int(np.ceil(cnt[0] / cnt[1]))
            aug_texts = []
            aug_labels = []
            for t, lab in zip(X_texts, y):
                if lab == 1:
                    for _ in range(factor-1):
                        aug_texts.append(t)
                        aug_labels.append(1)
            X_texts.extend(aug_texts)
            y = np.concatenate([y, np.array(aug_labels, dtype=int)])
            logging.info(f"Balanced dataset by oversampling attacks: new size {len(X_texts)}")

    # Vectorize
    vectorizer = TfidfVectorizer(max_features=500, analyzer='char', ngram_range=(2,5))
    X = vectorizer.fit_transform(X_texts)
    y = np.array(y)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y if len(np.unique(y))>1 else None)

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

    # Ensure model dir
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    logging.info(f"✅ Training complete — Accuracy: {acc:.3f} — Saved model to {MODEL_PATH}")
    print(f"[ML] Model trained — Accuracy: {acc:.3f}")

# -------------------------
# Predict
# -------------------------
def predict_request(text: str):
    """
    Predict (attack=1 / safe=0) and return (pred, prob)
    """
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        raise FileNotFoundError("Model chưa được huấn luyện. Hãy chạy train_model().")

    # load model + vectorizer
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    text_norm = normalize_request_text(text)
    X = vectorizer.transform([text_norm])
    # XGBoost predict_proba may return two columns [prob_class0, prob_class1]
    proba = model.predict_proba(X)[0]
    prob_attack = float(proba[1]) if len(proba) > 1 else float(proba[0])
    pred = int(prob_attack > 0.5)
    return pred, prob_attack

# -------------------------
# If run as script, train
# -------------------------
if __name__ == "__main__":
    # simple CLI: python machine_learning/ml_model.py
    try:
        train_model()
    except Exception as e:
        print("Training failed:", e)
        logging.error(f"Training failed: {e}")
