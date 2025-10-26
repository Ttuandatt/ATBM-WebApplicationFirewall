# ml_model.py
import os
import json
import pickle
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, "ml_model.pkl")
VECT_FILE = os.path.join(BASE_DIR, "vectorizer.pkl")

# ---------------------------
# Load / Save model & vectorizer
# ---------------------------
def save_model(model, vectorizer):
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)
    with open(VECT_FILE, "wb") as f:
        pickle.dump(vectorizer, f)
    logging.info("✅ ML model & vectorizer saved.")

def load_model():
    if not os.path.exists(MODEL_FILE) or not os.path.exists(VECT_FILE):
        return None, None
    with open(MODEL_FILE, "rb") as f:
        model = pickle.load(f)
    with open(VECT_FILE, "rb") as f:
        vectorizer = pickle.load(f)
    return model, vectorizer

# ---------------------------
# Training from logs.json
# ---------------------------
def train_from_logs(logs_json_path):
    """
    Train ML model from structured logs.json
    Each record: {"text":..., "label": 0|1}
    """
    if not os.path.exists(logs_json_path):
        raise FileNotFoundError(f"{logs_json_path} not found")

    with open(logs_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    texts = [r["text"] for r in data]
    labels = [r["label"] for r in data]

    if not texts:
        raise ValueError("No training data found in logs.json")

    vectorizer = TfidfVectorizer(ngram_range=(1,2), max_features=5000)
    X = vectorizer.fit_transform(texts)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, labels)

    save_model(clf, vectorizer)
    logging.info(f"✅ ML model trained on {len(texts)} samples")

    # Return metrics summary
    return {"samples": len(texts)}

# ---------------------------
# Prediction
# ---------------------------
def predict_request(text):
    """
    Return (pred, prob) for a request text.
    pred = 0: safe, 1: malicious
    prob = confidence of class 1
    """
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        raise FileNotFoundError("ML model not found. Please train first.")

    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]
    pred = int(prob > 0.5)
    return pred, prob
