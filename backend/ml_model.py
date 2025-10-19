# backend/ml_model.py
import os
import joblib
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "vectorizer.pkl")

def preprocess(text):
    # tiền xử lý cơ bản để dọn dữ liệu web request
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s\=\&\?\.\-\/\<\>]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def train_model(train_data):
    """
    train_data: list of tuples (text, label)
    label = 1 (attack), 0 (normal)
    """
    texts, labels = zip(*train_data)
    texts = [preprocess(t) for t in texts]

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X = vectorizer.fit_transform(texts)
    model = LogisticRegression(max_iter=500)
    model.fit(X, labels)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print("✅ ML model & vectorizer saved.")

def load_model():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        raise FileNotFoundError("Model hoặc vectorizer chưa được huấn luyện.")
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    return model, vectorizer

def predict(text):
    model, vectorizer = load_model()
    text = preprocess(text)
    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]
    pred = int(prob > 0.5)
    return pred, prob
