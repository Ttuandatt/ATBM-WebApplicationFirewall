#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_xss_models.py

Huấn luyện và đánh giá mô hình phát hiện XSS payloads.
Lưu CountVectorizer + MultinomialNB để dùng cho WAF runtime.

Usage:
    python train_xss_models.py
"""

import os
import sys
import joblib
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    BaggingClassifier, AdaBoostClassifier, RandomForestClassifier, StackingClassifier
)

# ======================== #
#       HELPER FUNCS       #
# ======================== #
def find_xss_dataset():
    """Tìm file dataset XSS trong project."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        # 1. Nếu chạy từ BinaryClassification/, lùi ra 1 cấp -> data/processed
        os.path.join(script_dir, '..', 'data', 'processed', 'processed_payloads.csv'),

        # 2. Nếu chạy từ thư mục gốc project
        os.path.join(script_dir, 'data', 'processed', 'processed_payloads.csv'),

        # 3. Nếu chạy từ sâu hơn (phòng trường hợp khác)
        os.path.join(script_dir, '..', '..', 'data', 'processed', 'processed_payloads.csv'),
    ]
    for p in candidates:
        if os.path.exists(p):
            return os.path.abspath(p)
    raise FileNotFoundError("Không tìm thấy file XSS dataset. Đã thử:\n" + "\n".join(candidates))


def custom_tokenizer(text):
    """Tokenizer cơ bản: tách theo khoảng trắng."""
    return text.split()


def ensure_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def save_artifacts(nb_clf, vectorizer, base_save_dir):
    """Lưu model NB + vectorizer."""
    ensure_dir(base_save_dir)
    nb_path = os.path.join(base_save_dir, "nb_classifier_xss.pkl")
    vect_path = os.path.join(base_save_dir, "count_vectorizer_xss.pkl")
    joblib.dump(nb_clf, nb_path)
    joblib.dump(vectorizer, vect_path)
    print(f"✅ Saved NB model to: {nb_path}")
    print(f"✅ Saved vectorizer to: {vect_path}")
    return nb_path, vect_path


# ======================== #
#          MAIN            #
# ======================== #
def main():
    print("🔍 Looking for XSS dataset...")
    try:
        df_path = find_xss_dataset()
    except FileNotFoundError as ex:
        print("❌ ERROR:", ex)
        sys.exit(1)

    print("📂 Loading dataset from:", df_path)
    df = pd.read_csv(df_path, dtype=str, keep_default_na=False)

    # Chuẩn hóa cột
    cols = [c.lower() for c in df.columns]
    payload_col = df.columns[cols.index('payload')] if 'payload' in cols else df.columns[0]
    label_col = df.columns[cols.index('is_malicious')] if 'is_malicious' in cols else df.columns[1]

    df = df[[payload_col, label_col]].copy()
    df.columns = ['payload', 'is_malicious']

    def to_int_lbl(x):
        try:
            return int(float(x))
        except Exception:
            return 1 if str(x).strip() else 0

    df['payload'] = df['payload'].astype(str).fillna('').apply(lambda s: s.strip())
    df['is_malicious'] = df['is_malicious'].apply(to_int_lbl).astype(int)
    df = df[df['payload'] != ''].drop_duplicates(subset=['payload'])

    print("📊 Dataset size after cleaning:", len(df))
    print("Label distribution:")
    print(df['is_malicious'].value_counts())

    # Chỉ giữ nhãn hợp lệ
    df = df[df['is_malicious'].isin([0, 1])]

    # Vectorization
    vectorizer = CountVectorizer(min_df=1, tokenizer=custom_tokenizer, ngram_range=(1, 3))
    X = vectorizer.fit_transform(df['payload'])
    y = df['is_malicious'].values

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ========================
    # TRAINING MULTIPLE MODELS
    # ========================
    print("\nTraining MultinomialNB...")
    nb = MultinomialNB().fit(X_train, y_train)
    y_pred = nb.predict(X_test)
    print("NaiveBayes Accuracy:", accuracy_score(y_test, y_pred))
    print("NaiveBayes Classification Report:\n", classification_report(y_test, y_pred))

    print("\nTraining LogisticRegression...")
    lr = LogisticRegression(max_iter=2000).fit(X_train, y_train)
    y_pred_lr = lr.predict(X_test)
    print("Logistic Accuracy:", accuracy_score(y_test, y_pred_lr))
    print("Logistic Classification Report:\n", classification_report(y_test, y_pred_lr))

    print("\nTraining RandomForest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    print("RandomForest Accuracy:", accuracy_score(y_test, y_pred_rf))
    print("RandomForest Classification Report:\n", classification_report(y_test, y_pred_rf))

    # ========================
    # SAVE NB MODEL
    # ========================
    save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models", "xss")
    save_artifacts(nb, vectorizer, save_dir)
    print("\n✅ Training completed successfully.")


if __name__ == "__main__":
    main()
