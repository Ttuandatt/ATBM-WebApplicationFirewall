#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_sql_models.py

Chạy training/evaluation cho SQLi dataset (CountVectorizer + nhiều classifier).
Lưu NB model và vectorizer ra disk, và kết quả training ra file CSV.

Usage:
    python train_sql_models.py
"""

import os
import sys
import joblib
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# classifiers
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import BaggingClassifier, AdaBoostClassifier, RandomForestClassifier, StackingClassifier


# =====================================================
# 🔹 Các hàm tiện ích
# =====================================================

def find_dataset():
    """Tự tìm file dataset đã xử lý."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, 'data', 'processed', 'processed_payloads.csv'),
        os.path.join(script_dir, '..', 'data', 'processed', 'processed_payloads.csv'),
        os.path.join(script_dir, '..', '..', 'data', 'processed', 'processed_payloads.csv'),
    ]
    for p in candidates:
        if os.path.exists(p):
            return os.path.abspath(p)
    raise FileNotFoundError("Không tìm thấy dataset. Đã thử:\n" + "\n".join(candidates))


def custom_tokenizer(text):
    return text.split()


def ensure_dir(path):
    """Đảm bảo thư mục tồn tại."""
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


# =====================================================
# 🔹 Quản lý lưu kết quả và report
# =====================================================

def load_previous_results(results_path):
    """Đọc kết quả cũ (nếu có)."""
    if os.path.exists(results_path):
        return pd.read_csv(results_path)
    else:
        return pd.DataFrame(columns=["model", "accuracy", "report_file", "model_file"])


def save_result(results_path, model_name, accuracy, report_text, model_file):
    """Ghi kết quả mới vào CSV và lưu report ra file riêng."""
    ensure_dir(results_path)
    base_dir = os.path.dirname(results_path)

    # Lưu file report chi tiết
    report_path = os.path.join(base_dir, f"{model_name}_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    # Ghi summary vào CSV
    df = load_previous_results(results_path)
    new_row = pd.DataFrame([{
        "model": model_name,
        "accuracy": accuracy,
        "report_file": report_path,
        "model_file": model_file
    }])
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(results_path, index=False)
    print(f"✅ Đã lưu kết quả của {model_name} vào {results_path}")


def model_already_trained(results_df, model_name):
    """Kiểm tra mô hình đã được train chưa."""
    return model_name in results_df["model"].values


# =====================================================
# 🔹 Hàm chính
# =====================================================

def main():
    print("🔍 Đang tìm dataset...")
    try:
        df_path = find_dataset()
    except FileNotFoundError as ex:
        print("ERROR:", ex)
        sys.exit(1)

    print("📂 Đang load dataset từ:", df_path)
    df = pd.read_csv(df_path, dtype=str, keep_default_na=False)

    # Chuẩn hóa cột
    cols = [c.lower() for c in df.columns]
    payload_col = df.columns[cols.index('payload')] if 'payload' in cols else df.columns[0]
    label_col = df.columns[cols.index('is_malicious')] if 'is_malicious' in cols else df.columns[1]

    df = df[[payload_col, label_col]].copy()
    df.columns = ['payload', 'is_malicious']

    # Chuyển nhãn thành số
    def to_int_lbl(x):
        try:
            return int(float(x))
        except Exception:
            return 1 if str(x).strip() else 0

    df['payload'] = df['payload'].astype(str).fillna('').apply(lambda s: s.strip())
    df['is_malicious'] = df['is_malicious'].apply(to_int_lbl).astype(int)
    df = df[df['payload'] != ''].drop_duplicates(subset=['payload'])
    df = df[df['is_malicious'].isin([0, 1])]

    print("📊 Dataset:", len(df), "mẫu.")
    print(df['is_malicious'].value_counts())

    # Vector hóa
    vectorizer = CountVectorizer(min_df=1, tokenizer=custom_tokenizer, ngram_range=(1, 3))
    X = vectorizer.fit_transform(df['payload'])
    y = df['is_malicious'].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Thư mục lưu model + kết quả
    script_dir = os.path.dirname(os.path.abspath(__file__))
    save_dir = os.path.join(script_dir, "saved_models")
    results_path = os.path.join(save_dir, "results.csv")
    os.makedirs(save_dir, exist_ok=True)

    results_df = load_previous_results(results_path)

    # =====================================================
    # 🔸 Danh sách mô hình cần train
    # =====================================================
    models = [
        ("NaiveBayes", MultinomialNB()),
        ("SVM", SVC()),
        ("LogisticRegression", LogisticRegression(max_iter=2000)),
        ("DecisionTree", DecisionTreeClassifier()),
        ("Bagging", BaggingClassifier(estimator=DecisionTreeClassifier(), n_estimators=50, random_state=42)),
        ("AdaBoost", AdaBoostClassifier(estimator=DecisionTreeClassifier(), n_estimators=50, random_state=42)),
        ("RandomForest", RandomForestClassifier(n_estimators=100, random_state=42)),
        ("Stacking", StackingClassifier(
            estimators=[
                ('rf', RandomForestClassifier(n_estimators=50, random_state=42)),
                ('svc', SVC(probability=True, random_state=42))
            ],
            final_estimator=LogisticRegression(),
            n_jobs=-1
        ))
    ]

    # =====================================================
    # 🔸 Train từng mô hình (chỉ train nếu chưa có kết quả)
    # =====================================================
    for model_name, clf in models:
        if model_already_trained(results_df, model_name):
            print(f"⏩ Bỏ qua {model_name} (đã có trong kết quả trước đó).")
            continue

        print(f"\n🚀 Training {model_name}...")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)

        print(f"{model_name} Accuracy: {acc:.4f}")
        print(report)

        # Lưu model
        model_path = os.path.join(save_dir, f"{model_name}.pkl")
        joblib.dump(clf, model_path)

        # Ghi kết quả
        save_result(results_path, model_name, acc, report, model_path)

    # Lưu vectorizer (nếu chưa có)
    vect_path = os.path.join(save_dir, "count_vectorizer.pkl")
    if not os.path.exists(vect_path):
        joblib.dump(vectorizer, vect_path)
        print(f"💾 Saved vectorizer to: {vect_path}")

    print("\n🎯 Hoàn tất training tất cả mô hình!")


if __name__ == "__main__":
    main()
