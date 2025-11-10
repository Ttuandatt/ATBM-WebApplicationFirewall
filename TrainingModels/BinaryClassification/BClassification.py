#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BClassification_AdaptiveWAF.py

Phiên bản TỐI ƯU 2025 cho Adaptive WAF:
- LightGBM + char n-gram TF-IDF (2-5)
- Feature phụ: độ dài + tỷ lệ ký tự đặc biệt
- Xử lý mất cân bằng: class_weight='balanced' (LightGBM native)
- Pipeline đầy đủ, dễ deploy (ONNX/Treelite sau này)
- Tự động skip model đã train, lưu kết quả chi tiết

Usage:
    python BClassification_AdaptiveWAF.py
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline as SklearnPipeline
from lightgbm import LGBMClassifier
import re

# =====================================================
# Các hàm tiện ích
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

def ensure_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def load_previous_results(results_path):
    if os.path.exists(results_path):
        return pd.read_csv(results_path)
    else:
        return pd.DataFrame(columns=["model", "accuracy", "f1_macro", "f1_minority", "report_file", "model_file", "preprocessor_file"])

def save_result(results_path, model_name, acc, f1_macro, f1_min, report_text, model_file, prep_file):
    ensure_dir(results_path)
    base_dir = os.path.dirname(results_path)
    report_path = os.path.join(base_dir, f"{model_name}_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    df = load_previous_results(results_path)
    new_row = pd.DataFrame([{
        "model": model_name,
        "accuracy": acc,
        "f1_macro": f1_macro,
        "f1_minority": f1_min,
        "report_file": report_path,
        "model_file": model_file,
        "preprocessor_file": prep_file
    }])
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(results_path, index=False)
    print(f"Đã lưu kết quả {model_name} → {results_path}")

def model_already_trained(results_df, model_name):
    return model_name in results_df["model"].values

# =====================================================
# Feature engineering phụ
# =====================================================

def add_features(df):
    """Thêm 2 feature mạnh: độ dài + tỷ lệ ký tự đặc biệt"""
    df = df.copy()
    df['payload_length'] = df['payload'].str.len()
    special_chars = r'[^a-zA-Z0-9\s]'
    df['special_chars_ratio'] = df['payload'].apply(lambda x: len(re.findall(special_chars, x)) / (len(x) + 1))
    return df

# =====================================================
# Hàm chính
# =====================================================

def main():
    print("Đang tìm dataset...")
    try:
        df_path = find_dataset()
    except FileNotFoundError as ex:
        print("ERROR:", ex)
        sys.exit(1)

    print("Đang load dataset từ:", df_path)
    df = pd.read_csv(df_path, dtype=str, keep_default_na=False)

    # Chuẩn hóa cột
    cols = [c.lower() for c in df.columns]
    payload_col = df.columns[cols.index('payload')] if 'payload' in cols else df.columns[0]
    label_col = df.columns[cols.index('is_malicious')] if 'is_malicious' in cols else df.columns[1]

    df = df[[payload_col, label_col]].copy()
    df.columns = ['payload', 'is_malicious']

    # Chuẩn hóa nhãn
    def to_int_lbl(x):
        try:
            return int(float(x))
        except:
            return 1 if str(x).strip().lower() in ['1', 'true', 'malicious', '1.0'] else 0
    df['payload'] = df['payload'].astype(str).fillna('').str.strip()
    df['is_malicious'] = df['is_malicious'].apply(to_int_lbl).astype(int)
    df = df[df['payload'] != ''].drop_duplicates(subset=['payload'])
    df = df[df['is_malicious'].isin([0, 1])].reset_index(drop=True)

    print(f"Dataset: {len(df)} mẫu")
    print("Phân bố nhãn:")
    print(df['is_malicious'].value_counts())

    # Thêm feature phụ
    df = add_features(df)

    # Train/test split
    X = df[['payload', 'payload_length', 'special_chars_ratio']]
    y = df['is_malicious']
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # =====================================================
    # Pipeline TỐI ƯU cho WAF (LightGBM + char n-gram TF-IDF)
    # =====================================================
    tfidf = TfidfVectorizer(
        analyzer='char',
        ngram_range=(2, 5),
        lowercase=True,
        max_features=100_000,
        dtype=np.float32,
        sublinear_tf=True
    )

    preprocessor = ColumnTransformer([
        ('tfidf', tfidf, 'payload'),
        ('numeric', 'passthrough', ['payload_length', 'special_chars_ratio'])
    ], remainder='drop')

    model = LGBMClassifier(
        n_estimators=1000,
        learning_rate=0.05,
        max_depth=-1,
        num_leaves=256,
        colsample_bytree=0.8,
        subsample=0.9,
        reg_lambda=1.0,
        class_weight='balanced',   # xử lý mất cân bằng cực tốt
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )

    pipe = SklearnPipeline([
        ('prep', preprocessor),
        ('clf', model)
    ])

    # Thư mục lưu
    script_dir = os.path.dirname(os.path.abspath(__file__))
    save_dir = os.path.join(script_dir, "saved_models", "AdaptiveWAF")
    os.makedirs(save_dir, exist_ok=True)
    results_path = os.path.join(save_dir, "results.csv")
    results_df = load_previous_results(results_path)

    model_name = "LightGBM_CharNgram_TFIDF_Balanced"

    if model_already_trained(results_df, model_name):
        print(f"Model {model_name} đã được train trước đó. Bỏ qua.")
    else:
        print(f"\nTraining {model_name} (có thể mất 1-3 phút với 150k mẫu)...")
        pipe.fit(X_train, y_train)

        y_pred = pipe.predict(X_test)
        y_prob = pipe.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        f1_macro = f1_score(y_test, y_pred, average='macro')
        f1_min = f1_score(y_test, y_pred, pos_label=1)  # F1 của lớp malicious

        report = classification_report(y_test, y_pred, digits=4)
        print(f"Accuracy: {acc:.5f}")
        print(f"F1-macro: {f1_macro:.5f}")
        print(f"F1-malicious: {f1_min:.5f}")
        print(report)

        # Lưu model + preprocessor riêng (rất quan trọng cho Flask/FastAPI)
        model_path = os.path.join(save_dir, "lightgbm_waf.pkl")
        preprocessor_path = os.path.join(save_dir, "preprocessor.pkl")

        joblib.dump(pipe, model_path)                    # toàn bộ pipeline
        joblib.dump(preprocessor, preprocessor_path)     # chỉ preprocessor (nếu cần riêng)

        # Ghi kết quả
        save_result(
            results_path, model_name, acc, f1_macro, f1_min,
            report, model_path, preprocessor_path
        )

    # =====================================================
    # Luôn lưu lại model tốt nhất để Flask dùng (dù đã train trước đó)
    # =====================================================
    final_model_path = os.path.join(save_dir, "waf_model.pkl")
    final_preprocessor_path = os.path.join(save_dir, "waf_preprocessor.pkl")

    if os.path.exists(model_path):
        # Copy lại với tên cố định
        import shutil
        shutil.copy(model_path, final_model_path)
        if os.path.exists(preprocessor_path):
            shutil.copy(preprocessor_path, final_preprocessor_path)

        print(f"\nModel tốt nhất đã được lưu cho inference:")
        print(f"   → {final_model_path}")
        print(f"   → {final_preprocessor_path}")
    else:
        print("Không tìm thấy model đã train!")

    print("\nHOÀN TẤT! WAF ML Model đã sẵn sàng cho production.")

if __name__ == "__main__":
    main()