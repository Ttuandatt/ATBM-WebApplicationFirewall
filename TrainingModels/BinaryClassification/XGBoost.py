#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phiên bản TỐI ƯU 2025 cho Adaptive WAF (XGBoost):
- XGBoost + char n-gram TF-IDF (2-5)
- Feature phụ: độ dài + tỷ lệ ký tự đặc biệt
- Xử lý mất cân bằng: scale_pos_weight
- Pipeline đầy đủ, dễ deploy
- Tính FN, FP + Luôn train lại + Chỉ lưu model nếu recall tốt nhất
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, f1_score, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline as SklearnPipeline
from xgboost import XGBClassifier
import re
import shutil
from datetime import datetime

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
        return pd.DataFrame(columns=[
            "model", "accuracy", "f1_macro", "f1_malicious", "recall_malicious",
            "fn", "fp", "report_file", "model_file", "preprocessor_file", "version", "timestamp"
        ])

def save_result(results_path, model_name, acc, f1_macro, f1_min, recall_min, fn, fp, report_text, model_file, prep_file, version):
    ensure_dir(results_path)
    base_dir = os.path.dirname(results_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(base_dir, f"{model_name}_v{version}_{timestamp}_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    df = load_previous_results(results_path)
    new_row = pd.DataFrame([{
        "model": model_name,
        "accuracy": acc,
        "f1_macro": f1_macro,
        "f1_malicious": f1_min,
        "recall_malicious": recall_min,
        "fn": fn,
        "fp": fp,
        "report_file": report_path,
        "model_file": model_file,
        "preprocessor_file": prep_file,
        "version": version,
        "timestamp": timestamp
    }])
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(results_path, index=False)
    print(f"Đã lưu kết quả {model_name}_v{version} → {results_path}")
    return df

def get_next_version(results_df, model_name):
    """Tìm version tiếp theo (xgboost_v1, v2, ...)"""
    existing = results_df[results_df["model"].str.startswith(model_name + "_v")]
    if existing.empty:
        return 1
    versions = []
    for m in existing["model"]:
        try:
            v = int(m.split("_v")[-1])
            versions.append(v)
        except:
            continue
    return max(versions) + 1 if versions else 1

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

    # Tính scale_pos_weight cho XGBoost
    neg_count = (df['is_malicious'] == 0).sum()
    pos_count = (df['is_malicious'] == 1).sum()
    scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
    print(f"scale_pos_weight = {scale_pos_weight:.2f} (neg: {neg_count}, pos: {pos_count})")

    # Thêm feature phụ
    df = add_features(df)

    # Train/test split
    X = df[['payload', 'payload_length', 'special_chars_ratio']]
    y = df['is_malicious']
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # =====================================================
    # Pipeline TỐI ƯU cho WAF (XGBoost + TF-IDF)
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

    model = XGBClassifier(
        n_estimators=1200,
        learning_rate=0.05,
        max_depth=8,
        min_child_weight=1,
        subsample=0.9,
        colsample_bytree=0.8,
        reg_lambda=1.5,
        scale_pos_weight=scale_pos_weight,  # Xử lý mất cân bằng
        random_state=42,
        n_jobs=-1,
        verbosity=0,
        eval_metric='logloss',
        tree_method='hist'  # Tối ưu tốc độ
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

    # Lấy version mới (luôn train lại)
    base_model_name = "xgboost"
    version = get_next_version(results_df, base_model_name)
    model_name = f"{base_model_name}_v{version}"
    model_path = os.path.join(save_dir, f"{model_name}.pkl")
    preprocessor_path = os.path.join(save_dir, f"{model_name}_preprocessor.pkl")

    print(f"\nBắt đầu training {model_name} (luôn train lại)...")

    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)
    y_prob = pipe.predict_proba(X_test)[:, 1]

    # Tính các chỉ số
    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average='macro')
    f1_malicious = f1_score(y_test, y_pred, pos_label=1)

    # Tính FN, FP từ confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    recall_malicious = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    report = classification_report(y_test, y_pred, digits=4)
    print(f"Accuracy: {acc:.5f}")
    print(f"F1-macro: {f1_macro:.5f}")
    print(f"F1-malicious: {f1_malicious:.5f}")
    print(f"Recall-malicious: {recall_malicious:.5f}")
    print(f"FN (False Negative): {fn}")
    print(f"FP (False Positive): {fp}")
    print("\nClassification Report:\n", report)

    # Lưu model tạm
    joblib.dump(pipe, model_path)
    joblib.dump(preprocessor, preprocessor_path)

    # Lưu kết quả
    results_df = save_result(
        results_path, model_name, acc, f1_macro, f1_malicious, recall_malicious,
        fn, fp, report, model_path, preprocessor_path, version
    )

    # =====================================================
    # CHỈ LƯU LẠI waf_model.pkl NẾU RECALL TỐT NHẤT (trong XGBoost)
    # =====================================================
    final_model_path = os.path.join(save_dir, "waf_model.pkl")
    final_preprocessor_path = os.path.join(save_dir, "vectorizer.pkl")

    # Lọc các model XGBoost
    # results_df = load_previous_results(results_path)
    if not results_df["model"].empty:
        best_recall = results_df["recall_malicious"].max()
        if recall_malicious >= best_recall:
            print(f"\nMODEL CÓ RECALL TỐT NHẤT ({recall_malicious:.5f}) → Lưu vào waf_model.pkl")
            shutil.copy(model_path, final_model_path)
            shutil.copy(preprocessor_path, final_preprocessor_path)
            print(f"   → {final_model_path}")
            print(f"   → {final_preprocessor_path}")
        else:
            print(f"\nXGBoost mới recall {recall_malicious:.5f} < best {best_recall:.5f} → Không cập nhật waf_model.pkl")
    else:
        # Lần đầu tiên
        print("\nLần đầu train XGBoost → Lưu waf_model.pkl")
        shutil.copy(model_path, final_model_path)
        shutil.copy(preprocessor_path, final_preprocessor_path)

    print("\nHOÀN TẤT! XGBoost WAF Model đã sẵn sàng cho production.")

if __name__ == "__main__":
    main()