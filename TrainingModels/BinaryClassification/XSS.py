#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Train binary classifiers chỉ cho XSS (binary classification).
Sử dụng CountVectorizer + một số classifier.
Lưu kết quả vào thư mục saved_models/XSS.
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


# ---------------------------
# Utility functions
# ---------------------------

def find_dataset():
    """Tìm dataset processed_payloads.csv tự động"""
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
    if os.path.isdir(path):
        return
    d = os.path.dirname(path)
    target = d if d else path
    if target and not os.path.exists(target):
        os.makedirs(target, exist_ok=True)


# ---------------------------
# Results management
# ---------------------------

def load_previous_results(results_path):
    if os.path.exists(results_path):
        return pd.read_csv(results_path)
    else:
        return pd.DataFrame(columns=["model", "accuracy", "report_file", "model_file"])


def save_result(results_path, model_name, accuracy, report_text, model_file):
    ensure_dir(results_path)
    base_dir = os.path.dirname(results_path)

    report_path = os.path.join(base_dir, f"{model_name}_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

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
    return model_name in results_df["model"].values


# ---------------------------
# Label extraction helpers
# ---------------------------

def extract_xss_label(df):
    """Trả về nhãn binary cho XSS"""
    cols_lower = {c.lower(): c for c in df.columns}
    for candidate in ['is_xss', 'is_xss_malicious', 'is_xssmalicious']:
        if candidate in cols_lower:
            col = cols_lower[candidate]
            s = df[col]
            if pd.api.types.is_numeric_dtype(s) or pd.api.types.is_bool_dtype(s):
                return pd.to_numeric(s, errors='coerce').fillna(0).astype(int)
            else:
                return s.astype(str).str.contains("xss", case=False, na=False).astype(int)

    # fallback
    for candidate in ['attack_type', 'type', 'label', 'attack', 'attackname', 'is_malicious', 'malicious']:
        if candidate in cols_lower:
            col = cols_lower[candidate]
            s = df[col].astype(str)
            if s.str.contains("xss", case=False, na=False).any():
                return s.str.contains("xss", case=False, na=False).astype(int)
            else:
                return pd.to_numeric(s, errors='coerce').fillna(0).astype(int)

    raise ValueError("Không tìm thấy cột label cho XSS")


# ---------------------------
# Main
# ---------------------------

def main():
    attack_name = "XSS"
    print(f"🔍 Attack target: {attack_name}")

    try:
        df_path = find_dataset()
    except FileNotFoundError as ex:
        print("ERROR:", ex)
        sys.exit(1)

    print("📂 Đang load dataset từ:", df_path)
    df = pd.read_csv(df_path, dtype=str, keep_default_na=False)

    cols = [c.lower() for c in df.columns]
    if 'payload' in cols:
        payload_col = df.columns[cols.index('payload')]
    else:
        payload_col = df.columns[0]
        print(f"⚠️ Không tìm thấy cột 'payload'. Sử dụng cột đầu tiên: {payload_col}")

    try:
        y_series = extract_xss_label(df)
    except ValueError as ex:
        print("ERROR:", ex)
        sys.exit(1)

    df_payloads = df[payload_col].astype(str).fillna('').apply(lambda s: s.strip())
    combined = pd.DataFrame({'payload': df_payloads, 'label': y_series})
    combined = combined[combined['payload'] != ''].drop_duplicates(subset=['payload'])
    combined = combined[combined['label'].isin([0,1])]
    combined = combined.reset_index(drop=True)

    print("📊 Dataset sau xử lý:", len(combined), "mẫu.")
    print(combined['label'].value_counts())

    vectorizer = CountVectorizer(min_df=1, tokenizer=custom_tokenizer, ngram_range=(1,3))
    X = vectorizer.fit_transform(combined['payload'])
    y = combined['label'].values

    if len(y) < 10:
        print("⚠️ Dataset quá nhỏ để train (ít hơn 10 mẫu). Dừng.")
        sys.exit(1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    save_dir = os.path.join(script_dir, "saved_models", "XSS")
    os.makedirs(save_dir, exist_ok=True)

    results_path = os.path.join(save_dir, "results_xss.csv")
    results_df = load_previous_results(results_path)

    models = [
        ("NaiveBayes", MultinomialNB()),
        ("SVM", SVC()),
        ("LogisticRegression", LogisticRegression(max_iter=2000)),
        ("DecisionTree", DecisionTreeClassifier()),
        ("Bagging", BaggingClassifier(estimator=DecisionTreeClassifier(), n_estimators=50, random_state=42)),
        ("AdaBoost", AdaBoostClassifier(estimator=DecisionTreeClassifier(max_depth=1), n_estimators=30, random_state=42)),
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

    best_model_name = None
    best_acc = 0
    best_model = None
    any_trained = False

    for model_name, clf in models:
        if model_already_trained(results_df, model_name):
            print(f"⏩ Bỏ qua {model_name} (đã có trong {results_path}).")
            continue

        print(f"\n🚀 Training {model_name} for {attack_name}...")
        try:
            clf.fit(X_train, y_train)
        except Exception as e:
            print(f"❌ Lỗi khi train {model_name}: {e}")
            continue

        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, digits=4)

        print(f"{model_name} Accuracy: {acc:.4f}")
        print(report)

        model_path = os.path.join(save_dir, f"{model_name}_xss.pkl")
        joblib.dump(clf, model_path)

        save_result(results_path, model_name, acc, report, model_path)

        any_trained = True
        if acc > best_acc:
            best_acc = acc
            best_model_name = model_name
            best_model = clf

    # nếu không có model mới, chọn best từ file results
    if not any_trained:
        print("⚠️ Không có model nào được train mới. Chọn model tốt nhất từ results trước đó...")
        if os.path.exists(results_path):
            df_results = pd.read_csv(results_path)
            df_results["accuracy"] = pd.to_numeric(df_results["accuracy"], errors="coerce")
            df_results = df_results[df_results["model_file"].notna() & df_results["accuracy"].notna()]
            if not df_results.empty:
                best_row = df_results.loc[df_results["accuracy"].idxmax()]
                best_model_name = best_row["model"]
                best_acc = best_row["accuracy"]
                candidate_path = best_row.get("model_file", None)
                if pd.notna(candidate_path) and os.path.exists(candidate_path):
                    best_model = joblib.load(candidate_path)
                    print(f"✅ Model tốt nhất trước đó: {best_model_name} (accuracy={best_acc:.4f})")
                else:
                    print(f"⚠️ Không tìm thấy file model tại {candidate_path}")

    # lưu model chính và vectorizer
    if best_model is not None:
        main_model_path = os.path.join(save_dir, "xss.pkl")
        joblib.dump(best_model, main_model_path)
        print(f"💾 Đã lưu model tốt nhất -> {main_model_path}")

    vectorizer_path = os.path.join(save_dir, "vectorizer_xss.pkl")
    joblib.dump(vectorizer, vectorizer_path)
    print(f"💾 Đã lưu vectorizer -> {vectorizer_path}")

    print("\n🎯 Hoàn tất!")


if __name__ == "__main__":
    main()
