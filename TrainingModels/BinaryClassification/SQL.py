#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_sql_models.py

Chạy training/evaluation cho SQLi dataset (CountVectorizer + nhiều classifier).
Lưu NB model và vectorizer ra disk.

Usage:
    python train_sql_models.py
"""

import os
import sys
import argparse
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

def find_dataset():
    """
    Try to locate processed dataset file used in the notebook.
    Returns full path or raises FileNotFoundError.
    Tries several common candidate locations.
    """
    # script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = []

    # candidate used in original notebook (two levels up from cwd)
    parent_dir = os.path.abspath(os.path.join(script_dir, "..", ".."))
    candidates.append(os.path.join(parent_dir, 'data', 'processed', 'sqli-by-chou@ibcher+.csv'))
    # common project layout: TrainingModels/data/processed/processed_payloads.csv or sqli-by-...
    candidates.append(os.path.join(script_dir, 'data', 'processed', 'sqli-by-chou@ibcher+.csv'))
    candidates.append(os.path.join(script_dir, 'data', 'processed', 'processed_payloads.csv'))
    candidates.append(os.path.join(script_dir, '..', 'TrainingModels', 'data', 'processed', 'processed_payloads.csv'))
    candidates.append(os.path.join(script_dir, '..', '..', 'TrainingModels', 'data', 'processed', 'processed_payloads.csv'))
    # also try relative to repository root
    candidates.append(os.path.join(script_dir, '..', '..', 'machine_learning', 'data', 'processed', 'processed_payloads.csv'))
    # finally try the path user previously used in notebook style (parent_dir/data/processed/)
    candidates.append(os.path.join(parent_dir, 'data', 'processed', 'processed_payloads.csv'))

    for p in candidates:
        if p and os.path.exists(p):
            return os.path.abspath(p)

    # if none found, show tried candidates for debugging
    raise FileNotFoundError("Processed dataset not found. Tried:\n" + "\n".join(candidates))

def custom_tokenizer(text):
    # Simple tokenizer: split on whitespace. You can extend with more logic (punctuation splitting, regex).
    return text.split()

def ensure_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def save_artifacts(nb_clf, vectorizer, base_save_dir):
    """
    Save NB model and vectorizer to base_save_dir.
    """
    ensure_dir(base_save_dir)
    nb_path = os.path.join(base_save_dir, "nb_classifier.pkl")
    vect_path = os.path.join(base_save_dir, "count_vectorizer.pkl")
    joblib.dump(nb_clf, nb_path)
    joblib.dump(vectorizer, vect_path)
    print(f"Saved NB model to: {nb_path}")
    print(f"Saved vectorizer to: {vect_path}")
    return nb_path, vect_path

def main():
    print("Looking for dataset...")
    try:
        df_path = find_dataset()
    except FileNotFoundError as ex:
        print("ERROR:", ex)
        sys.exit(1)

    print("Loading dataset from:", df_path)
    # read only necessary columns (tolerant if file contains different header names)
    # We'll try to read the named columns; if they don't exist, read entire CSV and adapt.
    df = pd.read_csv(df_path, dtype=str, keep_default_na=False)

    # Normalize column names to expected ones if possible
    cols = [c.lower() for c in df.columns]
    if 'payload' in cols:
        payload_col = df.columns[cols.index('payload')]
    else:
        # fallback: try second column
        payload_col = df.columns[0]
        print(f"[WARN] 'payload' column not found; using first column '{payload_col}' as payload.")

    if 'is_malicious' in cols:
        label_col = df.columns[cols.index('is_malicious')]
    else:
        # fallback: try to locate a numeric 0/1 column or default to column index 1 if exists
        label_col = None
        for i, c in enumerate(df.columns):
            # check values
            vals = set(df[c].unique()[:20])
            if vals.issubset({'0','1','0.0','1.0','0.00','1.00'}):
                label_col = c
                break
        if label_col is None and len(df.columns) > 1:
            label_col = df.columns[1]
            print(f"[WARN] 'is_malicious' column not found; guessing column '{label_col}' as label. Check correctness.")
        elif label_col is None:
            print("[ERROR] Could not determine label column.")
            sys.exit(1)

    # Filter and prepare
    df = df[[payload_col, label_col]].copy()
    df.columns = ['payload', 'is_malicious']
    # convert label to int
    def to_int_lbl(x):
        try:
            return int(float(x))
        except Exception:
            # any non-int becomes 1 if not empty else 0
            return 1 if str(x).strip() else 0
    df['payload'] = df['payload'].astype(str).fillna('').apply(lambda s: s.strip())
    df['is_malicious'] = df['is_malicious'].apply(to_int_lbl).astype(int)

    # drop truly empty payloads
    df = df[df['payload'] != '']
    # drop duplicates
    df = df.drop_duplicates(subset=['payload'])
    print("Dataset size after cleaning:", len(df))
    print("Distribution of labels:")
    print(df['is_malicious'].value_counts())

    # ✅ Giữ lại chỉ các nhãn hợp lệ (0 và 1) trước khi tách train/test
    valid_labels = [0, 1]
    before = len(df)
    df = df[df['is_malicious'].isin(valid_labels)]
    after = len(df)
    if after < before:
        print(f"[INFO] Filtered out {before - after} rows with invalid labels. Remaining: {after}")


    # vectorize (CountVectorizer with custom_tokenizer and ngram 1..3)
    vectorizer = CountVectorizer(min_df=1, tokenizer=custom_tokenizer, ngram_range=(1,3))
    X = vectorizer.fit_transform(df['payload'])
    y = df['is_malicious'].values

    # train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 1) Naive Bayes
    print("\nTraining MultinomialNB...")
    nb_classifier = MultinomialNB()
    nb_classifier.fit(X_train, y_train)
    y_pred = nb_classifier.predict(X_test)
    print("NaiveBayes Accuracy:", accuracy_score(y_test, y_pred))
    print("NaiveBayes Classification Report:\n", classification_report(y_test, y_pred))

    # 2) SVM
    print("\nTraining SVC (may be slow)...")
    svm_classifier = SVC()
    svm_classifier.fit(X_train, y_train)
    y_pred_svm = svm_classifier.predict(X_test)
    print("SVM Accuracy:", accuracy_score(y_test, y_pred_svm))
    print("SVM Classification Report:\n", classification_report(y_test, y_pred_svm))

    # 3) Logistic Regression
    print("\nTraining LogisticRegression...")
    logistic_reg = LogisticRegression(max_iter=2000)
    logistic_reg.fit(X_train, y_train)
    y_pred_log = logistic_reg.predict(X_test)
    print("Logistic Accuracy:", accuracy_score(y_test, y_pred_log))
    print("Logistic Classification Report:\n", classification_report(y_test, y_pred_log))

    # 4) Decision Tree
    print("\nTraining DecisionTreeClassifier...")
    tree = DecisionTreeClassifier()
    tree.fit(X_train, y_train)
    y_pred_tree = tree.predict(X_test)
    print("Decision Tree Accuracy:", accuracy_score(y_test, y_pred_tree))
    print("Decision Tree Classification Report:\n", classification_report(y_test, y_pred_tree))

    # Ensemble methods
    print("\nTraining Bagging (DecisionTree base)...")
    bagging = BaggingClassifier(estimator=DecisionTreeClassifier(), n_estimators=50, random_state=42)
    bagging.fit(X_train, y_train)
    y_pred_bag = bagging.predict(X_test)
    print("Bagging Accuracy:", accuracy_score(y_test, y_pred_bag))
    print("Bagging Classification Report:\n", classification_report(y_test, y_pred_bag))

    print("\nTraining AdaBoost (DecisionTree base)...")
    boosting = AdaBoostClassifier(estimator=DecisionTreeClassifier(), n_estimators=50, random_state=42)
    boosting.fit(X_train, y_train)
    y_pred_boost = boosting.predict(X_test)
    print("AdaBoost Accuracy:", accuracy_score(y_test, y_pred_boost))
    print("AdaBoost Classification Report:\n", classification_report(y_test, y_pred_boost))

    print("\nTraining RandomForest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    print("RandomForest Accuracy:", accuracy_score(y_test, y_pred_rf))
    print("RandomForest Classification Report:\n", classification_report(y_test, y_pred_rf))

    print("\nTraining Stacking classifier (RF + SVC -> Logistic)...")
    estimators = [
        ('rf', RandomForestClassifier(n_estimators=50, random_state=42)),
        ('svc', SVC(probability=True, random_state=42))
    ]
    stack = StackingClassifier(estimators=estimators, final_estimator=LogisticRegression(), n_jobs=-1)
    stack.fit(X_train, y_train)
    y_pred_stack = stack.predict(X_test)
    print("Stacking Accuracy:", accuracy_score(y_test, y_pred_stack))
    print("Stacking Classification Report:\n", classification_report(y_test, y_pred_stack))

    # save NB and vectorizer for use by WAF
    # choose a sensible save directory: same folder as csv's parent or models/ under script dir
    script_dir = os.path.dirname(os.path.abspath(__file__))
    save_dir = os.path.join(script_dir, "saved_models")
    if not os.path.exists(save_dir):
        os.makedirs(save_dir, exist_ok=True)

    save_artifacts(nb_classifier, vectorizer, save_dir)
    print("\nAll done.")

if __name__ == "__main__":
    main()
