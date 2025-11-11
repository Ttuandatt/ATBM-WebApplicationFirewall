# WAF/MLDetector.py
import joblib
import numpy as np
import os
from urllib.parse import unquote
import pickle
import re

def custom_tokenizer(text):
    return text.split()

class CustomUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if name == 'custom_tokenizer':
            return custom_tokenizer
        return super().find_class(module, name)

class MLDetector:
    def __init__(self, model_dir):
        self.model_dir = model_dir
        self.detectors = self._load_all_detectors()

    def _load_detector(self, attack_name):
        dir_path = os.path.join(self.model_dir, attack_name)
        if not os.path.isdir(dir_path):
            return None

        model_files = [f for f in os.listdir(dir_path) if f.endswith('.pkl') and 'vectorizer' not in f.lower()]
        vec_files = [f for f in os.listdir(dir_path) if 'vectorizer' in f.lower()]

        if not model_files:
            return None

        model_path = os.path.join(dir_path, model_files[0])
        vec_path = os.path.join(dir_path, vec_files[0]) if vec_files else None

        try:
            model = joblib.load(model_path)
            if vec_path:
                with open(vec_path, 'rb') as f:
                    vectorizer = CustomUnpickler(f).load()
            else:
                vectorizer = None
            return {'model': model, 'vectorizer': vectorizer}
        except Exception as e:
            print(f"[ML] Load {attack_name} failed: {e}")
            return None

    def _load_all_detectors(self):
        detectors = {}
        for attack in ['SQLInjection', 'XSS']:
            detectors[attack] = self._load_detector(attack)
        return detectors

    def extract_features(self, payload):
        length = len(payload)
        special_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', payload)) / (length + 1)
        return np.array([[length, special_ratio]])

    def predict(self, payload: str):
        results = {}
        for attack, detector in self.detectors.items():
            if not detector or not detector['model']:
                continue
            try:
                if detector['vectorizer']:
                    X_text = detector['vectorizer'].transform([payload])
                    X_num = self.extract_features(payload)
                    X = np.hstack([X_text.toarray(), X_num])
                else:
                    X = self.extract_features(payload)
                prob = detector['model'].predict_proba(X)[0][1]
                pred = detector['model'].predict(X)[0]
                results[attack] = {'pred': int(pred), 'prob': float(prob)}
            except:
                results[attack] = {'pred': 0, 'prob': 0.0}
        return results