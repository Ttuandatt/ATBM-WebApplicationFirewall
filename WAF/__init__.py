# WAF/__init__.py
from flask import request
import joblib
import numpy as np
import json
import os
import subprocess
import ctypes
from abc import ABC, abstractmethod

# Đường dẫn thư mục hiện tại
base_dir = os.path.dirname(os.path.abspath(__file__))

def is_admin():
    """Kiểm tra quyền admin (Windows/Linux)"""
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:  # Linux/macOS
            return os.geteuid() == 0
    except Exception:
        return False


class WAF_AI(ABC):
    """
    Base class cho các detector WAF AI.
    Chỉ cần model_path → chứa toàn bộ pipeline (Tfidf + Model)
    """
    def __init__(self, model_path: str, vectorizer_path: str = None):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path  # Không dùng nữa, giữ cho tương thích
        self.admin_privileges = is_admin()
        self.model = None

        # --- Load model (toàn bộ pipeline) ---
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        try:
            self.model = joblib.load(model_path)
            print(f"[WAF_AI] Pipeline loaded from: {model_path}")
        except Exception as e:
            print(f"[WAF_AI] Error loading pipeline: {e}")
            self.model = None

        # --- Bỏ hoàn toàn việc load vectorizer riêng ---
        if vectorizer_path:
            print(f"[WAF_AI] Warning: vectorizer_path ignored. Using pipeline only.")

    def block_ips_feature(self, client_ip: str):
        """Chặn IP bằng firewall (iptables / netsh) nếu có quyền admin"""
        if not self.admin_privileges:
            print("[WAF] Admin privileges not available. IP blocking disabled.")
            return

        config_path = os.path.join(base_dir, 'models', 'config.json')
        if not os.path.exists(config_path):
            print(f"[WAF] Config file not found: {config_path}")
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception as e:
            print(f"[WAF] Error reading config: {e}")
            return

        whitelist = config.get('whitelisted_ips', [])
        if client_ip in whitelist:
            print(f"[WAF] IP {client_ip} is whitelisted. Skipping block.")
            return

        print(f"[WAF] Blocking malicious IP: {client_ip}")

        if os.name == 'nt':  # Windows
            try:
                rule_name = f"BlockIP_{client_ip.replace('.', '_')}"
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}', 'dir=in', 'action=block',
                    f'remoteip={client_ip}'
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                print(f"[WAF] IP {client_ip} blocked (Windows Firewall).")
            except subprocess.CalledProcessError as e:
                print(f"[WAF] Failed to block IP on Windows: {e}")
        else:  # Linux
            try:
                cmd = ['iptables', '-A', 'INPUT', '-s', client_ip, '-j', 'DROP']
                subprocess.run(cmd, check=True, capture_output=True)
                print(f"[WAF] IP {client_ip} blocked (iptables).")
            except subprocess.CalledProcessError as e:
                print(f"[WAF] Failed to block IP on Linux: {e}")

    @abstractmethod
    def detect(self, payload: str, client_ip: str) -> bool:
        """Trả về True nếu phát hiện tấn công"""
        pass


class AdaptiveWAF_AI(WAF_AI):
    """
    Detector cho AdaptiveWAF - dùng pipeline đầy đủ (Tfidf + LightGBM)
    """

    def _preprocess_payload(self, payload: str):
        """Tạo DataFrame đúng cấu trúc như lúc train"""
        import re
        import pandas as pd
        return pd.DataFrame([{
            'payload': payload,
            'payload_length': len(payload),
            'special_chars_ratio': len(re.findall(r'[^a-zA-Z0-9\s]', payload)) / (len(payload) + 1)
        }])

    def detect(self, payload: str, client_ip: str) -> bool:
        """
        Dự đoán payload có độc hại không.
        Trả về True nếu là tấn công → sẽ chặn IP.
        """
        if not payload or not payload.strip():
            return False

        if self.model is None:
            print("[AdaptiveWAF_AI] Model not loaded. Skipping detection.")
            return False

        try:
            # Tạo input đúng định dạng
            df_input = self._preprocess_payload(payload)

            # Dự đoán
            pred = self.model.predict(df_input)[0]
            prob = self.model.predict_proba(df_input)[0]
            malicious_prob = prob[1] if len(prob) > 1 else prob[0]

            print(f"[AdaptiveWAF_AI] Payload: '{payload}'")
            print(f"   → Prediction: {pred}, Probability: {malicious_prob:.4f}")

            if pred == 1:
                self.block_ips_feature(client_ip)
                return True

            return False

        except Exception as e:
            print(f"[AdaptiveWAF_AI] Prediction error: {e}")
            return False