# WAF/WAF_Flask.py
from flask import request, jsonify, Flask
from WAF import AdaptiveWAF_AI
import os
from urllib.parse import unquote
import glob
import json

# --- Cập nhật đường dẫn tuyệt đối tới thư mục saved_models ---
current_dir = os.path.dirname(os.path.abspath(__file__))
base_model_dir = os.path.join(
    current_dir, '..', 'TrainingModels', 'BinaryClassification', 'saved_models'
)
base_model_dir = os.path.abspath(base_model_dir)
# ------------------------------------------------------------

# Danh sách các loại tấn công sẽ được load (tên folder trong saved_models)
ATTACK_NAMES = ['AdaptiveWAF']

def find_model_file(attack_dir):
    """
    Tìm file model .pkl trong attack_dir.
    Ưu tiên: waf_model.pkl → *.pkl (không phải vectorizer)
    """
    preferred = os.path.join(attack_dir, 'waf_model.pkl')
    if os.path.exists(preferred):
        return preferred

    # Tìm file .pkl nào không chứa 'vectorizer'
    for p in glob.glob(os.path.join(attack_dir, '*.pkl')):
        name = os.path.basename(p).lower()
        if 'vectorizer' not in name:
            return p

    return None

def load_detectors():
    """
    Load tất cả detector cho các ATTACK_NAMES.
    Trả về dict: attack_name → AdaptiveWAF_AI instance (hoặc None nếu lỗi)
    """
    detectors = {}
    for attack in ATTACK_NAMES:
        attack_dir = os.path.join(base_model_dir, attack)
        if not os.path.isdir(attack_dir):
            print(f"[WAF] Warning: Directory not found: {attack_dir}. Skipping {attack}.")
            detectors[attack] = None
            continue

        model_file = find_model_file(attack_dir)
        if model_file is None:
            print(f"[WAF] No valid model file found in {attack_dir}. Skipping.")
            detectors[attack] = None
            continue

        print(f"[WAF] Loading detector: {attack} → {model_file}")
        try:
            # vectorizer_path = None → không cần load riêng
            detector = AdaptiveWAF_AI(model_file, vectorizer_path=None)
            detectors[attack] = detector
        except Exception as e:
            print(f"[WAF] Error loading detector for {attack}: {e}")
            detectors[attack] = None

    return detectors

# Load detectors khi import module
_DETECTORS = load_detectors()


def extract_payloads_from_request(req):
    """
    Trích xuất tất cả payload khả nghi từ request:
    - path segment cuối
    - query params
    - form data
    - JSON body
    - raw body
    """
    payloads = set()

    try:
        # 1. Path cuối
        path = req.path or ''
        decoded_path = unquote(path)
        last_seg = decoded_path.strip('/').split('/')[-1]
        if last_seg:
            payloads.add(last_seg)

        # 2. Query params
        for v in req.args.values():
            if v := v.strip():
                payloads.add(unquote(v))

        # 3. Form data
        for v in req.form.values():
            if v := v.strip():
                payloads.add(unquote(v))

        # 4. JSON body
        try:
            json_body = req.get_json(silent=True)
            if isinstance(json_body, dict):
                for v in json_body.values():
                    if isinstance(v, str) and v.strip():
                        payloads.add(v.strip())
                    else:
                        payloads.add(json.dumps(v, ensure_ascii=False))
            elif isinstance(json_body, (list, str)) and json_body:
                payloads.add(json.dumps(json_body, ensure_ascii=False))
        except:
            pass

        # 5. Raw body
        try:
            raw = req.get_data(as_text=True)
            if raw := raw.strip():
                payloads.add(unquote(raw))
        except:
            pass

    except Exception as e:
        print(f"[WAF] Error extracting payloads: {e}")

    return [p for p in payloads if p]


def rusicadeWAF_AI(app: Flask):
    """
    Middleware WAF: Kiểm tra request trước khi xử lý.
    Chặn nếu phát hiện tấn công.
    """
    @app.before_request
    def monitor_request():
        client_ip = request.remote_addr or "unknown"
        print(f"\n[WAF] Incoming request from IP: {client_ip}")
        print(f"[WAF] URL: {request.url}")

        payloads = extract_payloads_from_request(request)
        if not payloads:
            return None  # Không có gì để kiểm tra

        print(f"[WAF] Extracted {len(payloads)} payload(s) to check.")

        # Kiểm tra từng detector
        for attack_name, detector in _DETECTORS.items():
            if detector is None:
                continue

            for payload in payloads:
                print(f"[WAF] Checking payload with {attack_name}: '{payload}'")
                try:
                    if detector.detect(payload, client_ip):
                        print(f"[WAF] MALICIOUS PAYLOAD DETECTED! Blocking IP: {client_ip}")
                        return (
                            f"""
                            <html>
                                <head>
                                    <title>Access Denied - Rusicade WAF_AI</title>
                                    <style>
                                        body {{ font-family: Arial; text-align: center; padding: 50px; background: #f0f0f0; }}
                                        .box {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); display: inline-block; }}
                                        h1 {{ color: #d32f2f; }}
                                        h2 {{ color: #333; }}
                                    </style>
                                </head>
                                <body>
                                    <div class="box">
                                        <h1>Rusicade WAF_AI</h1>
                                        <h2>Potential Attack Detected!</h2>
                                        <p><strong>Attack Type:</strong> {attack_name}</p>
                                        <p><strong>Payload:</strong> <code>{payload}</code></p>
                                        <p>Your IP <strong>{client_ip}</strong> has been blocked.</p>
                                        <hr>
                                        <small>Contact admin if this is a mistake.</small>
                                    </div>
                                </body>
                            </html>
                            """,
                            400
                        )
                except Exception as e:
                    print(f"[WAF] Error in detection for {attack_name}: {e}")
                    continue

        # Nếu không phát hiện tấn công
        print(f"[WAF] Request from {client_ip} is CLEAN.")
        return None

    return app