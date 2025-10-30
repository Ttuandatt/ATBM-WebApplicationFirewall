# WAF/WAF_Flask.py
from flask import request, jsonify
from WAF import SQLInjectionWAF_AI
import os
from urllib.parse import unquote
import numpy as np
import glob
import json

# --- Cập nhật đường dẫn tuyệt đối tới thư mục saved_models ---
current_dir = os.path.dirname(os.path.abspath(__file__))
base_model_dir = os.path.join(current_dir, '..', 'TrainingModels', 'BinaryClassification', 'saved_models')
base_model_dir = os.path.abspath(base_model_dir)
# ------------------------------------------------------------

# Danh sách attacks mà middleware sẽ load (tên phải tương ứng với folder trong saved_models)
ATTACK_NAMES = ['SQLInjection', 'XSS']

def find_vectorizer_file(attack_dir):
    """
    Tìm file vectorizer trong attack_dir.
    Trả về đường dẫn hoặc None.
    """
    # tìm các file có tên chứa 'vectorizer' (không phân biệt hoa thường)
    candidates = []
    for p in glob.glob(os.path.join(attack_dir, '*.pkl')):
        if 'vectorizer' in os.path.basename(p).lower():
            candidates.append(p)
    if candidates:
        # trả file đầu tiên tìm được
        return candidates[0]
    # fallback: tìm file tên 'vectorizer.pkl'
    fallback = os.path.join(attack_dir, 'vectorizer.pkl')
    if os.path.exists(fallback):
        return fallback
    return None

def find_model_file(attack_dir):
    """
    Tìm file model phù hợp trong attack_dir.
    Cố gắng chọn file rõ ràng (ví dụ sqli.pkl, *_xss.pkl), nếu không thì trả file .pkl đầu tiên không phải vectorizer.
    """
    # ưu tiên các file có tên attack (case-insensitive)
    attack_name_lower = os.path.basename(attack_dir).lower()
    for p in glob.glob(os.path.join(attack_dir, '*.pkl')):
        name = os.path.basename(p).lower()
        # skip vectorizer files
        if 'vectorizer' in name:
            continue
        if attack_name_lower in name:
            return p
    # fallback: trả file .pkl đầu tiên không phải vectorizer
    for p in glob.glob(os.path.join(attack_dir, '*.pkl')):
        name = os.path.basename(p).lower()
        if 'vectorizer' in name:
            continue
        return p
    return None

def load_detectors():
    """
    Load detector instances for all ATTACK_NAMES.
    Trả về dict attack_name -> detector instance (hoặc None nếu load fail).
    """
    detectors = {}
    for attack in ATTACK_NAMES:
        attack_dir = os.path.join(base_model_dir, attack)
        if not os.path.isdir(attack_dir):
            print(f"[WAF] Warning: attack dir not found: {attack_dir}. Skipping {attack}.")
            detectors[attack] = None
            continue

        model_file = find_model_file(attack_dir)
        vectorizer_file = find_vectorizer_file(attack_dir)

        # if not found a model file but there's a common-named model in parent (e.g., sqli.pkl)
        if model_file is None:
            # try searching parent saved_models dir for files that mention attack
            for p in glob.glob(os.path.join(base_model_dir, '*', '*.pkl')):
                if attack.lower() in os.path.basename(p).lower() and 'vectorizer' not in os.path.basename(p).lower():
                    model_file = p
                    break

        # fallback to generic names
        if model_file is None:
            print(f"[WAF] No model .pkl found for {attack} in {attack_dir}. Skipping load.")
            detectors[attack] = None
            continue

        if vectorizer_file is None:
            # try parent dir 'SQLInjection' vectorizer as fallback for XSS (in case only one vectorizer was saved)
            fallback_vec = os.path.join(base_model_dir, 'SQLInjection', 'vectorizer.pkl')
            if os.path.exists(fallback_vec):
                vectorizer_file = fallback_vec

        print(f"[WAF] Loading {attack}: model={model_file}, vectorizer={vectorizer_file}")
        try:
            detector = SQLInjectionWAF_AI(model_file, vectorizer_file)
            detectors[attack] = detector
        except Exception as e:
            print(f"[WAF] Error loading detector for {attack}: {e}")
            detectors[attack] = None
    return detectors

# load detectors on import
_DETECTORS = load_detectors()

def extract_payloads_from_request(req):
    """
    Lấy tất cả payloads khả dĩ từ request để kiểm tra:
      - path segments (cuối path)
      - tất cả giá trị trong query string (request.args)
      - tất cả giá trị trong form (request.form)
      - JSON body (nếu có)
      - raw body (request.get_data())
    Trả về list các chuỗi (decoded).
    """
    payloads = []

    try:
        # path last segment
        path = req.path or ''
        try:
            decoded_path = unquote(path)
        except:
            decoded_path = path
        last_segment = decoded_path.split('/')[-1]
        if last_segment:
            payloads.append(last_segment)

        # query params
        for k, v in req.args.items():
            if v:
                payloads.append(unquote(v))

        # form data
        for k, v in req.form.items():
            if v:
                payloads.append(unquote(v))

        # json body
        try:
            json_body = req.get_json(silent=True)
            if isinstance(json_body, dict):
                for k, v in json_body.items():
                    if isinstance(v, str) and v.strip():
                        payloads.append(v)
                    else:
                        # if value is list/dict -> stringify
                        payloads.append(json.dumps(v, ensure_ascii=False))
            elif isinstance(json_body, list):
                payloads.append(json.dumps(json_body, ensure_ascii=False))
        except Exception:
            pass

        # raw body
        try:
            raw = req.get_data(as_text=True)
            if raw and raw.strip():
                payloads.append(unquote(raw))
        except Exception:
            pass

    except Exception as e:
        print(f"[WAF] Error extracting payloads: {e}")

    # deduplicate and filter empty
    cleaned = []
    seen = set()
    for p in payloads:
        if not p:
            continue
        s = p.strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
    return cleaned

def preprocess_single_payload(payload, vectorizer):
    """
    Vectorize a single payload using provided vectorizer.
    Trả về numpy array suitable for model.predict or None nếu không meaningful.
    """
    if not vectorizer:
        print("[WAF] No vectorizer provided for this detector. Skipping vectorize.")
        return None
    try:
        vec = vectorizer.transform([payload]).toarray()
        if not np.any(vec):
            # no tokens matched
            return None
        return vec
    except Exception as e:
        print(f"[WAF] Error vectorizing payload: {e}")
        return None

def rusicadeWAF_AI(app):
    """
    Register before_request handler to monitor incoming requests for multiple attack detectors.
    """
    @app.before_request
    def monitor_request():
        client_ip = request.remote_addr
        print(f"[WAF] Client IP: {client_ip}")
        payloads = extract_payloads_from_request(request)
        if not payloads:
            # nothing to check
            return None

        # iterate detectors
        for attack_name, detector in _DETECTORS.items():
            if detector is None:
                # not loaded
                continue

            for payload in payloads:
                preprocessed = preprocess_single_payload(payload, detector.vectorizer)
                if preprocessed is None:
                    # nothing meaningful for this payload & detector
                    continue

                try:
                    prediction = detector.model.predict(preprocessed) if detector.model is not None else [0]
                    print(f"[WAF] Attack={attack_name} payload='{payload}' prediction={prediction}")
                    if hasattr(prediction, '__len__') and prediction[0] == 1:
                        # call block feature (will check admin inside)
                        try:
                            detector.block_ips_feature(client_ip)
                        except Exception as e:
                            print(f"[WAF] Error blocking IP: {e}")
                        # return blocking page
                        return """
                        <html>
                            <head><title>Access Denied :Rusicade WAF_AI</title></head>
                            <body>
                                <h1 style="color:red"> Rusicade WAF_AI - Web Application Firewall</h1>
                                <h2>Error: Potential {attack} Detected!</h2>
                                <p>Your request has been blocked due to suspicious activity.</p>
                            </body>
                        </html>
                        """.format(attack=attack_name), 400
                except Exception as e:
                    print(f"[WAF] Error during prediction for {attack_name}: {e}")
                    continue

        # if none matched, allow request
        return None
