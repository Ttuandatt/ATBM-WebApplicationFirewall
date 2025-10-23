"""
1_Data_cleaning.py
------------------
Script làm sạch dữ liệu payload cho dự án Machine Learning Web Application Firewall (WAF)

Chức năng:
- Đọc dữ liệu từ các file .txt (SQL, XSS, SHELL)
- Gắn nhãn (malicious hoặc non-malicious)
- Làm sạch dữ liệu: loại bỏ trùng, trống, ký tự thừa, payload lỗi
- Trộn ngẫu nhiên dữ liệu để tránh bias
- Lưu kết quả thành .csv và .pickle để sử dụng trong bước phân tích
"""

# ===============================
# STEP 1: Import thư viện cần thiết
# ===============================
import numpy as np
import pandas as pd
import pickle

# ===============================
# STEP 2: Định nghĩa hàm đọc file .txt và tạo DataFrame
# ===============================
def from_txt_to_dataframe(src_file, is_malicious, injection_type):
    """
    Đọc payloads từ file txt trong thư mục 'data/'
    và tạo thành DataFrame gồm:
    - payload: chuỗi dữ liệu
    - is_malicious: 1 nếu là dữ liệu tấn công, 0 nếu hợp lệ
    - injection_type: loại tấn công (SQL, XSS, SHELL, LEGAL)
    """
    path = f"data/{src_file}.txt"
    with open(path, "r", encoding="utf-8") as f:
        payloads_txt = f.readlines()

    # Tạo DataFrame từ danh sách payloads
    payloads = pd.DataFrame(payloads_txt, columns=["payload"])
    payloads["is_malicious"] = [is_malicious] * len(payloads)
    payloads["injection_type"] = [injection_type] * len(payloads)

    print(f"[INFO] Loaded {len(payloads)} payloads from {src_file}.txt ({injection_type})")
    print(payloads.head(), "\n")
    return payloads


# ===============================
# STEP 3: Gộp tất cả payloads vào 1 DataFrame
# ===============================
payloads = pd.DataFrame(columns=["payload", "is_malicious", "injection_type"])

payloads = pd.concat([
    from_txt_to_dataframe("SQLCollection", 1, "SQL"),
    from_txt_to_dataframe("XSSCollection", 1, "XSS"),
    from_txt_to_dataframe("ShellCollection", 1, "SHELL"),
    from_txt_to_dataframe("non-maliciousCollection", 0, "LEGAL")
], ignore_index=True)

print(f"[INFO] Tổng số dòng ban đầu: {len(payloads)}\n")

# ===============================
# STEP 4: Làm sạch dữ liệu
# ===============================

# 4.1. Xóa ký tự xuống dòng '\n' và khoảng trắng dư thừa
payloads["payload"] = payloads["payload"].str.strip("\n")
payloads["payload"] = payloads["payload"].str.strip()

# 4.2. Loại bỏ dòng trống
rows_before = len(payloads)
payloads = payloads[payloads["payload"].str.len() != 0]
print(f"[CLEAN] Empty payloads removed: {rows_before - len(payloads)}")

# 4.3. Loại bỏ payload tấn công có độ dài = 1 ký tự
rows_before = len(payloads)
payloads = payloads[
    (payloads["is_malicious"] == 0) |
    ((payloads["is_malicious"] == 1) & (payloads["payload"].str.len() > 1))
]
print(f"[CLEAN] Malicious payloads of length 1 removed: {rows_before - len(payloads)}")

# 4.4. Loại bỏ dòng trùng lặp
rows_before = len(payloads)
payloads = payloads.drop_duplicates(subset="payload", keep="last")
print(f"[CLEAN] Duplicate payloads removed: {rows_before - len(payloads)}")

# 4.5. Xử lý các payload có định dạng byte (b'<payload>') → chuyển thành chuỗi bình thường
payloads["payload"] = [
    p[2:-1] if p.startswith("b'") or p.startswith('b"') else p
    for p in payloads["payload"]
]

# ===============================
# STEP 5: Shuffle dữ liệu và reset index
# ===============================
payloads = payloads.sample(frac=1).reset_index(drop=True)
payloads.index.name = "index"

# ===============================
# STEP 6: Lưu dữ liệu ra file CSV
# ===============================
payloads.to_csv("data/payloads.csv", encoding="utf-8")
print(f"[SAVE] Dữ liệu đã lưu vào data/payloads.csv ({len(payloads)} dòng)")

# ===============================
# STEP 7: Kiểm tra và loại bỏ giá trị null sau khi lưu CSV
# ===============================
payloads = pd.read_csv("data/payloads.csv", index_col="index", encoding="utf-8")
rows_before = len(payloads)
payloads = payloads[~payloads["payload"].isnull()]
print(f"[CLEAN] Null/NaN payloads removed: {rows_before - len(payloads)}")

# Lưu lại file CSV sau khi loại null
payloads.to_csv("data/payloads.csv", encoding="utf-8")

# ===============================
# STEP 8: (Tuỳ chọn) Lưu DataFrame thành file .pickle để load nhanh sau này
# ===============================
with open("data/payloads.pkl", "wb") as f:
    pickle.dump(payloads, f)
print("[SAVE] DataFrame đã lưu vào data/payloads.pkl")

print("\n[INFO] Data cleaning hoàn tất.")
print(f"Tổng số payloads cuối cùng: {len(payloads)}")
print(payloads.head())
