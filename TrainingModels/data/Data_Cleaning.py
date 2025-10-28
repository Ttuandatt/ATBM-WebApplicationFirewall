#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prepare_payloads.py

Đọc các file payload (SQLCollection.txt, XSSCollection.txt, ShellCollection.txt),
và file non-maliciousCollection.txt (CSV-like), làm sạch format cơ bản,
gán nhãn và lưu thành CSV để dùng cho training.

Output:
  TrainingModels/data/processed/processed_payloads.csv

Usage:
  python prepare_payloads.py
"""

from pathlib import Path
import csv
import sys

# --- Cấu hình đường dẫn (thay đổi nếu cần) ---
BASE = Path(__file__).resolve().parent  # nơi script nằm
# Input mặc định: BASE/data/raw/<filename>
INPUT_DIR = BASE / "raw"
# Output : ../TrainingModels/data/processed/processed_payloads.csv
OUTPUT_DIR = BASE.parent / "data" / "processed"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = OUTPUT_DIR / "processed_payloads.csv"

# Map input filenames -> injection type
FILES = {
    "SQLCollection.txt": "SQL",
    "XSSCollection.txt": "XSS",
    "ShellCollection.txt": "SHELL",
    "non-maliciousCollection.txt": "LEGAL"     # non-maliciousCollection.txt có cấu trúc CSV-like: id,payload,is_malicious,injection_type
}

def read_lines_preserve_whitespace(path):
    """
    Đọc file trả về list các dòng nguyên gốc (loại bỏ newline).
    Giữ whitespace nội tại của dòng (không .strip()).
    Xóa BOM nếu có ở đầu file/đầu dòng.
    """
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                # remove trailing newline characters but keep internal/leading/trailing spaces
                line = raw.rstrip("\r\n")
                # remove a possible BOM at beginning of file/first line
                if line.startswith("\ufeff"):
                    line = line.lstrip("\ufeff")
                out.append(line)
    except FileNotFoundError:
        print(f"[WARN] File not found: {path}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Failed reading {path}: {e}", file=sys.stderr)
    return out

def normalize_payload(s):
    """
    Chuẩn hoá nhẹ payload:
    - Nếu là None -> ''
    - Bỏ byte-order-mark nếu còn sót
    - Thay các newline bên trong thành space (để tránh ghi CSV bị phá vỡ hàng)
    - Giữ nguyên leading/trailing spaces (nếu bạn muốn trim, đổi ở đây)
    """
    if s is None:
        return ""
    s = str(s)
    # strip BOM if anywhere (just in case)
    s = s.replace("\ufeff", "")
    # replace internal CR/LF with single space to keep single-line CSV rows
    s = s.replace("\r", " ").replace("\n", " ")
    return s

def load_all_payloads(input_dir, files_map):
    """
    Trả về list of tuples (payload_string, is_malicious_int, injection_type_str)
    Xử lý đặc biệt cho file non-malicious (LEGAL) nếu file có dạng CSV.
    """
    records = []
    for fname, inj_type in files_map.items():
        p = Path(input_dir) / fname
        if not p.exists():
            print(f"[INFO] Missing file: {p} -- skipping.")
            continue

        # Nếu là file LEGAL (non-malicious) nhiều khả năng đã có cấu trúc CSV-like -> parse bằng csv.reader
        if inj_type == "LEGAL":
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if not row:
                            continue
                        # We expect something like: id,payload,is_malicious,injection_type
                        # But be tolerant: payload might contain commas; so handle len >= 2
                        if len(row) >= 4:
                            # typical case
                            # id = row[0]
                            payload = ",".join(row[1:-2]) if len(row) > 4 else row[1]
                            # but more robust approach: assume last two columns are is_malicious and injection_type
                            try:
                                is_mal = int(row[-2])
                            except Exception:
                                # fallback if not int
                                is_mal = 0
                            inj_t = row[-1] if row[-1] else "LEGAL"
                        elif len(row) == 3:
                            # maybe id,payload,injection_type  or id,payload,is_malicious
                            # We'll assume format id,payload,is_malicious
                            payload = row[1]
                            try:
                                is_mal = int(row[2])
                            except Exception:
                                is_mal = 0
                            inj_t = "LEGAL"
                        elif len(row) == 2:
                            # maybe payload,is_malicious
                            payload = row[0] if row[0] else row[1]
                            try:
                                is_mal = int(row[1])
                            except Exception:
                                is_mal = 0
                            inj_t = "LEGAL"
                        else:
                            # len(row)==1 -> it's a raw payload token (unexpected for LEGAL file), treat as payload
                            payload = row[0]
                            is_mal = 0
                            inj_t = "LEGAL"

                        payload = normalize_payload(payload)
                        # skip truly empty
                        if payload == "":
                            continue
                        records.append((payload, int(is_mal), inj_t))
            except Exception as e:
                print(f"[ERROR] Failed to parse LEGAL file {p}: {e}", file=sys.stderr)
            continue

        # else: treat each line as a payload text, label=1
        lines = read_lines_preserve_whitespace(p)
        if not lines:
            print(f"[INFO] No lines loaded from {p} (maybe file empty).")
            continue
        for line in lines:
            # If the line is completely empty string (length 0) -> skip
            # If the line contains only whitespace, we keep it (user sample included ' ' etc.)
            if line == "":
                # skip truly empty lines
                continue
            cleaned = normalize_payload(line)
            # After normalization, still skip empty
            if cleaned == "":
                continue
            records.append((cleaned, 1, inj_type))
    return records

def deduplicate_preserve_order(records):
    """
    records: list of tuples (payload, is_malicious, injection_type)
    Return deduped list preserving first occurrence (based on payload string only).
    """
    seen = set()
    out = []
    for payload, label, inj in records:
        if payload in seen:
            continue
        seen.add(payload)
        out.append((payload, label, inj))
    return out

def write_csv(records, out_file):
    """
    Ghi CSV có header index,payload,is_malicious,injection_type
    Sử dụng quoting=csv.QUOTE_MINIMAL để giữ nguyên ký tự đặc biệt,
    nhưng csv module sẽ tự escape (dùng ").
    """
    with open(out_file, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.writer(csvf, quoting=csv.QUOTE_MINIMAL)
        # header (lưu ý theo ví dụ bạn muốn index đầu tiên)
        writer.writerow(["index", "payload", "is_malicious", "injection_type"])
        for i, (payload, label, inj) in enumerate(records):
            writer.writerow([i, payload, label, inj])

def main():
    print("== Preparing payloads ==")
    print(f"Input dir: {INPUT_DIR}")
    print(f"Output file: {OUTPUT_FILE}")
    raw = load_all_payloads(INPUT_DIR, FILES)
    print(f"Loaded {len(raw)} raw payload lines (including duplicates).")
    dedup = deduplicate_preserve_order(raw)
    print(f"After deduplication: {len(dedup)} unique payloads.")
    # Optional: sort or shuffle here if you want; currently preserve original order (SQL first, then XSS, then SHELL, then LEGAL)
    write_csv(dedup, OUTPUT_FILE)
    print("Saved processed CSV.")
    print("Done.")

if __name__ == "__main__":
    main()
