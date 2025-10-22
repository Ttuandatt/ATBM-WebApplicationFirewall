from ml_model import predict_request

sample = {
    "Source Port": 50553,
    "Destination Port": 3389,
    "NAT Source Port": 50553,
    "NAT Destination Port": 3389,
    "Bytes": 3327,
    "Bytes Sent": 1438,
    "Bytes Received": 1889,
    "Packets": 15,
    "Elapsed Time (sec)": 17,
    "pkts_sent": 8,
    "pkts_received": 7
}

pred, prob = predict_request(sample)
print(f"Kết quả dự đoán: {'🚫 Attack' if pred else '✅ Allow'} — Xác suất: {prob:.2f}")
