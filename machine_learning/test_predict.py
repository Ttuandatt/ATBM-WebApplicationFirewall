# test_predict.py
from ml_model import predict_request

samples = [
    "GET /index.html",
    "GET /search?q=' OR '1'='1",
    "<script>alert('xss')</script>"
]

for s in samples:
    print(s, "->", predict_request(s))
