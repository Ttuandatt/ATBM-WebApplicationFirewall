# WAF/RetrainModule.py
import pandas as pd
from TrainingModels.BinaryClassification.saved_models.AdaptiveWAF import main as retrain

def periodic_retrain():
    abnormal = pd.read_csv("logs/abnormal_data.csv", names=["payload", "is_malicious", "type"])
    if len(abnormal) > 100:
        print("Đang retrain model với dữ liệu mới...")
        # Gộp với dataset cũ và retrain
        retrain()  # gọi lại hàm train