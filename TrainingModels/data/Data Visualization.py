import pandas as pd
import matplotlib.pyplot as plt

# Đường dẫn tới file CSV đầu ra mà Data_Cleaning.py tạo ra
# csv_path = "C:/Users/LENOVO/source/repos/ATBM-WebApplicationFirewall_30_10/TrainingModels/data/processed/processed_payloads.csv"

csv_path = "C:/Users/LENOVO/source/repos/ATBM-WebApplicationFirewall_30_10/payloads.csv"

# Đọc dữ liệu
df = pd.read_csv(csv_path)

# Đếm số lượng từng loại tấn công
attack_counts = df['injection_type'].value_counts()

# Hiển thị dữ liệu thống kê ra terminal
print("Số lượng từng loại injection:")
print(attack_counts)

# Vẽ biểu đồ cột
plt.figure(figsize=(8, 5))
attack_counts.plot(kind='bar', color='skyblue', edgecolor='black')

#plt.title('Số lượng từng loại tấn công (injection_type)')
plt.xlabel('Ịnjection Type')
plt.ylabel('Số lượng mẫu')
plt.xticks(rotation=0)
plt.grid(axis='y', linestyle='--', alpha=0.7)

plt.tight_layout()
plt.show()
