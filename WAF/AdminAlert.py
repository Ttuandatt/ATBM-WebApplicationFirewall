# WAF/AdminAlert.py
import smtplib
from email.mime.text import MIMEText

def send_alert_to_admin(ip, attack_type, payload):
    # Cấu hình email ở đây
    pass  # Bạn có thể thêm Gmail/SMTP sau