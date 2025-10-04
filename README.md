# ATBM-WebApplicationFirewall

# Hướng dẫn chạy thử code v0.0
### 1. Chạy backend
- Chuyển đến directory backend: ```cd backend```
- Chạy file waf.py: ```python waf.py```
- Chạy file backend_app.py: ```python backend_app.py```
- Chạy file admin_api.py: ```python admin_api.py```
### 2. Chạy front end
- Chuyển đến directory frontend: ```cd frontend```
- ```npm run dev```
### 3. Chạy admin-ui
- Chuyển đến directory admin-ui: ```cd admin-ui```
- Chạy giao diện Admin Dashboard: ```python -m http.server 8080```

*** Nếu có lỗi thì search ChatGPT để config nhé cả nhà ***

# WAF Informtaion

### 1. WAF này thuộc loại gì?

- Loại: Rule-based Web Application Firewall (tường lửa ứng dụng web dựa trên luật).

- Cơ chế: Dùng regex pattern matching để dò tìm payload độc hại trong HTTP request (ví dụ XSS <script>, SQLi UNION SELECT).

- Chuẩn/Nguyên lý: Nó tuân theo mô hình OWASP CRS (Core Rule Set) cơ bản – tức là phát hiện dựa vào signature/regex thay vì ML hay hành vi.

*👉 Nghĩa là: nó không phải network firewall (L3/L4), mà thuộc lớp Application Firewall (L7), cụ thể hơn là WAF theo chuẩn OWASP Top 10 (SQLi, XSS, RFI/LFI, Path Traversal...).*

### 2. So với các chuẩn/công nghệ ngoài thực tế

- ModSecurity (chuẩn phổ biến nhất, tích hợp CRS của OWASP): cũng hoạt động rule-based, nhưng có hàng nghìn rule, kèm theo anomaly scoring, whitelist/blacklist phức tạp hơn.

- AWS WAF / Cloudflare WAF: cũng có core rule set dựa trên regex + managed rules, nhưng họ có thêm AI/ML, scoring, geo-block, bot-detection.

- WAF hiện tại đang làm: phiên bản prototype nhẹ, dùng seed rules JSON để match request payload. Nó tương đương một bản mini-ModSecurity, phù hợp để học và thử nghiệm.

### 3. Các thành phần hệ thống hiện tại đang có

- Frontend: Web app (giả lập user gửi request).

- Backend (WAF proxy):

  - Nhận HTTP request từ user → kiểm tra payload dựa vào rules.json.

  - Nếu match rule → chặn + log lại (payload, URL, IP, timestamp).

  - Nếu không match → forward request đến ứng dụng đích (giống reverse proxy).

- Admin-UI:

  - Giao diện quản lý rules.

  - Load rules từ admin_api.py (/rules endpoint).

  - Cho phép bật/tắt, thêm rule mới.

### 4. Chuẩn hoạt động / Flow xử lý (chuẩn WAF cơ bản)

- User → gửi request (có thể chứa attack payload).

- Request đi qua WAF proxy (backend).

- So sánh request content với rules trong rules.json.

- Nếu match: block/log.

- Nếu không: forward đến app thật.

- Admin → dùng Admin-UI để quản lý rules.

- Admin-UI gọi API (/rules) từ admin_api.py.

- Rules được cập nhật vào rules.json.

- Backend reload hoặc đọc rules.json để update bộ lọc.

### 5. Điểm mạnh và hạn chế

***✅ Điểm mạnh:***

Nhẹ, dễ hiểu, minh họa nguyên lý rule-based WAF.

Có UI quản lý rule → trực quan.

Có logging request để sau này phân tích (có thể làm auto rule-gen).

***⚠️ Hạn chế (so với chuẩn thực tế):***

Chỉ rule-based, chưa có anomaly scoring.

Chưa có tính năng negative security model (whitelist), chỉ mới positive (block khi khớp regex).

Chưa xử lý tốt false positive/false negative.

Chưa có high-performance engine (ModSecurity viết C, tích hợp vào Nginx/Apache, rất nhanh).
