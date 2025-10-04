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

**✅ Điểm mạnh:**

Nhẹ, dễ hiểu, minh họa nguyên lý rule-based WAF.

Có UI quản lý rule → trực quan.

Có logging request để sau này phân tích (có thể làm auto rule-gen).

**⚠️ Hạn chế (so với chuẩn thực tế):**

Chỉ rule-based, chưa có anomaly scoring.

Chưa có tính năng negative security model (whitelist), chỉ mới positive (block khi khớp regex).

Chưa xử lý tốt false positive/false negative.

Chưa có high-performance engine (ModSecurity viết C, tích hợp vào Nginx/Apache, rất nhanh).


### Kiến trúc Web bán sách + WAF

👩‍💻 User (khách hàng)
       |
       v
 🌐 Frontend (React + Vite UI)
 http://localhost:5173
       |
       v
 🔰 WAF Proxy (waf.py)   <--- so khớp với rules.json
       |    (block nếu match rule)
       v
 🖥️ Backend App (backend_app.py)
       |--- 📚 Database (Books, Users, Orders)
       |
       v
  Trả dữ liệu (sách, giỏ hàng, thanh toán)


### Quản trị bảo mật (Admin)

👨‍💼 Admin
       |
       v
 🌐 Admin-UI (index.html)
 http://localhost:8080
       |
       v
 🛠️ Admin API (admin_api.py)
       |
       v
 📄 rules.json  <--- nơi lưu trữ rules
       |
       v
 🔰 WAF Proxy (waf.py)  <--- đọc rules.json để update filter


### 📑 Giải thích luồng

1. Khách hàng truy cập frontend để mua sách.

- Request gửi qua waf.py.

- waf.py kiểm tra rules.json.

- Nếu hợp lệ → chuyển vào backend_app.py.

- backend_app.py truy vấn database → trả kết quả về frontend.

2. Admin mở Admin-UI để quản lý rules.

- Gọi API tới admin_api.py.

- admin_api.py cập nhật rules.json.

- waf.py đọc rules.json → áp dụng rule mới.



# Demo Scenario

### 0) Chuẩn bị (khởi động services)

- Mở 3 terminal (hoặc 3 Run config) và trong mỗi terminal cd backend và activate venv nếu cần.

- Terminal A — WAF:

```
cd ATBM-WebApplicationFirewall/backend
# (nếu chưa active venv) venv\Scripts\activate  (Windows)  hoặc  source venv/bin/activate
python waf.py
# WAF lắng nghe: http://127.0.0.1:5000
```

- Terminal B — Backend app (ứng dụng bán sách giả lập):
```
cd ATBM-WebApplicationFirewall/backend
python backend_app.py
# Backend app lắng nghe: http://127.0.0.1:5001
```

- Terminal C — Admin API:
```
cd ATBM-WebApplicationFirewall/backend
python admin_api.py
# Admin API lắng nghe: http://127.0.0.1:5002
```

- (Optional) Chạy frontend React (nếu muốn demo UI người dùng):
```
cd ATBM-WebApplicationFirewall/frontend
npm install   # nếu chưa cài
npm run dev   # mở http://localhost:5173
```

- (Optional) Chạy admin-ui (dashboard tĩnh):
```
cd ATBM-WebApplicationFirewall/admin-ui
python -m http.server 8080
# rồi mở http://localhost:8080
```

### 1) Scenario A — Truy cập bình thường (không bị block)

**Mục tiêu**: chứng minh request đi qua WAF và được forward tới backend_app (trả nội dung ứng dụng).

**Cách 1 — Dùng trình duyệt (thích hợp khi dùng frontend React)**

- Mở http://localhost:5173 (frontend) hoặc test trực tiếp WAF:

  - Mở http://127.0.0.1:5000/search?q=iphone trong trình duyệt.

- Kết quả mong đợi: bạn thấy nội dung từ backend_app.py — ví dụ Search Results for: iphone.

**Cách 2 — Dùng curl (chắc chắn, terminal)**
```
curl -i "http://127.0.0.1:5000/search?q=iphone"
```

- Expected (HTTP):

  - Status 200 OK

  - Body chứa: Search Results for: iphone

**Kiểm tra log**

Mở file log hoặc dùng admin API:
```
# xem log cuối
tail -n 20 backend/logs/waf.log

# hoặc gọi admin_api
curl "http://127.0.0.1:5002/api/logs"
```

- Expected log entry: một dòng ALLOWED: <src_ip> /search?... (WAF ghi allowed).

### 2) Scenario B — Vi phạm match rule (bị block)

Mục tiêu: gửi payload khớp rule (<script>.*?</script>) trong rules.json → WAF phải chặn (403) và ghi log BLOCKED.

Dùng curl (POST với body có <script>)
curl -i -X POST "http://127.0.0.1:5000/comment" \
  -H "Content-Type: text/plain" \
  --data "<script>alert('xss-demo')</script>"


Expected (HTTP):

Status 403 Forbidden

Body: Blocked by RuleForge WAF (hoặc thông báo tương tự trong waf.py)

Dùng curl (GET với raw query — có thể cần encode behavior)

Trường hợp bạn muốn thử GET (nhiều browser auto-encode so query) — để chắc chắn dùng:

# gửi raw query bằng curl (shell-escaping)
curl -i "http://127.0.0.1:5000/search?q=<script>alert(1)</script>"


Nếu shell/terminal encode, dùng POST body cách trên là an toàn và đảm bảo match.

Kiểm tra log
# xem các dòng cuối
tail -n 30 backend/logs/waf.log

# hoặc admin API
curl "http://127.0.0.1:5002/api/logs"


Expected log entry: sẽ có một dòng chứa BLOCKED: <src_ip> /comment?... <script>... — tùy format bạn dùng logging.warning(f"BLOCKED: ...") trong waf.py. Nếu bạn đã đổi sang JSON logs, sẽ thấy trường matched_rule hoặc tương tự.
