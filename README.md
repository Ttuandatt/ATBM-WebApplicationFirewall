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

**Mục tiêu**: Mô phỏng các request chứa payload tấn công (trùng với regex rule trong rules.json) →
WAF phải phát hiện, chặn (HTTP 403), ghi log BLOCKED, và không forward tới backend.

### ⚔️ 1. Cross-Site Scripting (XSS Attack)

Mô phỏng hành vi:

Kẻ tấn công cố gắng chèn thẻ <script> vào nội dung người dùng gửi (form bình luận, ô tìm kiếm, v.v.).
Mục tiêu là khiến trình duyệt nạn nhân thực thi JavaScript độc hại.

Rule tương ứng trong rules.json:
```
{
    "id": 1,
    "type": "XSS",
    "pattern": "<script[^>]*?>[\\s\\S]*?<\\/script>",
    "enabled": true,
    "source": "seed",
    "comment": "Chặn payload XSS dạng <script>...</script>. Dùng để phát hiện script tag trực tiếp trong body/query. (FP risk: thấp nếu đã decode input)."
  }
```

Command demo:
```
curl -i -X POST "http://127.0.0.1:5000/comment" \
  -H "Content-Type: text/plain" \
  --data "<script>alert('xss-demo')</script>"
```

Expected (HTTP response):
```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Blocked by RuleForge WAF
```

Expected log entry (trong backend/logs/waf.log hoặc /api/logs):
```
{"timestamp": "...", "src_ip": "127.0.0.1", "path": "/comment", "payload": "<script>alert('xss-demo')</script>", "matched_rule": "(<script>.*?</script>)", "action": "BLOCKED"}
```

### 🧨 2. SQL Injection (SQLi Attack)

Mô phỏng hành vi:
Kẻ tấn công chèn câu lệnh SQL vào input để trích xuất dữ liệu từ database (như users hoặc passwords).

Rule tương ứng trong rules.json:
```
{
    "id": 3,
    "type": "SQLi",
    "pattern": "(?:union\\s+select\\b)",
    "enabled": true,
    "source": "seed",
    "comment": "Phát hiện pattern 'UNION SELECT' – chỉ dùng khi normalized và case-insensitive. Rất hiệu quả với SQLi dạng union-based."
  }
```

Command demo:
```
curl -i "http://127.0.0.1:5000/search?q=1 UNION SELECT username,password FROM users"
```

Expected (HTTP response):
```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Blocked by RuleForge WAF
```

Expected log entry:
```
{"timestamp": "...", "src_ip": "127.0.0.1", "path": "/search", "payload": "1 UNION SELECT username,password FROM users", "matched_rule": "(UNION.*SELECT.*FROM)", "action": "BLOCKED"}
```

### 🧱 3. Command Injection (CMD Injection)

Mô phỏng hành vi:
Kẻ tấn công cố gắng chèn lệnh hệ thống (;, &&, |, v.v.) vào input — ví dụ khi backend gọi os.system() hoặc subprocess.

Rule tương ứng trong rules.json:
```
{
  "id": 3,
  "type": "regex",
  "pattern": "([;&|]{1,2}\\s*(cat|ls|whoami|id|rm)\\b)",
  "enabled": true,
  "source": "seed",
  "comment": "Phát hiện Command Injection — khi người dùng cố gắng thực thi lệnh hệ thống."
}
```

Command demo:
```
curl -i "http://127.0.0.1:5000/search?q=iphone;ls"
```

Expected (HTTP response):
```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Blocked by RuleForge WAF
```

Expected log entry:
```
{"timestamp": "...", "src_ip": "127.0.0.1", "path": "/search", "payload": "iphone;ls", "matched_rule": "([;&|]{1,2}\\s*(cat|ls|whoami|id|rm)\\b)", "action": "BLOCKED"}
```

---

# FLASK
### 🧩 1. Flask là gì?

Flask là một web framework viết bằng Python, dùng để:

- Xây dựng web server (máy chủ web nhỏ gọn)

- Tạo API (Application Programming Interface) — giúp frontend (HTML/JS) giao tiếp với backend

- Xử lý HTTP requests (GET, POST, PUT, DELETE,...)

- Trả về dữ liệu JSON hoặc giao diện HTML

👉 Tóm gọn: Flask giúp Python “nói chuyện” với trình duyệt, và là bộ não điều phối logic backend.

### ⚙️ 2. Flask hoạt động như thế nào?
🔁 Chu trình hoạt động cơ bản:

- 1️⃣ Frontend (trình duyệt / HTML) gửi request HTTP đến Flask (ví dụ: GET /api/rules)
- 2️⃣ Flask nhận request → chạy hàm Python tương ứng (route handler)
- 3️⃣ Flask xử lý logic: đọc file, chạy script, truy vấn DB,...
- 4️⃣ Flask trả kết quả (HTML hoặc JSON) về cho frontend
- 5️⃣ Frontend hiển thị kết quả cho người dùng

### 📘 3. Vai trò của Flask trong project RuleForge

Trong project của ta, Flask (file admin_api.py) đóng vai trò như “API Server” cho trang quản trị RuleForge Admin UI.
Cụ thể:

|       Thành phần	      |                         Vai trò                             |
|---------------------------------------------------------------------------------------|
|  admin_api.py (Flask)   | 	Backend API – đọc dữ liệu rule, log, chạy analyzer      |
|      admin-ui/	      |   Frontend – giao diện người dùng quản trị hiển thị dữ liệu |
|      rules.json         |      	Cơ sở dữ liệu rule (mẫu tấn công WAF)               |
|         waf.log         |     	File lưu log truy cập (ghi lại hành vi bị chặn)     |
|      analyzer.py        |	      Script tự động phân tích log → tạo rule mới           |


### 🌐 4. Luồng hoạt động của hệ thống

Dưới đây là sơ đồ luồng hoạt động tổng thể trong project của bạn:
```
┌──────────────────────────────┐
│  Người dùng (Admin UI)       │
│  → index.html, script.js     │
└────────────┬─────────────────┘
             │ ① Gửi request HTTP
             │   (GET /api/rules, GET /api/logs, GET /api/analyze)
             ▼
┌──────────────────────────────┐
│ Flask server (admin_api.py)  │
│  - Xử lý API request         │
│  - Đọc rules.json            │
│  - Đọc logs/waf.log          │
│  - Gọi analyzer.py           │
└────────────┬─────────────────┘
             │ ② Xử lý logic bằng Python
             ▼
┌──────────────────────────────┐
│  Dữ liệu hệ thống backend    │
│  - rules.json                │
│  - logs/waf.log              │
│  - analyzer.py               │
└────────────┬─────────────────┘
             │ ③ Trả kết quả JSON
             ▼
┌──────────────────────────────┐
│  Frontend nhận dữ liệu JSON  │
│  - script.js xử lý JSON      │
│  - Render ra bảng HTML       │
└──────────────────────────────┘
```

### 🧠 5. Flask trong project RuleForge giúp ích như thế nào?
|          Mục tiêu          |	                    Flask đảm nhận                            |
|---------------------------------------------------------------------------------------------|
|    Xem danh sách rules     |      /api/rules đọc file rules.json, trả về JSON               |
|    Xem log hoạt động       |	    /api/logs đọc file waf.log, trả về log                    |
|    Chạy phân tích          |     	/api/analyze gọi analyzer.py sinh rule mới                |
|  Giao tiếp với giao diện	 |      Cho phép admin-ui (HTML/JS) truy cập dữ liệu qua HTTP     |
|      Bảo vệ CORS	         | Dùng flask_cors.CORS(app) cho phép frontend khác port truy cập |


### 💡 6. Ví dụ cụ thể về hoạt động

Khi ta nhấn nút “Load Rules” trên giao diện:

1️⃣ Giao diện gọi JS:

```
fetch("http://127.0.0.1:5002/api/rules")
```

2️⃣ Flask nhận request /api/rules → chạy:
```
@app.route("/api/rules", methods=["GET"])
def get_rules():
    with open("rules.json") as f:
        return jsonify(json.load(f))
```

3️⃣ Flask trả về:
```
[
  {"id": 1, "type": "SQLi", "pattern": "UNION SELECT", "enabled": true}
]
```

4️⃣ JavaScript nhận JSON → hiển thị trong <table>.

### 🧩 7. So sánh Flask với các framework khác
|   Framework	|   Ngôn ngữ   |            Đặc điểm                   |
|----------------------------------------------------------------------|
|     Flask	    |    Python    |   Nhẹ, linh hoạt, dễ dùng             |
|     Django	|    Python    |   Mạnh hơn, có ORM và admin site sẵn  |
|   Express.js	|   JavaScript |   Giống Flask nhưng chạy trên Node.js |
|   Spring Boot | 	  Java     |   Cho ứng dụng lớn, enterprise-scale  |


### ✅ Kết luận

- Flask = Bộ não backend của RuleForge.

- Nó nhận request từ frontend, xử lý dữ liệu rule & log, và gửi phản hồi lại.

- Nhờ Flask, bta có thể tách biệt frontend (giao diện) và backend (xử lý dữ liệu), tạo ra một hệ thống có cấu trúc rõ ràng, dễ mở rộng.


---

# Demo Command

### Các lệnh PowerShell (và tương đương curl) để demo từng kiểu vi phạm tương ứng với các rule số 11→17 (sẽ tạo) trong rules.json. Trước khi chạy, chắc chắn đã khởi động:

- WAF: python backend/waf.py (port 5000)

- Backend app: python backend/backend_app.py (port 5001)

- Admin API: python backend/admin_api.py (port 5002)

Mỗi lệnh sẽ gọi WAF (http://127.0.0.1:5000/ ...) — nếu rule khớp, WAF trả 403 và ghi log JSON vào backend/logs/waf.log. Sau mỗi test, có thể kiểm tra log qua Admin API:
```
# Xem logs (PowerShell)
Invoke-RestMethod -Uri "http://127.0.0.1:5002/api/logs" -Method Get

# Hoặc dùng curl
curl "http://127.0.0.1:5002/api/logs"
```

### 1) CRLF / Header injection (rule id 11)

Mục tiêu: chèn chuỗi CRLF (%0d%0a hoặc \r\n) + header tên như Set-Cookie hay Location. Mô phỏng header injection / HTTP response splitting — kẻ tấn công cố gắng chèn CRLF (%0d%0a hoặc \r\n) tiếp theo là một header (ví dụ Set-Cookie: hoặc Location:) để chèn header giả, thao túng cookie hoặc redirect người dùng.

Rule liên quan: CRLF_INJECTION

Pattern: (?:%0d%0a|\r\n).*(?:Content-Type:|Set-Cookie:|Location:)

Cách hoạt động & lưu ý:

- Gửi trong query vì dễ quan sát; WAF sẽ URL-decode nội dung trước khi so khớp.

- Nếu rule bật → WAF trả 403 + JSON lý do, đồng thời ghi log BLOCKED với matched_rule.

- Nếu browser tự encode/normalize khác, dùng curl với %0d%0a là an toàn.

**Kết quả mong đợi**: 
- 403 + log BLOCKED; admin-ui / admin_api sẽ hiển thị entry có CRLF_INJECTION.

PowerShell (GET, query-encoded):
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/search?q=%0d%0aSet-Cookie:evil=1" -Method Get -ErrorAction SilentlyContinue
```

curl:
```
curl -i "http://127.0.0.1:5000/search?q=%0d%0aSet-Cookie:evil=1"
```

PowerShell (POST body with raw CRLF — may be tricky in console; better send encoded):
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/comment" -Method Post -Body "%0d%0aLocation:http://evil.exampl
```

### 2) XPath / LDAP injection hint (rule id 12)

Mục tiêu: gửi payload có chữ xpath/ldap hoặc filter=(...) ví dụ XPath expression. Mô phỏng payload có dạng XPath expression hoặc các chuỗi liên quan xpath, ldap, filter= → dùng để thử tấn công XML/XPath/LDAP injection (khi backend xử lý XML/LDAP).

Rule liên quan: XPATH_LDAP_INJECTION

Pattern: (?:\b(xpath|ldap)\b|filter=\(|\[\*\])

Cách hoạt động & lưu ý:

- Payload không trực tiếp gây lỗi trên app demo (app chỉ hiển thị query) — mục đích demo là để WAF log/alert cho pattern này.

- Rule mặc định trong file có thể đang disabled; bật trước khi demo nếu muốn block.

Kết quả mong đợi:

- Nếu rule enabled → 403 + log BLOCKED.

- Nếu rule disabled → request đi qua (200) và admin logs ghi ALLOWED.

**Kết quả mong đợi:**

- Nếu rule enabled → 403 + log BLOCKED.

- Nếu rule disabled → request đi qua (200) và admin logs ghi ALLOWED.

PowerShell (GET):
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/search?q=filter=(//* )[1]" -Method Get -ErrorAction SilentlyContinue
```

curl:
```
curl -i -G "http://127.0.0.1:5000/search" --data-urlencode "q=filter=(//* )[1]"
```

### 3) Suspicious long token (rule id 13)

Mục tiêu: gửi chuỗi >=80 ký tự (alnum/_/-) để kích hoạt.

Giả lập chuỗi dài khả nghi (base64, shellcode, long token) — rule cảnh báo khi có chuỗi alnum >= 80 ký tự. Dùng để phát hiện payload dài bất thường.

Rule liên quan: SUSPICIOUS_LONG_TOKEN

Pattern: [A-Za-z0-9\-_]{80,}

Cách hoạt động & lưu ý:

- Vì dễ false positive (ví dụ JWT, API token), rule thường disabled hoặc chỉ log.

- Dùng POST body giúp tránh URL encoding issues.

Kết quả mong đợi:

- Nếu rule enabled → 403; thường demo sẽ để rule disabled và xem log để minh họa cảnh báo.

PowerShell (POST with long token in body):
```
# tạo token 90 ký tự
$tok = ('A' * 90)
Invoke-RestMethod -Uri "http://127.0.0.1:5000/redeem" -Method Post -Body $tok -ContentType "text/plain" -ErrorAction SilentlyContinue
```

curl:
```
curl -i -X POST "http://127.0.0.1:5000/redeem" --data "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

### 4) SQL comment / obfuscation (rule id 14)

Mục tiêu: chứa /* ... */ trong input.
- /* ... */ là kỹ thuật obfuscation tấn công SQL (cố tình chèn comment để né bộ lọc).

- UNION SELECT ... mô phỏng SQL injection kiểu union-based để trích dữ liệu.

Rule liên quan:
- SQL_COMMENT_OBFUSCATION pattern: (?:/\*.*?\*/)

- SQLi pattern (seed/analyzer): (?:union\s+select\b) hoặc analyzer-generated (UNION|SELECT).*FROM

**Kết quả mong đợi:**

- Nếu rule enabled → 403 + BLOCKED log.

- Nếu rule disabled → request đi qua; analyzer sau này có thể tạo rule nếu nhiều BLOCKs xuất hiện.

PowerShell (GET):
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/search?q=1/*comment*/" -Method Get -ErrorAction SilentlyContinue
```

curl:
```
curl -i "http://127.0.0.1:5000/search?q=1/*comment*/" (SQL comment obfuscation)
```

Ta cũng có thể thử typical SQL payloads:
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/search?q=UNION+SELECT+password+FROM+users" -Method Get -ErrorAction SilentlyContinue (UNION-based SQLi)
```

### 5) Suspicious file extension (rule id 15)

Mục tiêu: truy cập tải/đường dẫn file .php, .jsp, .asp v.v.
- Phát hiện truy vấn/đường dẫn chứa extension thực thi server-side (.php, .jsp, .asp) — thường liên quan upload shell hoặc truy cập file thực thi.

- Kết hợp với path traversal (../) có thể dẫn tới LFI/RFI.

Rule liên quan: SUSPICIOUS_FILE_EXT và PATH_TRAVERSAL

- SUSPICIOUS_FILE_EXT pattern: (?:\.phps?|\.phtml|\.jsp|\.asp[x]?)$

- PATH_TRAVERSAL pattern: (?:%2e%2e%2f|%2e%2e\/|\.{2}%2f|\.{2}\/) hoặc (\.\./|/etc/passwd|/proc/self/environ)

Cách hoạt động & lưu ý:

- Để trigger, gửi tên file trong query/path.

- Có thể cần toLower/normalize để match encoded sequences.

**Kết quả mong đợi**: 403 + BLOCKED log nếu rule enabled.

PowerShell (GET):
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/download?file=shell.php" -Method Get -ErrorAction SilentlyContinue
```

curl:
```
curl -i "http://127.0.0.1:5000/download?file=shell.php"
```

Hoặc path traversal test:
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/search?q=../../etc/passwd" -Method Get -ErrorAction SilentlyContinue
```

### 6) Command injection pattern (rule id 16)

Mục tiêu: chèn ; ls hoặc | whoami v.v. Mô phỏng command injection — chèn shell metacharacters (;, |) kèm lệnh (whoami, ls, cat, rm), cố gắng thực thi lệnh trên server.

Rule liên quan: regex pattern: ([;&|]{1,2}\s*(cat|ls|whoami|id|rm)\b)

Cách hoạt động & lưu ý:

- Rule có thể dễ false-positive nếu ứng dụng chấp nhận chuỗi như a|b hợp lệ; cân nhắc bật chỉ ở môi trường nhạy cảm.

- Gửi POST body hoặc encoded GET để đảm bảo WAF nhận đúng chuỗi.

**Kết quả mong đợi**: 403 + BLOCKED log khi match.


PowerShell (GET with encoded characters):
```
# dùng --data-urlencode with curl style via Invoke-RestMethod not trivial; use curl for simplicity:
curl -i "http://127.0.0.1:5000/search?q=%3B%20ls%20-l"
```

curl raw:
```
curl -i "http://127.0.0.1:5000/search?q=%3B%20whoami"
```

PowerShell using POST body (raw semicolon):
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/comment" -Method Post -Body "; ls -la" -ContentType "text/plain" -ErrorAction SilentlyContinue
```

### 7) XSS with <script> (rule id 17)

Mục tiêu: gửi <script>...</script> trong body (POST) hoặc query. Mô phỏng Cross-Site Scripting (XSS) kiểu chèn thẻ <script> trong input, muốn chạy script trên trình duyệt nạn nhân.

Rule liên quan: XSS_ATTACK / XSS

Pattern: <script[^>]*?>[\s\S]*?<\/script> hoặc <script.*?>.*?</script>

Cách hoạt động & lưu ý:

- POST body thường ít bị encoding, dễ trigger.

- WAF decode/normalize trước khi match; nhiều WAF còn áp thêm HTML-entity decode để bắt evasion (&lt;script&gt;).

**Kết quả mong đợi**: 403 + BLOCKED log.

PowerShell (POST body):
```
Invoke-RestMethod -Uri "http://127.0.0.1:5000/comment" -Method Post -Body "<script>alert('xss')</script>" -ContentType "text/plain" -ErrorAction SilentlyContinue
```

curl:
```
curl -i -X POST "http://127.0.0.1:5000/comment" -H "Content-Type: text/plain" --data "<script>alert('xss')</script>"
```

GET variant (encoded):
```
curl -i "http://127.0.0.1:5000/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

### Kiểm tra kết quả

- Nếu rule match → WAF trả HTTP 403 với JSON chứa "message": "Blocked by WAF (rule ...)".

- Kiểm tra log JSON file backend/logs/waf.log hoặc Admin API GET /api/logs.

- Admin UI (http://localhost:8080) → Load Logs / Load Rules sẽ hiển thị cập nhật.

- Dùng Admin API:

    - Rules: curl "http://127.0.0.1:5002/api/rules"

    - Logs: curl "http://127.0.0.1:5002/api/logs"

### Lưu ý / Troubleshoot nhanh

- Nếu request bị browser auto-encode (GET), dùng POST body để đảm bảo chuỗi không bị encode.

- Một vài pattern (ví dụ long token) có thể bị disabled (enabled: false) — check rules.json trước.

- Nếu Admin API CORS lỗi khi dùng admin-ui, chắc chắn admin_api.py đã CORS(app).

- Để tránh false-positive thử từng rule 1-1 với payload nhỏ gọn.

- Trước demo, enalbe/disable rule mong muốn bằng sửa rules.json để minh hoạ block vs allow. (hoặc dùng UI nếu có endpoint toggle).

- Dùng POST body khi bạn cần payload không bị URL-encoding.

- Kiểm soát false positives: một vài rule (long token, cmd injection, xpath...) tốt nhất để enabled: false và chỉ log để phòng FP trong demo nếu backend giả lập có input hợp lệ.

- Analyzer: nếu bạn muốn tự động sinh rule từ logs, chạy GET /api/analyze sau khi có nhiều BLOCK để xem nó thêm rule vào rules.json.