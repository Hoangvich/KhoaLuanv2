# Hướng dẫn kết nối CSDL PostgreSQL

Hệ thống IDS lưu luồng, cảnh báo, cấu hình và tài khoản trong **PostgreSQL 16**. Backend (FastAPI và pipeline) kết nối qua SQLAlchemy và driver `psycopg` 3.

## 1. Thông tin kết nối mặc định

| Mục | Giá trị |
|---|---|
| Host | `localhost` |
| Port | `5432` |
| Database | `ids` (chạy hệ thống), `ids_test` (chạy `pytest`) |
| User | `ids_app` |
| Mật khẩu | `ids_app_dev` |
| Service Windows | `postgresql-x64-16` |
| Chuỗi kết nối (SQLAlchemy) | `postgresql+psycopg://ids_app:ids_app_dev@localhost:5432/ids` |

> Đây là tài khoản dùng khi phát triển. Lúc triển khai thật, đổi mật khẩu (mục 7) và không commit file `backend/.env`.

## 2. Cài PostgreSQL 16

1. Tải bộ cài Windows tại https://www.postgresql.org/download/windows/ (bản EDB), chọn phiên bản **16**.
2. Khi cài: giữ port `5432`, đặt mật khẩu cho tài khoản `postgres` và **ghi lại** (bước tạo database sẽ hỏi).
3. Kiểm tra service đang chạy:

```powershell
Get-Service postgresql-x64-16          # Status phải là Running
Start-Service postgresql-x64-16        # nếu đang Stopped
```

`psql.exe` nằm ở `C:\Program Files\PostgreSQL\16\bin\`. Muốn gõ `psql` ở mọi nơi thì thêm thư mục này vào biến môi trường `PATH`.

## 3. Tạo tài khoản, database và bảng

### Cách nhanh

Chạy script cài đặt từ thư mục gốc project; script tự làm cả mục 3 và mục 4:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

### Làm thủ công

```powershell
cd backend

# 1. Tạo role ids_app và hai database ids, ids_test (nhập mật khẩu postgres khi được hỏi)
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -h localhost -f scripts\setup_db.sql

# 2. Tạo bảng, cấu hình mặc định và tài khoản admin
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe -m app.seed
```

Script [scripts/setup_db.sql](scripts/setup_db.sql) chạy lại nhiều lần không lỗi: role và database đã có thì bỏ qua.

`app.seed` tạo 8 bảng: `users`, `settings`, `pipeline_runs`, `alerts`, `flows`, `traffic_minute`, `notifications`, `ingest_offsets`. Muốn xoá sạch dữ liệu và tạo lại bảng (chỉ dùng khi phát triển):

```powershell
.\.venv\Scripts\python.exe -m app.seed --reset
```

## 4. Cấu hình backend

Backend đọc chuỗi kết nối từ biến `DATABASE_URL` trong `backend/.env` (xem [app/config.py](app/config.py)). Nếu chưa có file này:

```powershell
cd backend
Copy-Item .env.example .env
```

Dòng cần sửa khi đổi host, user hoặc mật khẩu:

```ini
DATABASE_URL=postgresql+psycopg://<user>:<mật_khẩu>@<host>:<port>/<database>
```

- Mật khẩu có ký tự đặc biệt (`@ : / # %`…) phải mã hoá URL. Ví dụ `p@ss#1` thành `p%40ss%231`. Có thể dùng lệnh: `python -c "import urllib.parse; print(urllib.parse.quote('p@ss#1', safe=''))"`.
- Test dùng database `ids_test`. Muốn trỏ sang chỗ khác thì đặt biến `TEST_DATABASE_URL` trước khi chạy `pytest`.
- Sửa `.env` xong thì khởi động lại API và pipeline.

Kiểm tra backend kết nối được:

```powershell
cd backend
.\.venv\Scripts\python.exe -c "from app.db import engine; from sqlalchemy import text; print(engine.connect().execute(text('select version()')).scalar())"
```

In ra `PostgreSQL 16.x ...` là kết nối thành công.

## 5. Mở database bằng công cụ

### psql (dòng lệnh)

```powershell
chcp 65001                      # hiển thị tiếng Việt đúng trong console
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U ids_app -h localhost -d ids
```

Lệnh hay dùng trong psql:

| Lệnh | Ý nghĩa |
|---|---|
| `\dt` | Liệt kê bảng |
| `\d alerts` | Xem cấu trúc bảng `alerts` |
| `\x` | Bật/tắt hiển thị dọc (dễ đọc bản ghi dài) |
| `\q` | Thoát |

### DBeaver

1. **Database → New Database Connection → PostgreSQL**.
2. Điền: Host `localhost`, Port `5432`, Database `ids`, Username `ids_app`, Password `ids_app_dev`.
3. Lần đầu DBeaver sẽ hỏi tải driver, bấm **Download**.
4. **Test Connection** rồi **Finish**. Bảng nằm ở `ids → Schemas → public → Tables`.
5. Muốn thấy cả `ids_test`: tab **PostgreSQL**, tích **Show all databases**.

### pgAdmin 4 (đi kèm bộ cài PostgreSQL)

**Servers → Register → Server…**: tab *General* đặt tên tuỳ ý; tab *Connection* điền Host `localhost`, Port `5432`, Maintenance database `ids`, Username `ids_app`, Password `ids_app_dev`.

### Python ngoài backend (notebook, script phân tích)

```python
import pandas as pd
from sqlalchemy import create_engine

engine = create_engine('postgresql+psycopg://ids_app:ids_app_dev@localhost:5432/ids')
df = pd.read_sql('SELECT * FROM alerts ORDER BY last_seen DESC LIMIT 100', engine)
```

Cần cài `sqlalchemy` và `psycopg[binary]` (đã có trong `backend/requirements.txt`).

## 6. Các bảng và truy vấn mẫu

| Bảng | Nội dung |
|---|---|
| `users` | Tài khoản dashboard (`admin` / `viewer`), kênh nhận thông báo |
| `settings` | Cấu hình đổi được lúc chạy (τ, ngưỡng luật, kênh thông báo), dạng JSONB |
| `pipeline_runs` | Mỗi chu kỳ pipeline: số dòng vào, số luồng tấn công, thời gian xử lý, lỗi |
| `flows` | Từng luồng đã suy luận: IP/port, nhãn, điểm, nguồn (`model`/`rule`); chỉ giữ `FLOW_RETENTION_DAYS` ngày |
| `alerts` | Cảnh báo đã gom theo nguồn–đích, trạng thái `open`/`ack`/`closed` |
| `traffic_minute` | Số luồng theo phút × nhãn, dùng cho trang Tổng quan |
| `notifications` | Lịch sử gửi Telegram/Email và độ trễ |
| `ingest_offsets` | Vị trí đã đọc trong từng file CSV của CICFlowMeter |

```sql
-- Cảnh báo đang mở, mới nhất trước
SELECT id, label, severity, src_ip, dst_ip, dst_port, flow_count, source, last_seen
FROM alerts WHERE status = 'open' ORDER BY last_seen DESC;

-- Số luồng theo nhãn trong 1 giờ qua
SELECT label, SUM(flows) AS so_luong
FROM traffic_minute WHERE minute > now() - interval '1 hour'
GROUP BY label ORDER BY so_luong DESC;

-- 10 chu kỳ pipeline gần nhất
SELECT id, started_at, rows_in, rows_attack, alerts_new, round(ms::numeric, 1) AS ms, error
FROM pipeline_runs ORDER BY id DESC LIMIT 10;

-- Cấu hình runtime hiện tại
SELECT key, value, updated_by, updated_at FROM settings ORDER BY key;

-- Thông báo gửi lỗi
SELECT alert_id, channel, recipient, error, created_at FROM notifications WHERE status = 'failed';
```

> Nên **chỉ đọc** khi mở bằng công cụ ngoài. Cấu hình (`settings`) và tài khoản (`users`) sửa qua trang Quản trị để backend ghi đúng định dạng và băm mật khẩu.

## 7. Đổi mật khẩu `ids_app`

```sql
-- đăng nhập bằng postgres
ALTER ROLE ids_app PASSWORD 'mat-khau-moi';
```

Sau đó cập nhật `DATABASE_URL` trong `backend/.env` và khởi động lại API, pipeline.

## 8. Kết nối từ máy khác trong mạng LAN

Mặc định PostgreSQL chỉ nhận kết nối từ chính máy chủ. Để thành viên khác mở được bằng DBeaver:

1. Sửa `C:\Program Files\PostgreSQL\16\data\postgresql.conf`:

   ```ini
   listen_addresses = '*'
   ```

2. Thêm vào cuối `C:\Program Files\PostgreSQL\16\data\pg_hba.conf` (đổi dải mạng cho đúng LAN):

   ```
   host    ids,ids_test    ids_app    192.168.1.0/24    scram-sha-256
   ```

3. Mở cổng 5432 trên Windows Firewall và khởi động lại service (PowerShell chạy quyền Administrator):

   ```powershell
   New-NetFirewallRule -DisplayName 'PostgreSQL 5432' -Direction Inbound -Protocol TCP -LocalPort 5432 -Action Allow
   Restart-Service postgresql-x64-16
   ```

4. Máy kia dùng IP của máy chủ (xem bằng `ipconfig`) thay cho `localhost`.

Khi mở ra LAN thì **bắt buộc đổi mật khẩu** `ids_app` (mục 7).

## 9. Sao lưu và khôi phục

```powershell
$bin = 'C:\Program Files\PostgreSQL\16\bin'

# Sao lưu
& "$bin\pg_dump.exe" -U ids_app -h localhost -d ids -F c -f ids_backup.dump

# Khôi phục vào database ids (ghi đè đối tượng trùng tên)
& "$bin\pg_restore.exe" -U ids_app -h localhost -d ids --clean --if-exists ids_backup.dump
```

## 10. Lỗi thường gặp

| Thông báo lỗi | Nguyên nhân | Cách xử lý |
|---|---|---|
| `connection refused` / `Connection timed out` | Service chưa chạy, sai port, hoặc firewall chặn | `Start-Service postgresql-x64-16`; kiểm tra port; với LAN xem mục 8 |
| `password authentication failed for user "ids_app"` | Sai mật khẩu hoặc chưa chạy `setup_db.sql` | Chạy lại mục 3, hoặc đặt lại mật khẩu (mục 7) |
| `database "ids" does not exist` | Chưa tạo database | Chạy `scripts\setup_db.sql` (mục 3) |
| `relation "alerts" does not exist` | Chưa tạo bảng | `python -m app.seed` |
| `no pg_hba.conf entry for host ...` | Máy khác kết nối nhưng chưa được cho phép | Thêm dòng vào `pg_hba.conf` (mục 8) rồi restart service |
| `ModuleNotFoundError: No module named 'psycopg'` | Chưa cài thư viện hoặc không dùng `.venv` | `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` |
| `psql` không nhận lệnh | `bin` của PostgreSQL chưa có trong `PATH` | Gọi đường dẫn đầy đủ như trên, hoặc thêm vào `PATH` |
| Chữ tiếng Việt lỗi font trong psql | Console không ở UTF-8 | `chcp 65001` trước khi mở psql |
