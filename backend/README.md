# Backend — engine, pipeline, API

## Cấu trúc

| Thư mục | Vai trò |
|---|---|
| `engine/` | Suy luận, không phụ thuộc CSDL: `ids_features.py` (bản sao nguyên văn từ `Model Train`), `ids_rules.py` (tầng luật, từ `Test_Kich_Ban_C`), `cic_compat.py` (chuẩn hoá đầu vào CICFlowMeter), `analyzer.py` (mô hình + luật) |
| `pipeline/` | `ingest.py` đọc CSV mới, `aggregator.py` gom cảnh báo, `notifier.py` Telegram/email, `run.py` vòng lặp 5 s |
| `app/` | FastAPI: `models.py` (lược đồ CSDL), `api/` (các endpoint), `seed.py` (tạo bảng, admin) |
| `tools/` | `replay_pcap.py`: giả lập sensor từ pcap |
| `tests/` | `pytest` — chạy trên database `ids_test` |

## Lệnh thường dùng (từ thư mục `backend`, đặt `$env:PYTHONUTF8='1'`)

```powershell
.\.venv\Scripts\python.exe -m app.seed                 # tạo bảng + admin (--reset: xoá sạch rồi tạo lại)
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
.\.venv\Scripts\python.exe -m pipeline.run             # --once: chạy 1 chu kỳ
.\.venv\Scripts\python.exe -m tools.replay_pcap portscan.pcap
.\.venv\Scripts\python.exe -m pytest tests -q
```

Cấu hình tĩnh ở `.env` (mẫu: `.env.example`). Cấu hình lúc chạy (τ, ngưỡng luật, thông báo) ở bảng `settings`,
chỉnh trên trang Quản trị; pipeline đọc lại mỗi chu kỳ.

## Đầu vào từ CICFlowMeter

Pipeline đọc mọi file `*.csv` trong `INCOMING_DIR` (mặc định `data/incoming`), kể cả file đang được ghi nối tiếp.
Cần các cột định danh `Src IP, Src Port, Dst IP, Dst Port (hoặc Destination Port), Protocol, Timestamp` cùng
56 đặc trưng F_NOOS; tên cột kiểu CIC-IDS2017 hay CICFlowMeter-V4 đều được.

**Quy ước cờ TCP (quan trọng):** dữ liệu huấn luyện ghi cờ TCP dạng nhị phân và lệch cột (xem
`Test_Kich_Ban_C/results/Bao_Cao_Kich_Ban_C.md`, mục 2). `FLAG_MODE=auto` tự nhận biết: nếu CSV có số đếm cờ > 1
hoặc `RST Flag Count > 0` thì coi là đếm chuẩn và chuyển về quy ước huấn luyện (xấp xỉ). Khi cắm CICFlowMeter thật,
phát lại `portscan.pcap` qua nó và kiểm tra cột "Quy ước cờ" ở Quản trị → Mô hình & pipeline, cùng tỉ lệ phát hiện
PortScan.

## Mô hình

Mặc định `../Model Train/RF/models/rf_F_NOOS.joblib` (RF thắng theo quy tắc 3.8.5 ở kịch bản C), τ = 0,48
(τ* hiệu chỉnh ở kịch bản C). Đổi mô hình: sửa `MODEL_PATH` trong `.env`, khởi động lại API và pipeline.
Thư viện phải khớp phiên bản lúc huấn luyện (`requirements.txt`: scikit-learn 1.6.1).

## Lược đồ CSDL

| Bảng | Nội dung |
|---|---|
| `flows` | Từng luồng: định danh, số gói/byte, nhãn, điểm, nguồn phát hiện (`model`/`rule`), `alert_id` (giữ `FLOW_RETENTION_DAYS` ngày) |
| `alerts` | Một lượt tấn công: khoá gom, mức độ, nguồn – đích, thời gian luồng đầu/cuối, số luồng, trạng thái |
| `traffic_minute` | Số luồng theo phút × nhãn (cho trang Tổng quan) |
| `pipeline_runs` | Mỗi chu kỳ: số luồng, thời gian xử lý, lỗi (bằng chứng CN1) |
| `notifications` | Mỗi lần gửi Telegram/email kèm độ trễ (CN6) |
| `settings`, `users`, `ingest_offsets` | Cấu hình lúc chạy, tài khoản, vị trí đã đọc trong từng CSV |

## API chính (đầy đủ ở `/docs`)

| Endpoint | Quyền |
|---|---|
| `POST /api/auth/login`, `GET/PUT /api/auth/me` | — / đăng nhập |
| `GET /api/stats/overview`, `/timeseries`, `/top` (`?minutes=`) | xem |
| `GET /api/alerts` (lọc `status, label, severity, q, since, until, page, size`), `GET /api/alerts/{id}` | xem |
| `POST /api/alerts/{id}/ack`, `/close` | xem |
| `GET /api/flows`, `/api/model`, `/api/pipeline/status`, `/api/pipeline/runs` | xem |
| `GET/PUT /api/settings`, `POST /api/settings/test-notification` | quản trị |
| `GET/POST/PUT/DELETE /api/users` | quản trị |
| `POST /api/analyze` (tải CSV, gán nhãn không ghi CSDL) | quản trị |
| `GET /api/health` | — |
