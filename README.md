# Khoá luận AAHKL — Hệ thống giám sát và phát hiện bất thường mạng doanh nghiệp

| Thư mục | Nội dung |
|---|---|
| `Model Train/` | Huấn luyện RF, LightGBM, XGBoost, MLP (kịch bản A, B); gói mô hình `.joblib` |
| `Test_Kich_Ban_C/` | Kịch bản C: extractor khớp CICFlowMeter, tầng luật, đánh giá 3 mô hình, báo cáo |
| `backend/` | Engine suy luận, pipeline batch, API FastAPI, PostgreSQL |
| `frontend/` | Dashboard React (Tổng quan, Cảnh báo, Quản trị) |
| `scripts/` | Cài đặt, khởi động, phát lại pcap |
| `Data/`, `File Pcap/` | Dữ liệu hợp nhất, pcap mẫu |

## Chạy hệ thống

Yêu cầu: Python 3.12, Node.js 20+ (đã thử 24), PostgreSQL 16 (service `postgresql-x64-16`).

```powershell
# Lần đầu (tạo môi trường, database ids, tài khoản admin)
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1

# Mỗi lần chạy: mở 3 cửa sổ API, pipeline, frontend và trình duyệt
powershell -ExecutionPolicy Bypass -File scripts\start.ps1

# Chưa có sensor? Phát lại pcap như CICFlowMeter
powershell -ExecutionPolicy Bypass -File scripts\replay.ps1 portscan.pcap ddos.pcap
powershell -ExecutionPolicy Bypass -File scripts\replay.ps1 bruteforce.pcap --speed 20
```

- Dashboard: http://localhost:5173 — tài khoản mặc định `admin` / `admin123` (đổi ngay trong Hồ sơ).
- Tài liệu API (OpenAPI): http://localhost:8000/docs
- Database: `localhost:5432`, database `ids`, user `ids_app` / `ids_app_dev` (mở bằng DBeaver) — hướng dẫn: [backend/HUONG_DAN_KET_NOI_SQL.md](backend/HUONG_DAN_KET_NOI_SQL.md).

## Luồng dữ liệu

```
Cổng SPAN ─► CICFlowMeter ─► backend/data/incoming/*.csv ─► Pipeline (5 s) ─► PostgreSQL ◄─► FastAPI ◄─► React
                                   ▲                          │  RF + tầng luật theo nguồn
                    tools/replay_pcap (khi chưa có sensor)    └─ gom cảnh báo ─► Telegram / Email
```

Chi tiết: [backend/README.md](backend/README.md), [frontend/README.md](frontend/README.md).
