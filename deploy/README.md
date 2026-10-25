# Triển khai hệ thống IDS AAHKL lên VPS Ubuntu 22.04

Hướng dẫn đưa toàn bộ hệ thống (API FastAPI + pipeline + PostgreSQL + dashboard React) chạy như dịch vụ thật trên một VPS Ubuntu, truy cập qua trình duyệt. Đây là phần **triển khai thực tế** của khoá luận.

Kết quả cuối: dashboard ở `http://<IP-VPS>/`, pipeline và API tự chạy nền, tự khởi động lại khi reboot.

```
Internet ──► Nginx (cổng 80) ──► dashboard React (tĩnh)  +  /api ─► FastAPI (127.0.0.1:8000)
                                                                         │
                          pipeline (systemd, chu kỳ 5 s) ──────────► PostgreSQL 16 (chỉ localhost)
```

PostgreSQL và FastAPI chỉ lắng nghe nội bộ; chỉ Nginx mở ra ngoài. Tường lửa chỉ mở 22/80/443.

---

## 0. Trước khi bắt đầu (bảo mật)

Mật khẩu root của VPS đã từng bị lộ (dán trong chat), **đổi ngay**:

```bash
passwd
```

Mọi bước dưới đây chạy bằng `root` (hoặc thêm `sudo`).

## 1. Clone mã nguồn về `/opt/aahkl`

```bash
apt-get update && apt-get install -y git
git clone https://github.com/Hoangvich/KhoaLuanv2.git /opt/aahkl
```

> Đường dẫn `/opt/aahkl` là cố định trong các file dịch vụ systemd. Nếu muốn dùng chỗ khác, sửa `APP_DIR` ở đầu `deploy/setup_vps.sh` và hai đường dẫn trong `deploy/ids-*.service`.

Repo khá nặng (~0,5 GB vì có pcap và dữ liệu). Nếu mạng chậm và chỉ cần chạy hệ thống (chưa cần phát lại pcap), có thể bỏ qua thư mục nặng:

```bash
git clone --filter=blob:none https://github.com/Hoangvich/KhoaLuanv2.git /opt/aahkl
# Mô hình RF (~4,5 MB) nằm trong Model Train nên vẫn được tải; chỉ các blob lớn mới tải khi cần.
```

## 2. (Tuỳ chọn) Đặt trước mật khẩu admin và IP

Script sẽ **tự sinh mật khẩu admin ngẫu nhiên** và in ra một lần, nên có thể bỏ qua bước này. Nếu muốn tự đặt, sửa `deploy/env.production.example` trước khi chạy:

```bash
nano /opt/aahkl/deploy/env.production.example
# ADMIN_PASSWORD=...        (mật khẩu admin tự chọn)
# CORS_ORIGINS=http://103.65.234.246   (đổi thành IP/tên miền của bạn)
```

## 3. Chạy script cài đặt

```bash
cd /opt/aahkl
sudo bash deploy/setup_vps.sh
```

Script tự làm 9 bước: cài gói (Python 3.12, PostgreSQL 16, Nginx, Node 20) → tạo user dịch vụ `ids` → tạo CSDL → cài thư viện Python → tạo `backend/.env` → tạo bảng + admin → build frontend → cài 2 dịch vụ systemd + Nginx → bật tường lửa. Chạy lại nhiều lần không hỏng.

Cuối cùng script in **mật khẩu admin** (nếu tự sinh) và địa chỉ dashboard. **Ghi lại mật khẩu**, đăng nhập rồi đổi trong **Hồ sơ**.

## 4. Kiểm tra

```bash
systemctl status ids-api ids-pipeline --no-pager   # cả hai phải active (running)
curl -s http://127.0.0.1:8000/api/health            # {"status":"ok","db":"ok",...}
journalctl -u ids-pipeline -f                        # xem pipeline chạy mỗi 5 s (Ctrl+C để thoát)
```

Mở trình duyệt: `http://<IP-VPS>/` → đăng nhập admin.

## 5. Đưa dữ liệu vào để thấy cảnh báo

Ban đầu dashboard trống vì chưa có luồng. Pipeline đọc mọi file `*.csv` trong `backend/data/incoming/`. Hai cách đưa dữ liệu:

**a) Phát lại pcap mẫu (nhanh, để demo/chụp ảnh báo cáo).** Cần cài thêm scapy một lần:

```bash
cd /opt/aahkl/backend
sudo -u ids ./.venv/bin/python -m pip install scapy==2.6.0
sudo -u ids PYTHONUTF8=1 ./.venv/bin/python -m tools.replay_pcap portscan.pcap ddos.pcap bruteforce.pcap benign.pcap
```

Pipeline sẽ gom cảnh báo, dashboard cập nhật sau vài giây. (Chỉ chạy được nếu đã clone đầy đủ `File Pcap/`.)

**b) Sensor thật.** Trỏ CICFlowMeter ghi CSV vào `/opt/aahkl/backend/data/incoming/`. Pipeline tự đọc phần mới. Nhớ `chown ids:ids` thư mục nếu CICFlowMeter chạy bằng user khác.

## 5.1. (Tuỳ chọn) Bật sensor sống — giám sát trực tiếp

Mặc định pipeline chỉ đọc CSV/replay. Bật thêm **sensor** để hệ thống **giám sát trực tiếp**: liên tục bắt gói trên cổng mạng của VPS, trích xuất luồng và nạp vào pipeline. Khi đó dashboard phản ánh lưu lượng thật đến/đi của máy theo thời gian gần thực (gồm cả các lượt quét cổng thật mà mọi IP public trên Internet đều nhận).

Đây là chức năng **phòng thủ/quan sát**: chỉ nghe lưu lượng của chính VPS, không tác động ra ngoài.

```bash
cd /opt/aahkl && git pull
# Cần tcpdump và scapy (nếu chưa có)
apt-get install -y tcpdump
sudo -u ids /opt/aahkl/backend/.venv/bin/python -m pip install scapy==2.6.0
# Cài và bật dịch vụ sensor
install -m 755 deploy/sensor.sh /opt/aahkl/deploy/sensor.sh
install -m 644 deploy/ids-sensor.service /etc/systemd/system/ids-sensor.service
systemctl daemon-reload
systemctl enable --now ids-sensor.service
systemctl status ids-sensor --no-pager
```

- Mặc định sensor nghe cổng ra Internet (tự dò). Muốn nghe **mạng riêng Tailscale** thì sửa dòng `Environment=IFACE=tailscale0` trong `/etc/systemd/system/ids-sensor.service` rồi `systemctl daemon-reload && systemctl restart ids-sensor`.
- Theo dõi: `journalctl -u ids-sensor -f` (thấy "Đã ghi N luồng..." mỗi ~30 s).
- Tắt: `systemctl disable --now ids-sensor`.

## 6. HTTPS và truy cập (quan trọng khi mở ra Internet)

Hiện cấu hình chạy HTTP qua IP. Vì **mật khẩu đăng nhập đi dạng rõ (cleartext) trên HTTP**, khi demo công khai nên:

- Có tên miền trỏ về IP → cài chứng chỉ miễn phí: `apt-get install -y certbot python3-certbot-nginx && certbot --nginx -d ten-mien-cua-ban`.
- Chỉ có IP (Let's Encrypt không cấp cho IP) → hoặc dùng chứng chỉ tự ký, hoặc giới hạn truy cập bằng tường lửa chỉ cho IP nhà/trường khi trình diễn:
  ```bash
  ufw delete allow 80/tcp
  ufw allow from <IP-cua-ban> to any port 80 proto tcp
  ```
- Dù sao cũng **đổi mật khẩu admin mặc định** và không để tài khoản thừa.

CSDL đã chỉ lắng nghe `localhost` (mặc định Ubuntu), không mở ra ngoài; đó là lý do không cần đổi mật khẩu `ids_app`. Nếu sau này mở PostgreSQL ra LAN, đổi mật khẩu theo `backend/HUONG_DAN_KET_NOI_SQL.md` mục 7.

## 7. Cập nhật khi sửa code

```bash
cd /opt/aahkl
git pull
# Backend/pipeline:
sudo -u ids ./backend/.venv/bin/python -m pip install -r backend/requirements.txt   # nếu đổi thư viện
sudo systemctl restart ids-api ids-pipeline
# Frontend (nếu sửa giao diện):
cd frontend && npm ci && npm run build && rm -rf /var/www/ids/* && cp -r dist/* /var/www/ids/
```

## 8. Lỗi thường gặp

| Triệu chứng | Cách xử lý |
|---|---|
| `ids-api` không chạy, log báo lỗi kết nối CSDL | Kiểm tra `systemctl status postgresql`; thử `sudo -u postgres psql -c '\l'` xem có database `ids` |
| `ids-api` báo lỗi nạp mô hình | Thiếu `Model Train/RF/models/rf_F_NOOS.joblib` (clone thiếu) hoặc sai phiên bản thư viện; cài lại `requirements.txt` trong `.venv` |
| Dashboard trắng trang | `nginx -t`; kiểm tra `/var/www/ids/index.html` tồn tại; xem `/var/log/nginx/error.log` |
| Gọi `/api` trả 502 | `ids-api` chưa chạy; xem `journalctl -u ids-api -n 50` |
| `npm run build` lỗi thiếu RAM | VPS nhỏ: thêm swap `fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile` rồi build lại |

## 9. Gỡ bỏ

```bash
systemctl disable --now ids-api ids-pipeline
rm -f /etc/systemd/system/ids-*.service /etc/nginx/sites-enabled/ids /etc/nginx/sites-available/ids
systemctl daemon-reload && systemctl reload nginx
# CSDL và mã nguồn giữ lại; xoá thủ công nếu cần.
```
