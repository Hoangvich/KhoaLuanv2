# Kế hoạch kiểm thử hệ thống IDS AAHKL (bản triển khai trên VPS)

Tài liệu mô tả cách kiểm thử end-to-end hệ thống đã triển khai trên VPS Ubuntu (`http://103.65.234.246/`), làm bằng chứng cho **Chương 5** của khoá luận. Số liệu và các bước ở đây lấy từ mã nguồn thật (`backend/`), không bịa.

## 1. Mục tiêu và phạm vi

Chứng minh hệ thống đã triển khai đáp ứng 8 yêu cầu chức năng CN1–CN8 (Bảng 4.2) và phát hiện đúng 3 nhóm tấn công bằng **hệ lai mô hình Random Forest + tầng luật theo nguồn**:

- Phát hiện **PortScan** và **BruteForce** bằng tầng luật, **DoS/DDoS** bằng mô hình.
- Gom nhiều luồng tấn công thành ít cảnh báo (CN4).
- Pipeline chạy liên tục 5 s, cấu hình đổi lúc chạy, phân quyền, thông báo.

Đây là kiểm thử **chức năng** (functional), xác nhận hệ thống chạy đúng trên lưu lượng sinh ra có kiểm soát; **không** phải đo thống kê FPR/DR trên môi trường độc lập (phần đó đã làm ở Kịch bản C, mục 3.9).

## 2. Ranh giới an toàn (bắt buộc tuân thủ)

> Mọi lưu lượng tấn công chỉ chạy trong môi trường **do nhóm kiểm soát và cô lập**. Cụ thể:
> - **Không** tấn công máy/dịch vụ của bên thứ ba, website thật, hay mục tiêu ngoài phạm vi.
> - **Không** bắn tấn công qua Internet mở vào IP public `103.65.234.246` (vi phạm điều khoản nhà cung cấp VPS, dễ bị khoá máy). Khi cần máy ở xa đóng vai kẻ tấn công thì đi qua **mạng riêng ảo (Tailscale/WireGuard)** và nhắm **IP riêng 100.x**.
> - **Không** chạy flood thể tích lớn. DoS/DDoS kiểm thử bằng **phát lại pcap mẫu** (mô hình phát hiện tốt loại phản xạ UDP), không tạo flood thật.
> - Dò mật khẩu dùng **tài khoản giả** (`testuser_khongcothat`) để không khoá nhầm tài khoản thật.

## 3. Môi trường kiểm thử

| Thành phần | Vị trí | Vai trò |
|---|---|---|
| Hệ thống IDS (API + pipeline + PostgreSQL + dashboard) | VPS Ubuntu 103.65.234.246 | Đối tượng kiểm thử |
| Máy tấn công từ xa | Máy của thành viên khác | Sinh lưu lượng PortScan / BruteForce |
| Mạng riêng Tailscale | Nối VPS ↔ máy tấn công | Giữ lưu lượng trong đường hầm, không ra Internet mở |
| Sensor bắt gói | `tcpdump` trên VPS (`tailscale0`/`lo`) | Ghi pcap → `replay_pcap` nạp vào `data/incoming` |
| Database kiểm thử | `ids_test` trên VPS | Chạy 11 bài test tự động (`pytest`) |

## 4. Chuẩn bị

### 4.1. Công cụ trên VPS
```bash
apt-get install -y nmap hydra tcpdump
```

### 4.2. Mạng riêng (cho ca kiểm thử có máy tấn công ở xa)
Trên VPS:
```bash
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up            # mở link in ra, đăng nhập
tailscale ip -4         # ghi lại IP 100.x  ==> IP-VPS-RIENG
```
Máy tấn công (thành viên khác): cài app Tailscale (https://tailscale.com/download), đăng nhập **cùng tailnet**, cài `nmap` và `hydra`. Kiểm tra: `ping <IP-VPS-RIENG>`.

### 4.3. Môi trường test tự động
```bash
cd /opt/aahkl/backend
./.venv/bin/python -m pip install -r requirements-dev.txt   # thêm pytest, scapy
```

## 5. Danh sách ca kiểm thử

| Mã | Yêu cầu | Cách thực hiện | Kết quả mong đợi | Bằng chứng |
|---|---|---|---|---|
| TC1 | CN3 – PortScan | `nmap` quét cổng máy nạn nhân | Cảnh báo **Quét cổng**, mức Trung bình, "Phát hiện bởi: Luật", chi tiết "… cổng / 10 s" | Ảnh Chi tiết cảnh báo |
| TC2 | CN3 – BruteForce | `hydra` dò SSH (user giả) | Cảnh báo **Dò mật khẩu**, mức Cao, "Phát hiện bởi: Luật", "… phiên tới cổng 22 / 60 s" | Ảnh Chi tiết cảnh báo |
| TC3 | CN3 – DoS/DDoS | `replay_pcap ddos.pcap` | Cảnh báo **DoS/DDoS**, mức Cao, "Phát hiện bởi: Mô hình" | Ảnh Chi tiết cảnh báo |
| TC4 | FPR – lành tính | `replay_pcap benign.pcap` | Không (hoặc rất ít) cảnh báo; luồng gán **Bình thường** | Ảnh Tổng quan / truy vấn |
| TC5 | CN4 – gom cụm | Một đợt PortScan ~65k luồng | Số cảnh báo PortScan **rất ít** (≈1–3) dù hàng chục nghìn luồng | Truy vấn `alerts` |
| TC6 | CN1 – pipeline liên tục | Xem ô "Pipeline 10 phút" | Số chu kỳ ≈ 120/120, không bỏ chu kỳ, có `ms` mỗi chu kỳ | Ảnh Tổng quan + bảng `pipeline_runs` |
| TC7 | CN2 – không mất/trùng dòng | `pytest tests/test_pipeline_api.py` | `test_incremental_append`, `test_pipeline_creates_one_alert_per_attack` PASS | Log pytest |
| TC8 | CN6 – thông báo | Cấu hình Telegram ở Quản trị, gửi thử | Nhận tin; bảng `notifications` có `latency_ms` | Ảnh Telegram + truy vấn |
| TC9 | CN7 – đổi ngưỡng lúc chạy | Quản trị → đổi τ → lưu | Chu kỳ kế tiếp dùng τ mới (cột `tau` ở `pipeline_runs`) | Ảnh + truy vấn |
| TC10 | CN8 – phân quyền | Tạo user `viewer`, thử vào trang Quản trị | `viewer` bị chặn (403) trang Quản trị; admin vào được | Ảnh 2 vai trò |
| TC11 | Toàn bộ CN | `pytest tests -q` | 11/11 test PASS | Log pytest |

## 6. Kịch bản live: thành viên ở xa đóng vai kẻ tấn công

Thực hiện sau khi xong mục 4.2. Ba loại chạy nối tiếp, cách nhau vài giây.

**Bước 1 — VPS bật sensor (bắt gói trên cổng Tailscale, 120 giây):**
```bash
timeout 120 tcpdump -i tailscale0 -w /tmp/attack_live.pcap -U &
```

**Bước 2 — Máy tấn công (thay `<IP-VPS-RIENG>`):**
```bash
# TC1 PortScan
nmap -p 1-1000 <IP-VPS-RIENG>
# TC2 BruteForce (tạo wordlist nhỏ trước: seq 1 40 | sed 's/^/pw/' > pw.txt)
hydra -l testuser_khongcothat -P pw.txt -t 4 ssh://<IP-VPS-RIENG>
```

**Bước 3 — VPS nạp pcap vừa bắt vào pipeline:**
```bash
cd /opt/aahkl/backend
PYTHONUTF8=1 ./.venv/bin/python -m tools.replay_pcap /tmp/attack_live.pcap --instant
```

**Bước 4 — TC3 DoS/DDoS (phát lại pcap mẫu, không flood):**
```bash
PYTHONUTF8=1 ./.venv/bin/python -m tools.replay_pcap ddos.pcap --instant
```

**Bước 5 — Kiểm chứng trên dashboard:** trang **Cảnh báo** có 3 cảnh báo; mở từng cái xem nhãn, mức độ, "Phát hiện bởi", chi tiết luật. IP nguồn của PortScan/BruteForce là **IP Tailscale của máy tấn công** (100.x).

> Phương án thay thế không cần VPN: thành viên đó chạy `nmap`/`hydra` trong lab riêng của họ, `tcpdump` bắt lại thành `.pcap`, gửi file cho nhóm, rồi nạp bằng `replay_pcap <file>.pcap --instant`.

## 7. Kiểm thử tự động (chạy trên VPS)
```bash
cd /opt/aahkl/backend
PYTHONUTF8=1 ./.venv/bin/python -m pytest tests -q
```
11 bài: 6 bài `test_engine.py` (khớp kết quả Kịch bản C, quy ước cờ TCP, luật trải nhiều lô) + 5 bài `test_pipeline_api.py` (gom cụm 1 cảnh báo/đợt, đọc nối tiếp không trùng, luồng API, phân quyền, kiểm tra cấu hình). Lưu toàn bộ output làm phụ lục.

## 8. Thu thập bằng chứng cho Chương 5

Dùng các truy vấn SQL (mở bằng DBeaver hoặc `psql`, xem `backend/HUONG_DAN_KET_NOI_SQL.md`):

```sql
-- CN1: pipeline không bỏ chu kỳ, thời gian xử lý
SELECT id, started_at, rows_in, rows_attack, alerts_new, round(ms::numeric,1) ms, error
FROM pipeline_runs ORDER BY id DESC LIMIT 20;

-- CN3/CN4: mỗi đợt tấn công gom thành bao nhiêu cảnh báo
SELECT label, severity, source, src_ip, dst_ip, dst_port, flow_count, src_count, status
FROM alerts ORDER BY last_seen DESC;

-- Độ trễ phát hiện (từ luồng đầu tới lúc tạo cảnh báo)
SELECT id, label, (extract(epoch FROM created_at - first_seen))::int AS tre_phat_hien_giay
FROM alerts ORDER BY id DESC LIMIT 20;

-- CN6: độ trễ thông báo
SELECT alert_id, channel, status, latency_ms FROM notifications ORDER BY id DESC;
```

Ảnh màn hình cần chụp (điền Hình 4.6–4.10 đang trống):
- Đăng nhập, Tổng quan, Danh sách cảnh báo, Chi tiết một cảnh báo (thấy "Phát hiện bởi"), Quản trị (4 tab).

## 9. Tiêu chí đạt

| Nhóm | Đạt khi |
|---|---|
| Phát hiện (TC1–TC3) | Mỗi loại tấn công sinh đúng 1 cảnh báo đúng nhãn, đúng nguồn phát hiện (luật/mô hình) |
| Báo động giả (TC4) | Lưu lượng benign không sinh cảnh báo tấn công (hoặc ở mức rất thấp) |
| Gom cụm (TC5) | Số cảnh báo ≪ số luồng tấn công |
| Vận hành (TC6, TC9) | Pipeline chạy liên tục, đổi τ có hiệu lực ở chu kỳ kế tiếp |
| Thông báo (TC8) | Nhận được tin, có ghi `latency_ms` |
| Phân quyền (TC10) | `viewer` bị chặn trang/endpoint admin (403) |
| Tự động (TC7, TC11) | 11/11 bài pytest PASS |

## 10. Giới hạn của phép kiểm thử này

- Lưu lượng tấn công do nhóm sinh có kiểm soát, qua pcap/tunnel riêng; chưa phải lưu lượng hỗn hợp dài hạn của mạng doanh nghiệp thật.
- DoS/DDoS kiểm thử bằng pcap phản xạ UDP; chưa kiểm chứng TCP SYN Flood thật (đã nêu ở mục 3.11.3).
- Ngưỡng BruteForce kiểm thử với công cụ tự động (hydra), chưa đo với hành vi đăng nhập nhầm của người dùng thật.
