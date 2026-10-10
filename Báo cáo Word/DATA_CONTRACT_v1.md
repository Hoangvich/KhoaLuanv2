# 📋 DATA CONTRACT v1.0 — Chốt Ngày 2
> **Khóa luận:** Nghiên cứu ứng dụng học máy trong giám sát và phát hiện bất thường trên hệ thống mạng doanh nghiệp  
> **Tác giả đề xuất:** Nguyễn Huy Hoàng | **Người duyệt chốt:** Đoàn Lê Đức Anh (chủ pipeline)  
> **Ngày chốt tối đa:** Ngày 2 của sprint

> [!IMPORTANT]
> Đây là "hợp đồng kỹ thuật" ràng buộc cả 5 người. Sau khi cả nhóm duyệt và ghi tên bên dưới, **không ai được tự ý thay đổi schema mà không họp chốt lại**. Ai nộp file sai schema sẽ không ghép được vào pipeline chung.

---

## 1. ĐỊNH DẠNG FILE ĐẦU RA CHUẨN

| Thuộc tính | Quy định |
| :--- | :--- |
| **Định dạng** | Apache Parquet (`.parquet`) |
| **Kiểu số** | `float32` (bắt buộc — tiết kiệm 50% RAM cho CSE-CIC-IDS2018) |
| **Cột nhãn** | `label` — kiểu `str` |
| **Tên file chuẩn** | `cicids2017_cleaned.parquet` / `cic_ids2018_cleaned.parquet` / `lab_traffic_cleaned.parquet` |

---

## 2. BẢNG ÁNH XẠ NHÃN THỐNG NHẤT (Label Mapping)

> [!IMPORTANT]
> **4 nhãn hợp lệ duy nhất:** `BENIGN` · `DDoS` · `PortScan` · `BruteForce`  
> Tất cả nhãn khác phải **DROP rows**, không được ánh xạ sang nhãn khác.

### 2a. CICIDS2017

| Nhãn gốc | → Nhãn chuẩn | Ghi chú |
| :--- | :---: | :--- |
| `BENIGN` | `BENIGN` | |
| `DDoS` | `DDoS` | |
| `DoS Hulk` | `DDoS` | |
| `DoS GoldenEye` | `DDoS` | |
| `DoS slowloris` | `DDoS` | |
| `DoS Slowhttptest` | `DDoS` | |
| `PortScan` | `PortScan` | |
| `FTP-Patator` | `BruteForce` | Vét cạn FTP |
| `SSH-Patator` | `BruteForce` | Vét cạn SSH |
| `Web Attack – Brute Force` | **DROP ⛔** | Ngoài phạm vi |
| `Web Attack – XSS` | **DROP ⛔** | Ngoài phạm vi |
| `Web Attack – Sql Injection` | **DROP ⛔** | Ngoài phạm vi |
| `Bot` | **DROP ⛔** | Ngoài phạm vi |
| `Infiltration` | **DROP ⛔** | Ngoài phạm vi |
| `Heartbleed` | **DROP ⛔** | Quá ít mẫu |

### 2b. CSE-CIC-IDS2018

| Nhãn gốc | → Nhãn chuẩn | Ghi chú |
| :--- | :---: | :--- |
| `Benign` | `BENIGN` | Chú ý: viết hoa khác 2017 |
| `DDOS attack-HOIC` | `DDoS` | |
| `DDOS attack-LOIC-UDP` | `DDoS` | |
| `DDoS attacks-LOIC-HTTP` | `DDoS` | |
| `DoS attacks-GoldenEye` | `DDoS` | |
| `DoS attacks-Hulk` | `DDoS` | |
| `DoS attacks-SlowHTTPTest` | `DDoS` | |
| `DoS attacks-Slowloris` | `DDoS` | |
| `FTP-BruteForce` | `BruteForce` | |
| `SSH-Bruteforce` | `BruteForce` | |
| `Brute Force -Web` | **DROP ⛔** | |
| `Brute Force -XSS` | **DROP ⛔** | |
| `SQL Injection` | **DROP ⛔** | |
| `Infilteration` | **DROP ⛔** | Typo trong dataset gốc |
| `Bot` | **DROP ⛔** | |

### 2c. CIC-DDoS2019

| Nhãn gốc | → Nhãn chuẩn | Ghi chú |
| :--- | :---: | :--- |
| `BENIGN` | `BENIGN` | |
| `DrDoS_DNS` | `DDoS` | Amplification |
| `DrDoS_LDAP` | `DDoS` | |
| `DrDoS_MSSQL` | `DDoS` | |
| `DrDoS_NTP` | `DDoS` | |
| `DrDoS_NetBIOS` | `DDoS` | |
| `DrDoS_SNMP` | `DDoS` | |
| `DrDoS_SSDP` | `DDoS` | |
| `DrDoS_UDP` | `DDoS` | |
| `Syn` | `DDoS` | SYN Flood |
| `WebDDoS` | `DDoS` | |
| `TFTP` | `DDoS` | |
| `UDPLag` | `DDoS` | |

### 2d. Lab Traffic (Khải tự sinh)

| Kịch bản | → Nhãn chuẩn |
| :--- | :---: |
| Truy cập web / SSH hợp lệ | `BENIGN` |
| `hping3` SYN Flood | `DDoS` |
| `nmap` scan (SYN/Connect/Stealth) | `PortScan` |
| `hydra` SSH Brute Force | `BruteForce` |

---

## 3. SCHEMA 60 CỘT ĐẶC TRƯNG (Feature Schema)

> [!WARNING]
> **CỘT BỎ NGAY KHI ĐỌC DỮ LIỆU (Data Leakage):**
> `Flow ID` · `Source IP` · `Destination IP` · `Source Port` · `Timestamp`
>
> **`Destination Port` — NÊN BỎ:** Port 22=SSH→BruteForce, Port 53=DNS→DDoS.
> Giữ lại thì mô hình học số port thay vì học hành vi → thất bại ngoài thực tế.

### Nhóm A — Thời gian & tốc độ luồng (9 cột)

| # | Tên cột | Ý nghĩa với bài toán |
| :---: | :--- | :--- |
| 1 | `Flow Duration` | DDoS: rất ngắn; BruteForce: lặp đều |
| 2 | `Flow Bytes/s` | DDoS: cực cao |
| 3 | `Flow Packets/s` | DDoS SYN Flood: cực cao |
| 4 | `Flow IAT Mean` | PortScan: IAT đồng đều rất nhỏ |
| 5 | `Flow IAT Std` | |
| 6 | `Flow IAT Max` | |
| 7 | `Flow IAT Min` | |
| 8 | `Active Mean` | |
| 9 | `Idle Mean` | |

### Nhóm B — Thống kê Forward / Backward (26 cột)

| # | Tên cột | # | Tên cột |
| :---: | :--- | :---: | :--- |
| 10 | `Total Fwd Packets` | 11 | `Total Backward Packets` |
| 12 | `Total Length of Fwd Packets` | 13 | `Total Length of Bwd Packets` |
| 14 | `Fwd Packet Length Max` | 15 | `Fwd Packet Length Min` |
| 16 | `Fwd Packet Length Mean` | 17 | `Fwd Packet Length Std` |
| 18 | `Bwd Packet Length Max` | 19 | `Bwd Packet Length Min` |
| 20 | `Bwd Packet Length Mean` | 21 | `Bwd Packet Length Std` |
| 22 | `Fwd IAT Total` | 23 | `Fwd IAT Mean` |
| 24 | `Fwd IAT Std` | 25 | `Fwd IAT Max` |
| 26 | `Fwd IAT Min` | 27 | `Bwd IAT Total` |
| 28 | `Bwd IAT Mean` | 29 | `Bwd IAT Std` |
| 30 | `Bwd IAT Max` | 31 | `Bwd IAT Min` |
| 32 | `Fwd Packets/s` | 33 | `Bwd Packets/s` |
| 34 | `Fwd Header Length` | 35 | `Bwd Header Length` |

### Nhóm C — Cờ TCP (8 cột — quan trọng nhất cho DDoS & PortScan)

| # | Tên cột | Ý nghĩa với bài toán |
| :---: | :--- | :--- |
| 36 | `FIN Flag Count` | Port Scan kiểu FIN scan |
| 37 | `SYN Flag Count` | ⭐ **Cực quan trọng** — DDoS SYN Flood: SYN cao, ACK = 0 |
| 38 | `RST Flag Count` | Port Scan: RST cao (cổng đóng phản hồi RST) |
| 39 | `PSH Flag Count` | Phân biệt data transfer với control |
| 40 | `ACK Flag Count` | Tỉ lệ SYN/ACK bất cân xứng → DDoS |
| 41 | `URG Flag Count` | |
| 42 | `CWE Flag Count` | |
| 43 | `ECE Flag Count` | |

### Nhóm D — Kích thước gói tổng hợp (10 cột)

| # | Tên cột | # | Tên cột |
| :---: | :--- | :---: | :--- |
| 44 | `Min Packet Length` | 45 | `Max Packet Length` |
| 46 | `Packet Length Mean` | 47 | `Packet Length Std` |
| 48 | `Packet Length Variance` | 49 | `Average Packet Size` |
| 50 | `Avg Fwd Segment Size` | 51 | `Avg Bwd Segment Size` |
| 52 | `Subflow Fwd Bytes` | 53 | `Subflow Bwd Bytes` |

### Nhóm E — Tham số TCP cấp thấp & giao thức (7 cột)

| # | Tên cột | Ý nghĩa với bài toán |
| :---: | :--- | :--- |
| 54 | `Init_Win_bytes_forward` | BruteForce: window nhỏ cố định, lặp đều |
| 55 | `Init_Win_bytes_backward` | DDoS: server không phản hồi → -1 |
| 56 | `act_data_pkt_fwd` | |
| 57 | `min_seg_size_forward` | |
| 58 | `Subflow Fwd Packets` | |
| 59 | `Subflow Bwd Packets` | |
| 60 | `Protocol` | Port Scan: nhiều protocol; DDoS UDP: protocol=17 |

### Cột nhãn

| # | Cột | Kiểu | Giá trị hợp lệ |
| :---: | :--- | :--- | :--- |
| 61 | `label` | str | `BENIGN` / `DDoS` / `PortScan` / `BruteForce` |

---

## 4. QUY TẮC CHIA TRAIN / TEST

> [!CAUTION]
> **KHÔNG DÙNG `train_test_split()` ngẫu nhiên trên toàn dataset.**
> CICIDS2017 có hàng trăm nghìn luồng trùng lặp gần y hệt → chia ngẫu nhiên → data leakage → F1 ảo ~0.999 → hội đồng nghi ngờ ngay.

```
TRAIN SET (≈75%)
├── CICIDS2017 : Thứ 2 → Thứ 5 (Monday–Thursday)
├── CIC-IDS2018: Ngày 1 → Ngày 7
└── Lab Traffic : Kịch bản DDoS + PortScan

TEST SET (≈25%) — PHONG TỎA, KHÔNG NHÌN KHI TRAIN
├── CICIDS2017 : Thứ 6 (Friday) — ngày có PortScan + DDoS mạnh nhất
├── CIC-IDS2018: Ngày 8 → Ngày 10
└── Lab Traffic : Kịch bản BruteForce (hoàn toàn mới với mô hình)
```

> [!TIP]
> Khi hội đồng hỏi *"Tại sao F1 không phải 0.99?"* — đây là câu trả lời đáng điểm nhất: "Chúng tôi chia dữ liệu theo thời gian, tái hiện đúng kịch bản triển khai thực tế (train trên lịch sử, predict trên tương lai), nên kết quả phản ánh đúng hiệu năng tổng quát hóa."

---

## 5. CHIẾN LƯỢC XỬ LÝ MẤT CÂN BẰNG

> [!WARNING]
> **SMOTE chỉ áp dụng BÊN TRONG từng fold khi Cross-Validation, KHÔNG bao giờ trước khi chia data.**

| Lớp | Chiến lược | Lý do |
| :--- | :--- | :--- |
| `DDoS` (rất nhiều) | **Downsample** xuống ~300k mẫu | Tránh mô hình cực kỳ thiên lệch |
| `PortScan` (trung bình) | Giữ hoặc downsample nhẹ | Đủ mẫu |
| `BENIGN` (nhiều) | **Downsample** cân bằng với DDoS | |
| `BruteForce` (ít nhất) | **SMOTE** oversampling | Cần thêm mẫu tổng hợp |

**Thứ tự pipeline đúng:**
```
Raw CSV
  → Ánh xạ nhãn (bảng 2a/2b/2c/2d) + DROP rows ngoài phạm vi
  → Bỏ cột rò rỉ nhãn (Flow ID, IP, Port, Timestamp)
  → Xử lý NaN / Inf / kiểu dữ liệu → ép float32
  → Xuất Parquet (từng người theo dataset của mình)
          ↓
  [Đức Anh ĐL] Ghép các dataset → Chia Train/Test theo ngày
          ↓
  [CHỈ TRÊN TRAIN] Downsample DDoS/BENIGN → SMOTE BruteForce
          ↓
  [Linh] Fit StandardScaler trên TRAIN → save scaler.joblib
  → Transform cả TRAIN lẫn TEST bằng scaler đã fit
```

---

## 6. FILE OUTPUT BẮT BUỘC CUỐI TUẦN 1 (Ngày 7)

> [!IMPORTANT]
> Nếu cuối ngày 7 chưa có đủ 5 file này, **tuần 2 sẽ không thể bắt đầu**.

| File | Người tạo | Nội dung |
| :--- | :---: | :--- |
| `train.parquet` | Đức Anh (ĐL) | Dataset train đã ghép, cân bằng, đúng 61 cột schema |
| `test.parquet` | Đức Anh (ĐL) | Dataset test giữ riêng, chỉ transform (KHÔNG SMOTE) |
| `scaler.joblib` | Linh | StandardScaler đã `.fit()` trên train |
| `features.json` | Linh | Danh sách 60 tên cột đúng thứ tự |
| `label_encoder.json` | Đức Anh (ĐL) | `{"BENIGN":0, "BruteForce":1, "DDoS":2, "PortScan":3}` |

---

## 7. QUY TẮC GIT CHO NHÓM

- **KHÔNG commit file `.parquet`, `.csv`, `.pcap`, `.joblib`** lên GitHub (lưu Google Drive chung).
- **KHÔNG đụng vào nhánh `main`**.
- Mọi nhánh tính năng đều tạo từ `Demo`:

| Thành viên | Nhánh làm việc |
| :--- | :--- |
| Đoàn Lê Đức Anh | `ducAnh-dl/pipeline-integration` |
| Nguyễn Huy Hoàng | `hoang/cicids2017-eda` |
| Phùng Ngọc Linh | `linh/feature-selection` |
| Nguyễn Văn Khải | `khai/lab-traffic` |
| Trương Nguyễn Đức Anh | `ducAnh-tn/cic-ids2018` |

---

## 8. XÁC NHẬN DUYỆT (Chốt Ngày 2)

| Tên | Vai trò | Đã đọc & đồng ý |
| :--- | :--- | :---: |
| Đoàn Lê Đức Anh | Chủ pipeline | ☐ |
| Nguyễn Huy Hoàng | CICIDS2017 + EDA | ☐ |
| Phùng Ngọc Linh | Feature selection | ☐ |
| Nguyễn Văn Khải | Lab traffic | ☐ |
| Trương Nguyễn Đức Anh | CSE-CIC-IDS2018 | ☐ |
