# BÁO CÁO KỊCH BẢN C — KIỂM THỬ TRÊN PCAP NGOÀI TẬP HUẤN LUYỆN

> Sinh tự động bởi `test_lab_3_models.py` lúc 2026-10-13 13:27:24 (scikit-learn 1.9.1). Bộ đặc trưng `F_NOOS` (56 cột).

## 1. Dữ liệu

Nhóm không có pcap thu riêng trong lab; cả 4 file là pcap mẫu. Kết quả là kiểm thử trên lưu lượng ngoài tập huấn luyện, không phải lưu lượng lab 3 VLAN/pfSense.

| File | Nhãn | Cách gán nhãn | Ghi chú |
|---|---|---|---|
| `benign.pcap` | BENIGN | toàn bộ luồng | chủ yếu DNS và HTTPS, không có SSH |
| `ddos.pcap` | DoS/DDoS | toàn bộ luồng | trùng từng byte `amp.UDP.memcached.ntp.cldap.pcap`: phản xạ UDP, không có SYN flood |
| `portscan.pcap` | PortScan | luồng 192.168.1.149 → 192.168.1.4 | quét SYN 65.535 cổng |
| `bruteforce.pcap` | BruteForce | luồng 192.168.1.149 → 192.168.1.4:22 | hydra dò mật khẩu SSH |

| Nhãn | Số luồng đánh giá | Bị loại (Flow Duration = 0) |
|---|---:|---:|
| BENIGN | 1,880 | 268 |
| DoS/DDoS | 1,724 | 258 |
| PortScan | 65,535 | 0 |
| BruteForce | 480 | 475 |

## 2. Trích xuất đặc trưng khớp CICFlowMeter

`pcap_flow_extractor.py` được đối chiếu với dữ liệu huấn luyện (`Data/data/processed/unified.parquet`):

- Độ dài gói tính cả padding Ethernet (CIC-2017: gói ACK thuần dài 6 byte, gói SYN 58 byte dài 2 byte).
- Header = độ dài header TCP thật (20/24/32/40) hoặc 8 với UDP; chỉ xử lý gói TCP/UDP.
- Active chỉ được ghi khi luồng có khoảng Idle (> 5 s) — đúng ở 100% dòng huấn luyện.
- **Cờ TCP trong dữ liệu huấn luyện là nhị phân và bị ghi lệch cột**: `SYN Flag Count` trùng 100% với `Fwd PSH Flags`, `RST Flag Count` trùng 100% với `ECE Flag Count`. Quy tắc suy ra (khớp 10 kiểu luồng phổ biến nhất của CIC-2017): PSH = gói đi đầu tiên có SYN; ACK = gói đi đầu tiên có ACK; FIN = gói đi đầu tiên có FIN; SYN = gói đi đầu tiên có PSH; URG = gói về đầu tiên chỉ có ACK; RST = 0.

## 3. Phương pháp

Lặp 200 lần chia đôi theo tầng nhãn. Nửa hiệu chỉnh chọn τ* nhỏ nhất thỏa FPR(BENIGN) ≤ 1%; nửa đánh giá đo AUC (tấn công vs BENIGN), tỉ lệ phát hiện (DR), FPR và phát hiện theo lớp. Số liệu: trung vị [khoảng 95%]. Luật quyết định: tấn công nếu 1 − P(BENIGN) ≥ τ*.

## 4. Kết quả mô hình đơn lẻ (sau hiệu chỉnh ngưỡng)

| Mô hình      | AUC                     |   τ* (trung vị) | FPR (%)           | DR (%)               | DR TB theo lớp (%)   |   DoS/DDoS (%) |   PortScan (%) |   BruteForce (%) |   Dung lượng (MB) |   Dự đoán 1.000 luồng (ms) |
|:-------------|:------------------------|----------------:|:------------------|:---------------------|:---------------------|---------------:|---------------:|-----------------:|------------------:|---------------------------:|
| LightGBM     | 0.9953 [0.9925; 0.9979] |          0.5161 | 0.96 [0.32; 2.13] | 96.27 [92.86; 98.53] | 54.23 [43.19; 63.17] |          53.89 |          98    |            10.83 |              0.76 |                       10.8 |
| RandomForest | 0.9981 [0.9970; 0.9992] |          0.48   | 0.21 [0.00; 1.49] | 99.06 [99.03; 99.09] | 64.25 [63.86; 64.60] |          92.81 |          99.95 |             0    |              4.28 |                       45.9 |
| XGBoost      | 0.9986 [0.9981; 0.9989] |          0.6677 | 0.96 [0.32; 2.24] | 97.61 [97.50; 97.95] | 56.20 [52.67; 70.31] |          22.27 |          99.97 |            46.88 |              1.31 |                       24.4 |

## 5. Hệ lai: mô hình + tầng luật theo nguồn

`ids_rules.py` gom luồng theo IP nguồn trong cửa sổ thời gian. Luật chỉ bổ sung cảnh báo cho luồng mà mô hình cho là BENIGN:

- **BruteForce:** ≥ M phiên TCP mới từ một nguồn tới cùng một cổng đăng nhập (21, 22, 23, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900) của cùng một đích trong 60 s (sàn 10).
- **PortScan (dự phòng):** ≥ N cổng khác nhau của cùng một đích trong 10 s (sàn 20).
- N, M = giá trị lớn nhất trên BENIGN của nửa hiệu chỉnh + 1, không thấp hơn mức sàn. Trung vị: N = 20, M = 10. τ* hiệu chỉnh lại để FPR tổng ≤ 1%.
- Chi phí: 1354 ms cho 70,620 luồng (Python thuần).

Giá trị lớn nhất của hai thống kê theo nhãn:

| Label      |   Số cổng / 10 s |   Số phiên / 60 s |
|:-----------|-----------------:|------------------:|
| BENIGN     |                8 |                 0 |
| DoS/DDoS   |                1 |                 0 |
| PortScan   |            65535 |                 1 |
| BruteForce |                1 |                20 |

| Hệ                  |   τ* (trung vị) | FPR (%)           | DR (%)               | DR TB theo lớp (%)   |   DoS/DDoS (%) |   PortScan (%) |   BruteForce (%) |
|:--------------------|----------------:|:------------------|:---------------------|:---------------------|---------------:|---------------:|-----------------:|
| LightGBM + luật     |          0.5161 | 0.96 [0.32; 2.13] | 98.80 [98.29; 99.09] | 83.80 [76.79; 87.59] |          53.89 |            100 |            97.5  |
| RandomForest + luật |          0.48   | 0.21 [0.00; 1.49] | 99.80 [99.77; 99.83] | 96.77 [96.16; 97.32] |          92.81 |            100 |            97.5  |
| XGBoost + luật      |          0.6677 | 0.96 [0.32; 2.24] | 98.01 [97.95; 98.07] | 73.43 [72.48; 74.52] |          22.27 |            100 |            98.12 |

Ma trận nhầm lẫn (lần chia đầu tiên, nửa đánh giá):

**LightGBM**

|                    |   Dự_đoán_BENIGN |   Dự_đoán_DoS/DDoS |   Dự_đoán_PortScan |   Dự_đoán_BruteForce |
|:-------------------|-----------------:|-------------------:|-------------------:|---------------------:|
| Thực_tế_BENIGN     |              931 |                  9 |                  0 |                    0 |
| Thực_tế_DoS/DDoS   |              397 |                465 |                  0 |                    0 |
| Thực_tế_PortScan   |              680 |                  0 |              32088 |                    0 |
| Thực_tế_BruteForce |              216 |                  0 |                  0 |                   24 |

**LightGBM + luật**

|                    |   Dự_đoán_BENIGN |   Dự_đoán_DoS/DDoS |   Dự_đoán_PortScan |   Dự_đoán_BruteForce |
|:-------------------|-----------------:|-------------------:|-------------------:|---------------------:|
| Thực_tế_BENIGN     |              931 |                  9 |                  0 |                    0 |
| Thực_tế_DoS/DDoS   |              397 |                465 |                  0 |                    0 |
| Thực_tế_PortScan   |                1 |                  0 |              32767 |                    0 |
| Thực_tế_BruteForce |                4 |                  0 |                  0 |                  236 |

**RandomForest**

|                    |   Dự_đoán_BENIGN |   Dự_đoán_DoS/DDoS |   Dự_đoán_PortScan |   Dự_đoán_BruteForce |
|:-------------------|-----------------:|-------------------:|-------------------:|---------------------:|
| Thực_tế_BENIGN     |              929 |                  0 |                 11 |                    0 |
| Thực_tế_DoS/DDoS   |               61 |                801 |                  0 |                    0 |
| Thực_tế_PortScan   |               16 |                  0 |              32752 |                    0 |
| Thực_tế_BruteForce |              240 |                  0 |                  0 |                    0 |

**RandomForest + luật**

|                    |   Dự_đoán_BENIGN |   Dự_đoán_DoS/DDoS |   Dự_đoán_PortScan |   Dự_đoán_BruteForce |
|:-------------------|-----------------:|-------------------:|-------------------:|---------------------:|
| Thực_tế_BENIGN     |              929 |                  0 |                 11 |                    0 |
| Thực_tế_DoS/DDoS   |               61 |                801 |                  0 |                    0 |
| Thực_tế_PortScan   |                1 |                  0 |              32767 |                    0 |
| Thực_tế_BruteForce |                4 |                  0 |                  0 |                  236 |

**XGBoost**

|                    |   Dự_đoán_BENIGN |   Dự_đoán_DoS/DDoS |   Dự_đoán_PortScan |   Dự_đoán_BruteForce |
|:-------------------|-----------------:|-------------------:|-------------------:|---------------------:|
| Thực_tế_BENIGN     |              933 |                  6 |                  0 |                    1 |
| Thực_tế_DoS/DDoS   |              664 |                198 |                  0 |                    0 |
| Thực_tế_PortScan   |               10 |                  0 |              32758 |                    0 |
| Thực_tế_BruteForce |              145 |                  0 |                  0 |                   95 |

**XGBoost + luật**

|                    |   Dự_đoán_BENIGN |   Dự_đoán_DoS/DDoS |   Dự_đoán_PortScan |   Dự_đoán_BruteForce |
|:-------------------|-----------------:|-------------------:|-------------------:|---------------------:|
| Thực_tế_BENIGN     |              933 |                  6 |                  0 |                    1 |
| Thực_tế_DoS/DDoS   |              664 |                198 |                  0 |                    0 |
| Thực_tế_PortScan   |                1 |                  0 |              32767 |                    0 |
| Thực_tế_BruteForce |                4 |                  0 |                  0 |                  236 |

## 6. Độ nhạy: nếu đếm cờ TCP đúng thay vì theo quy ước của dữ liệu huấn luyện

| Mô hình (cờ đếm đúng)   | AUC                     |   τ* (trung vị) | FPR (%)           | DR (%)            | DR TB theo lớp (%)   |   DoS/DDoS (%) |   PortScan (%) |   BruteForce (%) |
|:------------------------|:------------------------|----------------:|:------------------|:------------------|:---------------------|---------------:|---------------:|-----------------:|
| LightGBM                | 0.9051 [0.8944; 0.9173] |          0.5161 | 0.96 [0.32; 2.34] | 1.39 [0.86; 1.83] | 18.88 [11.39; 29.56] |          53.89 |              0 |             3.33 |
| RandomForest            | 0.6187 [0.5986; 0.6412] |          0.485  | 0.21 [0.00; 1.70] | 2.36 [2.33; 2.39] | 30.94 [30.51; 31.29] |          92.81 |              0 |             0    |
| XGBoost                 | 0.9292 [0.9195; 0.9394] |          0.6609 | 0.96 [0.21; 2.13] | 1.06 [0.84; 1.27] | 30.48 [21.08; 39.60] |          22.39 |              0 |            69.58 |

## 7. Tham chiếu: không hiệu chỉnh ngưỡng (toàn bộ dữ liệu)

| Mô hình      | Luật         |    AUC |   DR (%) |   FPR (%) |   DoS/DDoS (%) |   PortScan (%) |   BruteForce (%) |
|:-------------|:-------------|-------:|---------:|----------:|---------------:|---------------:|-----------------:|
| LightGBM     | argmax       | 0.9953 |    96.25 |      1.01 |          53.71 |          97.98 |            13.12 |
| LightGBM     | τ gốc = 0.50 | 0.9953 |    96.25 |      1.01 |          53.71 |          97.98 |            13.12 |
| RandomForest | argmax       | 0.9981 |    99.04 |      0.11 |          92.58 |          99.93 |             0    |
| RandomForest | τ gốc = 0.36 | 0.9981 |    99.12 |      3.46 |          94.03 |          99.98 |             0    |
| XGBoost      | argmax       | 0.9985 |    97.88 |      1.38 |          23.26 |          99.98 |            80.42 |
| XGBoost      | τ gốc = 0.64 | 0.9985 |    97.65 |      1.12 |          22.22 |          99.97 |            51.67 |

## 8. Quy tắc chốt mô hình (mục 3.8.5)

> Sau khi hiệu chỉnh ngưỡng với FPR ≤ 1%, nếu RF có AUC cao hơn LightGBM quá 0,02 hoặc tỉ lệ phát hiện cao hơn quá 2 điểm %, chuyển sang RF; ngược lại giữ LightGBM.

- ΔAUC (RF − LightGBM) = +0.0030 [-0.0007; +0.0056]
- ΔDR (RF − LightGBM) = +2.80 [+0.54; +6.17] điểm %
- RF thỏa điều kiện chuyển ở 60.0% số lần chia.
- Tham khảo (ngoài quy tắc): ΔDR trung bình theo lớp = +10.19 [+1.12; +21.03] điểm % (PortScan chiếm 97% số luồng tấn công); ΔDR của hệ lai = +0.99 [+0.70; +1.50] điểm %.

**Kết quả theo quy tắc: chuyển sang Random Forest.**

## 9. Giới hạn

- Không phải dữ liệu lab; `ddos.pcap` là mẫu công khai, không có SYN flood như mục 3.8.5 yêu cầu.
- Quy tắc cờ TCP được suy ra từ dữ liệu huấn luyện (chủ yếu CIC-2017), chưa đối chiếu với mã nguồn CICFlowMeter; backend phải dùng đúng phiên bản CICFlowMeter tạo ra quy ước này.
- `benign.pcap` không có SSH nên ngưỡng BruteForce chưa được kiểm tra báo động giả trên người dùng SSH thật; dò mật khẩu chậm hoặc phân tán qua nhiều IP sẽ lọt dưới ngưỡng.
- τ* hiệu chỉnh trên khoảng một nửa số luồng BENIGN nên FPR ngoài mẫu dao động quanh 1%.
- Mô hình huấn luyện bằng scikit-learn 1.6.1, chạy kiểm thử bằng 1.9.1.
