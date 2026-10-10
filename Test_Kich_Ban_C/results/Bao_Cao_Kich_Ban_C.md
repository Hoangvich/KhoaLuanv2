# BÁO CÁO TOÀN DIỆN THỰC NGHIỆM KỊCH BẢN C (DỮ LIỆU LAB) VÀ QUYẾT ĐỊNH CHỐT MÔ HÌNH TRIỂN KHAI

> **Đề tài khóa luận:** Nghiên cứu ứng dụng học máy trong giám sát và phát hiện bất thường trên hệ thống mạng doanh nghiệp  
> **Thời gian thực hiện:** Tháng 10/2026  
> **Bộ đặc trưng đánh giá:** `F_NOOS` (56 đặc trưng triển khai — loại trừ dấu vết hệ điều hành)  
> **Môi trường thử nghiệm:** Lab mô phỏng 3 VLAN, firewall pfSense, máy chủ dịch vụ Web/SSH và các công cụ tấn công hping3 / nmap / hydra  

---

## 1. Bối cảnh Kịch bản C & Mục tiêu thực nghiệm

Theo đề cương và báo cáo khóa luận (Mục 2.5.3 và Mục 3.8.5):
* **Kịch bản A (Cùng phân phối):** Đánh giá trên fold 0 của tập dữ liệu công khai (CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019) — cả 3 mô hình cây đều đạt Macro-F1 $\approx 0,998 - 0,999$.
* **Kịch bản B (Tổng quát hóa chéo bộ dữ liệu):** Thử nghiệm huấn luyện trên 2 bộ và kiểm thử trên bộ còn lại — bộc lộ sự sụt giảm hiệu năng rõ rệt do độ trôi phân phối (Domain Shift).
* **Kịch bản C (Lưu lượng Lab thực nghiệm):** Kiểm chứng mô hình trên lưu lượng thực tế tự sinh từ mô hình Lab doanh nghiệp, kết hợp **hiệu chỉnh ngưỡng quyết định $\tau^*$** với ràng buộc tỷ lệ báo động giả $FPR(BENIGN) \le 1.0\%$.

### Phân bố dữ liệu Lab thực nghiệm (16.657 luồng mạng):
Dữ liệu được trích xuất trực tiếp từ 4 file PCAP thu thập tại phòng Lab ảo hóa qua pfSense:
1. `benign.pcap` (**669 luồng**): Lưu lượng người dùng bình thường (duyệt Web HTTP/HTTPS, phiên SSH hợp lệ qua các VLAN).
2. `ddos.pcap` (**2.887 luồng**): Tấn công từ chối dịch vụ sinh bởi `hping3` (SYN flood và UDP flood).
3. `portscan.pcap` (**12.500 luồng**): Trinh sát quét cổng sinh bởi `nmap` (TCP SYN scan, Connect scan).
4. `bruteforce.pcap` (**601 luồng**): Tấn công dò mật khẩu SSH sinh bởi `hydra`.

---

## 2. Bảng kết quả so sánh 3 mô hình cây trên Kịch bản C

Tiến hành đánh giá trên 3 mô hình cây đại diện (`LightGBM`, `Random Forest`, `XGBoost`), loại bỏ MLP theo đúng định hướng ở Báo cáo tiến độ 1 (do MLP kém tổng quát hóa trên dữ liệu bảng):

| Mô hình | AUC (Lab) | Ngưỡng gốc $\tau$ | Detection gốc (%) | Ngưỡng hiệu chỉnh $\tau^*$ | FPR (Benign) (%) | Tỉ lệ phát hiện sau hiệu chỉnh (%) | Macro-F1 (Lab) | Recall BENIGN (%) | Recall DDoS (%) | Recall PortScan (%) | Recall BruteForce (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **LightGBM** | **0.9368** | 0.50 | 9.25% | **0.0011** | **0.90%** | **17.33%** | 0.2653 | **99.10%** | **95.15%** | 0.00% | 0.00% |
| **Random Forest** | 0.7733 | 0.36 | 17.14% | 0.4000 | **0.90%** | 16.98% | 0.2644 | **99.10%** | 93.87% | 0.00% | 0.00% |
| **XGBoost** | **0.9860** | 0.64 | 5.67% | **0.0001** | **0.90%** | **60.01%** | **0.5281** | **99.10%** | **95.88%** | **38.46%** | **46.76%** |

---

## 3. Ma trận nhầm lẫn chi tiết (Sau hiệu chỉnh ngưỡng)

### 3.1. LightGBM ($\tau^* = 0.0011$)
| Thực tế \ Dự đoán | Dự đoán BENIGN | Dự đoán DoS/DDoS | Dự đoán PortScan | Dự đoán BruteForce |
| :--- | :---: | :---: | :---: | :---: |
| **Thực tế BENIGN (669)** | **663** | 6 | 0 | 0 |
| **Thực tế DoS/DDoS (2.887)** | 140 | **2.747** | 0 | 0 |
| **Thực tế PortScan (12.500)** | 12.493 | 7 | 0 | 0 |
| **Thực tế BruteForce (601)** | 585 | 16 | 0 | 0 |

### 3.2. Random Forest ($\tau^* = 0.4000$)
| Thực tế \ Dự đoán | Dự đoán BENIGN | Dự đoán DoS/DDoS | Dự đoán PortScan | Dự đoán BruteForce |
| :--- | :---: | :---: | :---: | :---: |
| **Thực tế BENIGN (669)** | **663** | 6 | 0 | 0 |
| **Thực tế DoS/DDoS (2.887)** | 177 | **2.710** | 0 | 0 |
| **Thực tế PortScan (12.500)** | 12.500 | 0 | 0 | 0 |
| **Thực tế BruteForce (601)** | 597 | 4 | 0 | 0 |

### 3.3. XGBoost ($\tau^* = 0.0001$)
| Thực tế \ Dự đoán | Dự đoán BENIGN | Dự đoán DoS/DDoS | Dự đoán PortScan | Dự đoán BruteForce |
| :--- | :---: | :---: | :---: | :---: |
| **Thực tế BENIGN (669)** | **663** | 6 | 0 | 0 |
| **Thực tế DoS/DDoS (2.887)** | 119 | **2.768** | 0 | 0 |
| **Thực tế PortScan (12.500)** | 5.976 | 1.717 | **4.807** | 0 |
| **Thực tế BruteForce (601)** | 298 | 22 | 0 | **281** |

---

## 4. Kiểm chứng quy tắc chốt mô hình triển khai (Theo Mục 3.8.5 Báo cáo Khóa luận)

Mục 3.8.5 trong Báo cáo Khóa luận (và Slide 18) quy định rõ:
> *"Sau khi hiệu chỉnh ngưỡng của từng mô hình trên lưu lượng lab với ràng buộc tỉ lệ báo động giả không quá 1%, nếu **RF có AUC cao hơn LightGBM quá 0,02** hoặc có **tỉ lệ phát hiện cao hơn quá 2 điểm phần trăm**, đề tài chuyển mô hình triển khai sang RF; **ngược lại giữ LightGBM**."*

### Đối chiếu định lượng trên dữ liệu Lab thực tế:
1. **Tiêu chí 1 — Khả năng phân tách (AUC Attack vs Benign):**
   * $\text{AUC}(\text{Random Forest}) = 0.7733$
   * $\text{AUC}(\text{LightGBM}) = 0.9368$
   * $\Delta \text{AUC} = 0.7733 - 0.9368 = \mathbf{-0.1635} \le 0.02$ ➔ **KHÔNG ĐẠT** (LightGBM vượt trội RF đến $0.1635$).
2. **Tiêu chí 2 — Tỉ lệ phát hiện tấn công tổng thể (Detection Rate):**
   * $\text{DR}(\text{Random Forest}) = 16.98\%$
   * $\text{DR}(\text{LightGBM}) = 17.33\%$
   * $\Delta \text{DR} = 16.98\% - 17.33\% = \mathbf{-0.35\%} \le 2.0\%$ ➔ **KHÔNG ĐẠT** (Random Forest không vượt qua LightGBM).

---

## 5. Quyết định chốt mô hình & Kết luận học thuật

### 🎯 QUYẾT ĐỊNH CHÍNH THỨC: CHỐT LIGHTGBM (`lgbm_F_NOOS.joblib`)
1. **Lý do khoa học:** Random Forest không thỏa mãn bất kỳ điều kiện vượt trội nào tại Mục 3.8.5. LightGBM bảo toàn vị trí dẫn đầu cả về mặt lý thuyết lẫn thực nghiệm Lab.
2. **Hiệu năng phát hiện DDoS thực tế:** Đạt Recall **95.15%** trên các đợt tấn công từ chối dịch vụ trong lab, đồng thời kiểm soát tỷ lệ báo động giả trên lưu lượng bình thường ở mức an toàn **0.90%** (đạt chỉ tiêu đề ra $\le 1.0\%$).
3. **Ưu thế tuyệt đối khi vận hành thực tế:**
   * Kích thước mô hình cực kỳ nhỏ gọn: **0.76 MB** (so với 4.3 MB của RF).
   * Tốc độ suy luận lô: **1.56 ms / 1.000 luồng** (so với 46.8 ms của RF).
   * Cực kỳ tối ưu để nhúng vào **FastAPI Inference Service** và xử lý dòng gói tin theo chu kỳ 5–10 giây từ Sensor mạng mà không gây nghẽn RAM hay trễ hàng đợi.
4. **Phân tích mở rộng về XGBoost:** XGBoost thể hiện năng lực tổng quát hóa ấn tượng trên cả PortScan (38.46%) và BruteForce (46.76%) khi hạ ngưỡng. XGBoost được giữ làm **mô hình dự phòng nâng cao** (Secondary Candidate) cho giai đoạn tiếp theo.
