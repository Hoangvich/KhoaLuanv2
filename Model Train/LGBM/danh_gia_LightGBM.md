# Đánh giá mô hình: LightGBM

> Báo cáo theo **khung chuẩn dùng chung** cho cả 5 mô hình. Các mục đánh số giống hệt báo cáo Random Forest để đặt cạnh nhau so sánh. Ô đánh dấu ⏳ là số liệu cần điền từ file output.

## 0. Thẻ so sánh nhanh

Mọi chỉ số lấy trên **F_NOOS** (bộ đặc trưng triển khai), fold 0, theo ngưỡng triển khai, trừ khi ghi khác.

| Chỉ số | Giá trị |
|---|---:|
| Bảng A: macro-F1 (test) | **0,9989** |
| Bảng A: macro-F1 CV 4 fold (TB ± độ lệch chuẩn) | 0,9988 ± 0,0006 |
| Bảng A: FPR trên BENIGN | 0,010% (42 / 425.682) |
| Bảng A: tỉ lệ phát hiện tấn công | 99,95% |
| Bảng A: F1 lớp yếu nhất | PortScan: 0,9962 |
| Bảng B: phát hiện khi test trên 2017 / 2018 / 2019 | 14,1% / **0%** / 0,04% |
| Bảng B: AUC khi test trên 2017 / 2018 / 2019 | 0,65 / 0,97 / 0,77 |
| Phụ thuộc vân tay HĐH (F_ALL) | Có, vừa phải: hai cột `Init_Win_bytes_*` đứng đầu, mỗi cột ~0,013 |
| Dung lượng bundle | 1,13 MB |
| Dự đoán lô 10.000 flow | 154,5 ms |
| Tổng thời gian chạy (Kaggle CPU) | 40,7 phút |

## 1. Thông tin lần chạy

| Mục | Giá trị |
|---|---|
| run_id | `20260929-041555-lgbm` |
| Dữ liệu | `unified_clean.parquet`, sha256 bắt đầu bằng `0e0a7f922650` (khớp file dữ liệu dùng cho RF); 2.084.979 dòng train (fold 1–4), 521.936 dòng test (fold 0) |
| Giao thức chia | Gộp vector trùng (F_ALL) + 5 fold theo nhóm (hash F_NOOS), phân tầng bộ dữ liệu × lớp, test = fold 0, seed 42 |
| Tinh chỉnh | 12 cấu hình ngẫu nhiên × CV 4 fold trên 299.072 dòng mẫu; chọn theo quy tắc 1 độ lệch chuẩn (độ phức tạp = số vòng × số lá) |
| Tham số được chọn | `num_leaves=31`, `learning_rate=0.1`, `min_child_samples=100`, `subsample=0.7`, `colsample_bytree=0.8`, `reg_lambda=0`, `cw_power=0.5` |
| Early stopping | 10% nhóm (theo `group_id`) của phần huấn luyện, tối đa 3.000 vòng, dừng sau 50 vòng không cải thiện. Mô hình cuối học trên 90% fold 1–4 (RF học trên 100%) |
| Ngưỡng triển khai | F_NOOS: 0,50; F_ALL: 0,48 (chọn trên fold 1, mục tiêu FPR ≤ 1%) |
| Luật quyết định | Tấn công nếu 1 − P(BENIGN) ≥ ngưỡng; lớp = argmax các lớp tấn công |

### 1.1. Bề mặt tinh chỉnh

| Cấu hình | macro-F1 CV | Số vòng | Thời gian |
|---:|---:|---:|---:|
| 1 | 0,9987 ± 0,0002 | 206 | 81 s |
| 2 | 0,9986 ± 0,0001 | 128 | 64 s |
| 3 | 0,9987 ± 0,0002 | 242 | 92 s |
| 4 | 0,9986 ± 0,0001 | 248 | 90 s |
| 5 | **0,9989 ± 0,0001** | 420 | 132 s |
| 6 | 0,9988 ± 0,0001 | 438 | 129 s |
| **7 (chọn)** | 0,9987 ± 0,0001 | 202 | 80 s |
| 8 | 0,9988 ± 0,0003 | 103 | 37 s |
| 9 | 0,9987 ± 0,0001 | 72 | 50 s |
| 10 | 0,9986 ± 0,0003 | 168 | 67 s |
| 11 | 0,9988 ± 0,0002 | 566 | 213 s |
| 12 | 0,9988 ± 0,0002 | 284 | 94 s |

Cả 12 cấu hình chỉ chênh nhau 0,0003 macro-F1, nhỏ hơn độ dao động giữa các fold. **Siêu tham số gần như không ảnh hưởng đến Bảng A.** Quy tắc 1 độ lệch chuẩn vì vậy chọn cấu hình 7: kém cấu hình tốt nhất không đáng kể (trong phạm vi 1 độ lệch chuẩn) nhưng chỉ cần 202 vòng với 31 lá, thay vì 420 vòng.

## 2. Kiểm chứng chéo (fold 1–4, F_NOOS)

| Fold | macro-F1 | FPR | Phát hiện | AUC (OvR macro) |
|---|---:|---:|---:|---:|
| 1 | 0,9984 | 0,0001 | 0,9993 | 1,0000 |
| 2 | 0,9988 | 0,0001 | 0,9994 | 1,0000 |
| 3 | 0,9981 | 0,0002 | 0,9994 | 1,0000 |
| 4 | 0,9998 | 0,0002 | 0,9996 | 1,0000 |
| **Trung bình** | **0,9988** | **0,0001** | **0,9994** | **1,0000** |

Độ lệch giữa các fold khoảng 0,0006. Điểm test (0,9989) nằm sát trung bình CV, nên không có dấu hiệu quá khớp vào tập test. Fold 3 thấp nhất và fold 4 cao nhất ở cả RF lẫn LightGBM, cho thấy chênh lệch này đến từ **dữ liệu của từng fold**, không phải từ mô hình.

## 3. Bảng A: kết quả trên tập test (fold 0)

| Bộ đặc trưng | Quyết định | macro-F1 | FPR | Phát hiện | AUC |
|---|---|---:|---:|---:|---:|
| F_NOOS | argmax | 0,9989 | 0,0001 | 0,9995 | 1,0000 |
| **F_NOOS** | **ngưỡng 0,50** | **0,9989** | **0,0001** | **0,9995** | **1,0000** |
| F_ALL | argmax | 0,9990 | 0,0000 | 0,9999 | 1,0000 |
| F_ALL | ngưỡng 0,48 | 0,9990 | 0,0000 | 0,9999 | 1,0000 |

### 3.1. Ma trận nhầm lẫn: F_NOOS, ngưỡng 0,50

| Thật \ Dự đoán | BENIGN | DoS/DDoS | PortScan | BruteForce | Tổng |
|---|---:|---:|---:|---:|---:|
| **BENIGN** | 425.640 | 39 | 3 | 0 | 425.682 |
| **DoS/DDoS** | 45 | 75.243 | 0 | 0 | 75.288 |
| **PortScan** | 0 | 0 | 394 | 0 | 394 |
| **BruteForce** | 4 | 0 | 0 | 20.568 | 20.572 |

| Lớp | Precision | Recall | F1 |
|---|---:|---:|---:|
| BENIGN | 0,9999 | 0,9999 | 0,9999 |
| DoS/DDoS | 0,9995 | 0,9994 | 0,9994 |
| PortScan | 0,9924 | 1,0000 | 0,9962 |
| BruteForce | 1,0000 | 0,9998 | 0,9999 |

### 3.2. Ma trận nhầm lẫn: F_ALL, ngưỡng 0,48 (đối chứng)

| Thật \ Dự đoán | BENIGN | DoS/DDoS | PortScan | BruteForce |
|---|---:|---:|---:|---:|
| **BENIGN** | 425.664 | 15 | 3 | 0 |
| **DoS/DDoS** | 8 | 75.280 | 0 | 0 |
| **PortScan** | 0 | 0 | 394 | 0 |
| **BruteForce** | 4 | 0 | 0 | 20.568 |

### 3.3. Diễn giải

- **Báo động giả:** 42 trên 425.682 flow BENIGN (0,010%). Quy đổi: với 100.000 flow mỗi giờ, khoảng 10 cảnh báo giả mỗi giờ (RF: khoảng 16).
- **Bỏ sót:** 49 trên 96.254 flow tấn công (0,05%), gần như toàn bộ thuộc DoS/DDoS (45). Kiểu tấn công con bị bỏ sót: ⏳ (xem `runs/20260929-041555-lgbm/F_NOOS_test_nguong_theo_subtype.csv`). Cần đối chiếu xem có trùng với 47 flow DoS mà RF bỏ sót không: nếu trùng, đó là những flow khó về bản chất, không phải điểm yếu riêng của mô hình.
- **PortScan đúng 394/394,** chỉ mất precision do 3 flow BENIGN bị gán nhầm.
- **Ngưỡng 0,50 cho kết quả trùng argmax.** Xác suất của LightGBM phân tách rõ nên việc chọn ngưỡng không thay đổi gì trên fold 0.
- **F_ALL làm giảm bỏ sót DoS từ 45 xuống 8.** Phần lớn các flow DoS "khó" được cứu bằng vân tay hệ điều hành, tức là bằng thông tin không mang theo được sang mạng khác.

## 4. Mức quan trọng đặc trưng

Chỉ dùng để **diễn giải**, không dùng để chọn đặc trưng. Permutation importance = mức giảm macro-F1 khi xáo trộn cột đó (tính trên mẫu của fold 0). Gain = tổng mức giảm hàm mất mát nhờ các lần tách trên cột đó.

### 4.1. F_NOOS (triển khai)

| # | Đặc trưng | Permutation | Gain |
|---:|---|---:|---:|
| 1 | PSH Flag Count | **0,0062** | 1,9 × 10⁴ |
| 2 | Bwd IAT Min | 0,0025 | 1,4 × 10⁵ |
| 3 | Fwd Packet Length Max | 0,0025 | 1,3 × 10⁵ |
| 4 | Flow IAT Min | 0,0019 | 1,8 × 10⁴ |
| 5 | dst_port_class | 0,0018 | 2,0 × 10⁴ |
| 6 | act_data_pkt_fwd | 0,0017 | 1,1 × 10⁶ |
| 7 | Fwd Header Length | 0,0017 | 2,5 × 10⁵ |
| 8 | Packet Length Mean | 0,0012 | 6,8 × 10⁵ |
| 9 | Bwd Packet Length Min | 0,0010 | 8,3 × 10⁵ |
| 10 | Bwd Packets/s | 0,0009 | 8,8 × 10⁴ |

### 4.2. F_ALL (đối chứng)

| # | Đặc trưng | Permutation | Gain |
|---:|---|---:|---:|
| 1 | **Init_Win_bytes_forward** | **0,0139** | 4,1 × 10⁵ |
| 2 | **Init_Win_bytes_backward** | 0,0123 | 1,3 × 10⁶ |
| 3 | Packet Length Mean | 0,0043 | 6,5 × 10⁵ |
| 4 | Fwd Packet Length Max | 0,0025 | 4,7 × 10⁴ |
| 5 | Bwd Packets/s | 0,0011 | 2,3 × 10⁵ |

### 4.3. Diễn giải

- **Mức phụ thuộc phân tán, khác hẳn RF.** Đặc trưng quan trọng nhất của LightGBM chỉ làm macro-F1 giảm 0,006 khi bị xáo trộn, trong khi RF phụ thuộc vào `Total Length of Bwd Packets` tới 0,111. LightGBM không dựa vào một cột duy nhất; thông tin được dàn trải trên nhiều cột. Ở Bảng A, cả hai mô hình vẫn đạt 0,998–0,999, tức là **hai mô hình học hai "cách giải" khác nhau cho cùng một bài toán**. Đây là điểm đáng viết khi so sánh.
- **Hai mô hình bám vào những đặc trưng khác nhau.** Top 10 của LightGBM nghiêng về khoảng thời gian (`Bwd IAT Min`, `Flow IAT Min`) và cờ TCP, còn RF nghiêng về dung lượng. Riêng `PSH Flag Count` lọt top 2 ở cả hai, nên đây là tín hiệu hành vi đáng tin cậy nhất.
- **Vân tay HĐH vẫn được dùng khi có (F_ALL),** hai cột `Init_Win_bytes_*` đứng đầu, nhưng ở mức nhẹ hơn RF nhiều (0,014 so với 0,25).
- **Gain và permutation lệch nhau mạnh** (ví dụ `act_data_pkt_fwd`: gain cao thứ hai nhưng permutation chỉ xếp thứ 6). Gain đo mức cột được dùng khi *xây* cây, permutation đo mức mô hình *cần* cột đó khi dự đoán; các cột tương quan bù trừ cho nhau khi bị xáo trộn. Khi báo cáo nên ưu tiên permutation.

## 5. Bảng B: chéo bộ dữ liệu

Huấn luyện trên hai bộ, kiểm tra trên bộ còn lại, chỉ tính các lớp mô hình đã được học. Quyết định theo argmax.

| Test trên | Train trên | Bộ đặc trưng | macro-F1 | Phát hiện | FPR | AUC |
|---|---|---|---:|---:|---:|---:|
| 2017 | 2018 + 2019 | F_NOOS | 0,395 | 14,1% | 3,0% | 0,65 |
| 2018 | 2017 + 2019 | F_NOOS | 0,452 | **0,0%** | 0,16% | 0,97 |
| 2019 | 2017 + 2018 | F_NOOS | 0,005 | 0,04% | 0%* | 0,77 |
| 2017 | 2018 + 2019 | F_ALL | 0,373 | 12,7% | 2,6% | 0,65 |
| 2018 | 2017 + 2019 | F_ALL | 0,451 | 0,0% | 0,32% | 0,99 |
| 2019 | 2017 + 2018 | F_ALL | 0,005 | 0,03% | 0,28%* | 0,67 |

\*Bộ 2019 chỉ có 353 dòng BENIGN: FPR ở dòng này không có ý nghĩa thống kê.

Recall theo từng cặp chuyển giao (F_NOOS):

| Cặp | Recall |
|---|---:|
| BruteForce: 2017 → 2018 | 0,0% (bộ test 2018 chỉ có tấn công BruteForce, và không flow nào được cảnh báo) |
| DoS/DDoS: 2017 → 2019 | ≤ 0,04% |
| BruteForce: 2018 → 2017 | ⏳ (cột `recall_BruteForce`, dòng `cheo_test2017`) |
| DoS/DDoS: 2019 → 2017 | ⏳ (cột `recall_DoS/DDoS`, dòng `cheo_test2017`) |

### 5.1. Diễn giải

- **Cũng sụp đổ như RF:** từ 0,999 ở Bảng A xuống 0,005–0,45 ở Bảng B.
- **Test trên 2018:** vẫn không phát hiện được BruteForce nào, nhưng FPR thấp hơn RF nhiều (0,16% so với 1,0%). AUC 0,97 cho thấy thứ tự điểm vẫn khá tốt, nên hiệu chỉnh ngưỡng tại môi trường mới vẫn có triển vọng.
- **Test trên 2019 là điểm yếu rõ nhất:** AUC chỉ 0,77, thấp hơn nhiều so với RF (0,96). Với DDoS kiểu UDP reflection chưa từng gặp, LightGBM mất cả khả năng *xếp hạng*, không chỉ lệch ngưỡng. Hiệu chỉnh ngưỡng sẽ giúp ít hơn so với RF.
- **Khớp với tài liệu:** mô hình nhỉnh hơn ở Bảng A (LightGBM) lại không phải mô hình tổng quát hoá tốt hơn (RF giữ AUC tốt hơn ở 2 trên 3 chiều). Đây đúng là lý do luật chọn mô hình đặt Bảng B ở bước 2.

## 6. Vận hành

| Mục | F_NOOS | F_ALL |
|---|---:|---:|
| Dung lượng bundle `.joblib` | 1,13 MB | 0,71 MB |
| Dự đoán lô 10.000 flow | 154,5 ms | 86,3 ms |
| Thông lượng ước tính | ~65.000 flow/giây | ~115.000 flow/giây |
| Dự đoán 1 flow đơn lẻ | **1,31 ms** | 1,28 ms |
| Tổng thời gian chạy notebook | 40,7 phút | (chung) |

- **Nhẹ nhất đến giờ** (1,13 MB, bằng khoảng 1/4 RF) và **dự đoán từng flow nhanh hơn RF khoảng 35 lần** (1,3 ms so với 47 ms), vì không phải khởi động xử lý song song như RF.
- **Dự đoán theo lô lại chậm hơn RF** (155 ms so với 100 ms cho 10.000 flow). Con số này có thể dao động giữa các lần đo trên Kaggle: bản F_ALL cùng loại mô hình chỉ mất 86 ms. Nếu cần, nên đo lại trên máy chạy backend. Với lô 5–10 giây, cả hai mức đều thừa sức.
- **Huấn luyện nhanh gấp khoảng 4 lần RF** (40,7 phút so với 159,8 phút cho toàn bộ quy trình), thuận lợi khi phải huấn luyện lại, ví dụ khi bổ sung dữ liệu lab.
- Đã kiểm tra: load lại bundle và dự đoán qua `predict_frame` cho kết quả khớp 100% với lúc huấn luyện.

## 7. Kết luận

1. **Tốt nhất đến giờ ở Bảng A:** macro-F1 0,9989, FPR 0,010%, PortScan không bỏ sót flow nào. Tuy vậy, mức hơn RF (0,0007) nằm trong ngưỡng "tương đương thực tế" 0,005 của luật chọn.
2. **Bảng A không nhạy với siêu tham số:** 12 cấu hình chỉ chênh 0,0003.
3. **Tổng quát hoá kém như RF, và kém hơn RF ở chiều test 2019** (AUC 0,77 so với 0,96).
4. **Ưu thế vận hành rõ:** mô hình nhỏ, dự đoán từng flow nhanh, huấn luyện nhanh.

**Vai trò trong so sánh:** ứng viên mạnh về Bảng A và vận hành. Việc nó có vượt RF trong luật chọn hay không phụ thuộc vào bước 2 (Bảng B): notebook so sánh sẽ tính recall chuyển giao trung bình và bootstrap để quyết định.

## 8. Việc còn lại

- [ ] Điền các ô ⏳ từ `experiments.csv` và `runs/20260929-041555-lgbm/`.
- [ ] Đối chiếu các flow DoS bị bỏ sót với RF (cùng flow hay khác flow).
- [ ] Commit `experiments.csv`, `runs/` và `models/*.json` lên GitHub.
- [ ] Bảng C: đánh giá trên dữ liệu lab khi có, kèm thí nghiệm hiệu chỉnh ngưỡng.
