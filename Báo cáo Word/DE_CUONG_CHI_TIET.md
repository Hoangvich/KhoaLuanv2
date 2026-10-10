# BẢN ĐỀ CƯƠNG CHI TIẾT KHÓA LUẬN TỐT NGHIỆP

TRƯỜNG ĐẠI HỌC MỞ HÀ NỘI

KHOA CÔNG NGHỆ THÔNG TIN

ĐỀ CƯƠNG KHÓA LUẬN TỐT NGHIỆP ĐAI HỌC

NGÀNH CÔNG NGHỆ THÔNG TIN

NGHIÊN CỨU ỨNG DỤNG HỌC MÁY TRONG GIÁM SÁT VÀ PHÁT HIỆN BẤT THƯỜNG TRÊN HỆ THỐNG MẠNG DOANH NGHIỆP

Giảng viên hướng dẫn: ThS.Nguyễn Thành Huy

Sinh viên thực hiện: Đoàn Lê Đức Anh - 2310A04

Trương Nguyễn Đức Anh - 2210A03

Nguyễn Huy Hoàng -  2310A04

Nguyễn Văn Khải-  2310A04

Phùng Ngọc Linh - 2310A02

Hà Nội - 2026

MỤC LỤC

MỤC LỤC1


## I. Tóm tắt đề cương2


## II. Giới thiệu đề tài2


## III. Các đề tài liên quan3


## IV. Nội dung dự định đạt được5


### 1. Mục đích của đề tài5


### 2. Mục tiêu của đề tài5


### 3. Phạm vi bài toán6


### 4. Về dữ liệu huấn luyện7


### 5. Về mô hình học máy8


### 6. Về kiến trúc hệ thống10


### 7. Về giao diện11


### 8. Về chức năng11


### 9. Về công cụ sử dụng13


### 10. Tiêu chí đánh giá13


### 11. Khắc phục các hạn chế của đề tài liên quan14


## V. Kế hoạch thực hiện16


## VI. Phân công công việc18


## VII. Tài liệu tham khảo19


## VIII. Chữ ký20


## I. Tóm tắt đề cương

Tên đề tài: “Nghiên cứu ứng dụng học máy trong giám sát và phát hiện bất thường trên hệ thống mạng doanh nghiệp”.

Ngành: Công nghệ thông tin.

Chuyên ngành: Mạng và An toàn thông tin

Bài toán trọng tâm: Phát hiện 3 nhóm hành vi tấn công phổ biến nhất trên mạng nội bộ doanh nghiệp: DDoS/DoS, Port Scan (trinh sát mạng) và Brute Force (dò mật khẩu dịch vụ xác thực).

Nội dung đề cương bao gồm:

Giới thiệu đề tài

Các đề tài liên quan

Nội dung dự định đạt được

Kế hoạch thực hiện

Phân công công việc

Tài liệu tham khảo.


## II. Giới thiệu đề tài

Hệ thống mạng doanh nghiệp hiện nay thường phân vùng thành nhiều lớp: mạng nội bộ (LAN), vùng DMZ, hạ tầng máy chủ dịch vụ và kênh kết nối từ xa (VPN) — cấu trúc càng mở rộng, bề mặt tấn công càng lớn. Ba hình thức tấn công phổ biến, ảnh hưởng trực tiếp đến hoạt động kinh doanh: tấn công từ chối dịch vụ (DoS/DDoS) gây gián đoạn dịch vụ đối ngoại; quét cổng (Port Scan) là bước trinh sát mở đường cho xâm nhập sâu hơn; vét cạn mật khẩu (Brute Force) nhắm vào các dịch vụ xác thực như SSH, RDP, VPN.

Các giải pháp giám sát dựa trên luật/dấu hiệu (Signature-based) như Snort, Suricata có bốn hạn chế: khó phát hiện biến thể tấn công mới; phụ thuộc cập nhật luật thủ công; dễ gây quá tải cảnh báo (Alert Fatigue); khó thiết lập ngưỡng phù hợp với đặc thù lưu lượng riêng của từng mạng.

Đề tài tiếp cận theo hướng học máy dựa trên đặc trưng luồng mạng (Flow-based Machine Learning) — phân tích đặc trưng thống kê của luồng kết nối (thời lượng phiên, số lượng/kích thước gói tin, tỷ lệ cờ TCP, tần suất kết nối...) thay vì kiểm tra nội dung gói tin, vốn bị hạn chế bởi mã hoá TLS/HTTPS. Quy trình xử lý: thu thập lưu lượng qua cổng mirror/SPAN trên switch → trích xuất đặc trưng luồng → phân loại bằng mô hình học máy → lưu trữ và hiển thị cảnh báo trên dashboard.

Đối tượng thụ hưởng là quản trị viên mạng và kỹ sư vận hành an ninh (SOC), đặc biệt tại doanh nghiệp vừa và nhỏ — nơi triển khai đầy đủ giải pháp SIEM thương mại thường bị giới hạn bởi chi phí. Đề tài không thay thế các giải pháp SIEM hiện có, mà minh hoạ một hướng tiếp cận giám sát bằng học máy với chi phí triển khai thấp hơn, kỳ vọng góp phần rút ngắn thời gian phát hiện và cung cấp bằng chứng kỹ thuật (đặc trưng luồng bất thường, IP nguồn/đích, dịch vụ mục tiêu, độ tin cậy) hỗ trợ quản trị viên ra quyết định xử lý.


## III. Các đề tài liên quan


### 1. Đề tài 1: Áp dụng kỹ thuật học máy để xây dựng hệ thống phát hiện và ngăn chặn xâm nhập trong mạng điều khiển bằng phần mềm (SDN)

- Tác giả: Ngô Anh Quang, Nguyễn Duy Nhật Thành (GVHD: ThS. Nguyễn Khánh Thuật, ThS. Văn Thiên Luân) – Trường Đại học Công nghệ Thông tin, ĐHQG TP.HCM (UIT) – Năm: 2025.

- Kết quả nghiên cứu:

Xây dựng hệ thống phát hiện xâm nhập trong môi trường mạng điều khiển bằng phần mềm (SDN) dựa trên thuật toán XGBoost.

Thực hiện đầy đủ quy trình tiền xử lý, trích xuất và chuẩn hóa đặc trưng; thử nghiệm trên bộ dữ liệu SDN-Intrusion với hai nhóm lưu lượng: bình thường và tấn công DDoS.

Đánh giá hiệu năng toàn diện thông qua các chỉ số: Accuracy, Recall, F1-score và đường cong ROC.

- Hạn chế:

Phạm vi nhận diện hẹp, chỉ tập trung vào một dạng tấn công duy nhất (DDoS) trên môi trường SDN mô phỏng.

Chưa kiểm chứng trên hạ tầng mạng doanh nghiệp thực tế với các phân vùng chức năng phức tạp.

Chưa so sánh đối chứng với các thuật toán học máy và học sâu khác.


### 2. Đề tài 2: Phát hiện xâm nhập mạng sử dụng mạng nơ-ron đồ thị với đặc trưng nút và cạnh

- Tác giả Nguyễn Thị Thanh Thủy, Nguyễn Ngọc Điệp – Học viện Công nghệ Bưu chính Viễn thông (PTIT) – Tạp chí KH CNTT&TT – Năm: 2024.

- Kết quả nghiên cứu:

Đề xuất mô hình mạng nơ-ron đồ thị (GNN) kết hợp đồng thời đặc trưng nút và cạnh, thử nghiệm trên tập dữ liệu chuẩn CIC-IDS2017.

Mô hình đề xuất (GATv2 nhúng kết hợp) đạt F1-score = 95,1%, vượt trội hơn các phương pháp học máy truyền thống như Random Forest (89,35%), SVM (90,96%) và các mô hình học sâu CNN-BiLSTM (90,8%).

Hạn chế:

Quy tắc xây dựng cạnh đồ thị còn đơn giản (chỉ dựa trên IP nguồn chung), chưa bao quát được các quan hệ luồng phức tạp.

Chi phí tính toán tài nguyên phần cứng lớn, khó khả thi khi áp dụng trên đồ thị lưu lượng lớn của mạng doanh nghiệp thực tế.

Mới dừng lại ở bài toán phân loại nhị phân (Bình thường / Tấn công), chưa phân loại đa lớp (Multi-class) để định danh cụ thể từng loại tấn công.


### 3. Đề tài 3: Giải pháp phát hiện xâm nhập mạng sử dụng mô hình học sâu

- Tác giả: Lê Anh Quân, Trần Minh Quang, Lý Phương Khải, Trần Trung Nguyễn (GVHD: TS. Phan Thượng Cang) – Tạp chí Khoa học Đại học Cần Thơ – Năm: 2025.

- Kết quả nghiên cứu:

So sánh hiệu năng đa dạng mô hình học sâu (MLP, RNN, CNN, LSTM, BiLSTM, GRU, Autoencoder, Transformer) trên tập dữ liệu UNSW-NB15.

Xác định BiLSTM và GRU đạt độ chính xác cao nhất (98,78%) với thời gian huấn luyện tối ưu, trong khi Transformer đạt độ chính xác cao nhưng đòi hỏi chi phí tính toán và thời gian huấn luyện dài.

- Hạn chế:

Chỉ đánh giá ngoại tuyến (offline) trên một bộ dữ liệu công khai duy nhất, chưa kiểm thử trên lưu lượng thực tế sinh ra từ môi trường doanh nghiệp.

Chưa tích hợp thành hệ thống giám sát và cảnh báo theo thời gian thực (Real-time monitoring pipeline).


## IV. Nội dung dự định đạt được


### 1. Mục đích của đề tài

Đề tài nghiên cứu và ứng dụng các kỹ thuật học máy vào bài toán giám sát, phát hiện bất thường trên hệ thống mạng doanh nghiệp, tập trung vào ba loại tấn công phổ biến: DoS/DDoS (ảnh hưởng tính khả dụng), Port Scan (trinh sát, tiền đề cho xâm nhập sâu hơn) và Brute Force (ảnh hưởng tính bí mật qua chiếm đoạt tài khoản).

Xây dựng một hệ thống giám sát mạng hoàn chỉnh, có khả năng thu thập lưu lượng từ hạ tầng mạng doanh nghiệp, phân tích theo thời gian gần thực bằng mô hình học máy, phát sinh cảnh báo và trực quan hoá tình trạng an toàn của mạng cho đội quản trị.


### 2. Mục tiêu của đề tài

Nghiên cứu cơ sở lý thuyết: đặc điểm kỹ thuật, dấu hiệu trên tầng mạng của ba loại tấn công DoS/DDoS, Port Scan, Brute Force; các phương pháp phát hiện xâm nhập (dựa trên dấu hiệu, dựa trên bất thường); các thuật toán học máy phù hợp với dữ liệu luồng mạng.

Xây dựng bộ dữ liệu huấn luyện: kết hợp các bộ dữ liệu công khai (CICIDS2017, CSE-CIC-IDS2018, CIC-DDoS2019) với dữ liệu tự sinh từ lab thử nghiệm, nhằm tăng độ đa dạng và kiểm tra khả năng tổng quát hoá của mô hình.

Huấn luyện và so sánh một số thuật toán học máy tiêu biểu (cây quyết định, ensemble, học sâu) cho bài toán phân loại đa lớp; mô hình học không giám sát (phát hiện bất thường chưa từng biết) triển khai thêm nếu còn thời gian.

Xây dựng hệ thống giám sát dạng pipeline: thu thập lưu lượng, trích xuất đặc trưng, suy luận theo lô (batch định kỳ), lưu trữ kết quả và sinh cảnh báo.

Xây dựng dashboard giám sát: hiển thị lưu lượng gần thời gian thực, danh sách cảnh báo, chi tiết luồng nghi vấn, thống kê theo loại tấn công/IP nguồn/dịch vụ bị nhắm tới.

Xây dựng lab quy mô nhỏ, thực hiện các kịch bản tấn công có kiểm soát để kiểm chứng mô hình trên lưu lượng tự sinh, không chỉ trên dataset công khai.

Đánh giá hệ thống theo các tiêu chí định lượng: Precision/Recall/F1 theo từng lớp tấn công, tỉ lệ báo động giả (FPR), thời gian từ lúc tấn công đến lúc phát sinh cảnh báo, năng lực xử lý (số luồng/giây).

Xây dựng cơ chế cảnh báo qua Email/Telegram khi phát hiện bất thường.


### 3. Phạm vi bài toán

Trong phạm vi (In scope):

Loại tấn công

Kỹ thuật cụ thể được xét

Dấu hiệu trên tầng mạng

DDoS/DoS

SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, Slowloris (slow-rate)

Số luồng cực lớn trong thời gian ngắn, gói nhỏ, tỉ lệ SYN không hoàn tất bắt tay cao, nhiều IP nguồn → một đích

Port Scan

TCP SYN scan, TCP Connect scan, FIN/NULL/XMAS scan, UDP scan, quét dải mạng (host discovery)

Một IP nguồn → nhiều cổng/nhiều đích, luồng rất ngắn, nhiều RST, ít byte truyền

Brute Force

SSH, RDP, FTP, HTTP form login, VPN, SMB

Nhiều kết nối lặp lại tới cùng cổng dịch vụ xác thực, kích thước gói đồng dạng, tần suất đều, nhiều lần thất bại

Các biến thể trên được học từ dữ liệu công khai (đã có sẵn nhiều biến thể); dữ liệu tự sinh tại lab (mục IV.4.c) chỉ tái hiện một kỹ thuật đại diện mỗi loại để kiểm chứng trên lưu lượng thực.

Ngoài phạm vi (Out of scope):

Không xử lý mã độc/ransomware ở mức tệp tin (không phân tích payload nhị phân).

Không giải mã lưu lượng TLS; chỉ sử dụng metadata luồng.

Không xây dựng thiết bị phần cứng chuyên dụng; hệ thống triển khai ở mức phần mềm.

Không phát triển thành sản phẩm IPS/tự động chặn kết nối; hệ thống dừng ở mức phát hiện và cảnh báo.


### 4. Về dữ liệu huấn luyện

Nguyên tắc: các bộ dữ liệu dùng để huấn luyện chính phải cùng không gian đặc trưng (trích xuất bằng CICFlowMeter); dữ liệu có không gian đặc trưng khác được xử lý như thực nghiệm bổ sung riêng biệt, không gộp trực tiếp vào tập huấn luyện.

Dữ liệu công khai — huấn luyện chính (cùng trích xuất bằng CICFlowMeter)

Bộ dữ liệu

Vai trò

CICIDS2017

Bộ nền tảng — có đủ 3 lớp DDoS, Port Scan, Brute Force (FTP/SSH-Patator)

CSE-CIC-IDS2018

Bổ sung khối lượng, nhiều biến thể DoS/Brute Force

CIC-DDoS2019

Làm giàu lớp DDoS với các biến thể phản xạ/khuếch đại (NTP, DNS, LDAP, SNMP)

b. Dữ liệu mở rộng (nếu còn thời gian)

UNSW-NB15 trích xuất bằng công cụ Argus, không cùng không gian đặc trưng với nhóm CIC ở trên. Nếu sử dụng, sẽ xây pipeline trích xuất và huấn luyện riêng cho tập này để đánh giá khả năng tổng quát hoá giữa các không gian đặc trưng khác nhau — không đưa thẳng vào mô hình đã huấn luyện trên đặc trưng CICFlowMeter.

c. Dữ liệu tự sinh từ lab (quy mô nhỏ)

Testbed: 1 router/switch ảo chia 3 VLAN (người dùng, máy chủ, DMZ), 1 firewall (pfSense), 1 web server, 1 SSH server.

Lưu lượng bình thường: truy cập web, đăng nhập SSH, truyền file cơ bản giữa các VLAN.

Lưu lượng tấn công: hping3 (DDoS — SYN flood), nmap (Port Scan), hydra (Brute Force — SSH).

Ghi lại dưới dạng .pcap, gán nhãn theo thời gian và kịch bản.

d. Quy trình xử lý dữ liệu

Trích xuất đặc trưng luồng từ pcap bằng CICFlowMeter (đồng nhất không gian đặc trưng với các dataset CIC).

Làm sạch: loại bỏ bản ghi trùng, giá trị thiếu/vô hạn, và các cột định danh gây rò rỉ nhãn (Flow ID, IP, Timestamp).

Chuẩn hoá nhãn về hệ thống thống nhất: BENIGN, DDOS, PORTSCAN, BRUTEFORCE.

Chuẩn hoá thang đo đặc trưng (StandardScaler/MinMaxScaler), lưu scaler để dùng ở bước suy luận.

Xử lý mất cân bằng lớp: lấy mẫu dưới lớp đa số, SMOTE cho lớp thiểu số, hoặc class_weight.

Chọn lọc đặc trưng: Mutual Information, Feature Importance của mô hình cây, hệ số tương quan.

Chia dữ liệu train/validation/test theo thời gian và theo kịch bản, không chia ngẫu nhiên đơn thuần.


### 5. Về mô hình học máy

a. Kiến trúc phát hiện

Hệ thống sử dụng mô hình phân loại đa lớp (multi-class classification): mỗi luồng mạng được phân loại vào một trong bốn nhãn BENIGN, DDOS, PORTSCAN, BRUTEFORCE.

b. Các mô hình dự kiến so sánh

Nhóm

Mô hình

Lý do chọn

Cơ sở

Decision Tree, Logistic Regression

Làm mốc so sánh, dễ triển khai và diễn giải

Ensemble

Random Forest, XGBoost

Hiệu năng cao trên dữ liệu dạng bảng, hỗ trợ đánh giá mức độ quan trọng của đặc trưng (Feature Importance)

Học sâu

MLP (Multi-Layer Perceptron)

Khai thác quan hệ phi tuyến giữa các đặc trưng luồng mạng

c. Huấn luyện và tinh chỉnh

Tinh chỉnh siêu tham số bằng Grid Search hoặc Randomized Search, kết hợp 5-fold cross-validation.

Huấn luyện trên tập hợp CICIDS2017, CSE-CIC-IDS2018 và CIC-DDoS2019; đánh giá trên tập kiểm tra giữ riêng (hold-out) và trên dữ liệu tự sinh từ môi trường lab (mục IV.4.c).

Lựa chọn mô hình triển khai dựa trên hai tiêu chí: F1-score theo từng lớp tấn công và thời gian suy luận trên một lô luồng.

Đóng gói mô hình bằng joblib, lưu kèm bộ chuẩn hoá (scaler) và danh sách đặc trưng sử dụng để đảm bảo nhất quán khi triển khai.

d. Hướng mở rộng

Bổ sung mô hình học không giám sát (Isolation Forest hoặc Autoencoder) như một lớp phát hiện bổ sung, độc lập với mô hình phân loại chính.

Đánh giá mô hình trên tập dữ liệu UNSW-NB15 theo quy trình trích xuất đặc trưng riêng (mục IV.4.b).


### 6. Về kiến trúc hệ thống

Luồng xử lý dữ liệu:

[Switch/Router trong lab]

│ cổng mirror/SPAN (hoặc capture trực tiếp trên máy ảo)

▼

[Sensor thu thập lưu lượng] ── tcpdump / Zeek

│ pcap theo cửa sổ thời gian (5-10 giây/lần)

▼

[Bộ trích xuất đặc trưng] ── CICFlowMeter → vector đặc trưng luồng

│

▼

[Dịch vụ suy luận mô hình] ── FastAPI + mô hình đã huấn luyện

│ nhãn dự đoán + độ tin cậy

├──────────────► [CSDL PostgreSQL — lưu luồng, cảnh báo, lịch sử]

├──────────────► [Bộ cảnh báo: Email / Telegram]

▼

[Dashboard giám sát] ── React, cập nhật định kỳ qua gọi API

Hệ thống xử lý theo lô (batch định kỳ) thay vì xử lý luồng liên tục thời gian thực: mỗi chu kỳ (5-10 giây), sensor ghi lại một cửa sổ pcap, trích xuất đặc trưng, đưa qua mô hình suy luận và ghi kết quả vào CSDL; dashboard lấy dữ liệu mới bằng cách gọi API định kỳ. Cách tiếp cận này đơn giản hơn kiến trúc streaming (không cần hàng đợi dữ liệu dòng như Kafka), phù hợp với quy mô dữ liệu của một hệ thống demo, đồng thời vẫn đáp ứng yêu cầu giám sát gần thời gian thực.

Phân rã module (là cơ sở phân công công việc ở mục VI):

Module

Nội dung

M1

Nghiên cứu lý thuyết & tổng quan tài liệu

M2

Xây dựng lab quy mô nhỏ, kịch bản tấn công, thu thập pcap (mục IV.4.c)

M3

Tiền xử lý dữ liệu, trích xuất & chọn lọc đặc trưng (mục IV.4.d)

M4

Huấn luyện, tinh chỉnh, đánh giá mô hình học máy (mục IV.5)

M5

Pipeline xử lý theo lô + dịch vụ suy luận (model serving)

M6

Backend hệ thống: API, CSDL, gom cụm cảnh báo (event correlation), phân quyền

M7

Frontend dashboard giám sát

M8

Kiểm thử, triển khai, đánh giá hệ thống, viết báo cáo


### 7. Về giao diện

Dashboard thiết kế mật độ thông tin cao, phù hợp cho quản trị viên mạng cần nắm nhanh tình trạng hệ thống.

Trang tổng quan: tổng luồng đang giám sát, số cảnh báo theo mức độ, top IP nguồn nghi vấn; biểu đồ lưu lượng gần thời gian thực và biểu đồ phân bố loại tấn công.

Trang cảnh báo: danh sách cảnh báo lọc theo thời gian, loại tấn công, mức độ nghiêm trọng, IP nguồn/đích; xem chi tiết luồng và các đặc trưng khiến mô hình đưa ra kết luận.

Trang quản trị: quản lý tài khoản và phân quyền (Admin/Analyst/Viewer), xem log hoạt động — giao diện dạng bảng đơn giản, không cần thiết kế chuyên sâu.

Phân biệt mức độ nghiêm trọng bằng màu sắc.

Mở rộng nếu còn thời gian: trang phân tích mô hình (so sánh hiệu năng, confusion matrix, feature importance); trang xuất báo cáo PDF/CSV theo ngày/tuần/tháng; chế độ tối.


### 8. Về chức năng

a. Quản trị viên mạng / SOC

Giám sát lưu lượng và trạng thái các phân vùng mạng đang theo dõi.

Xem và xử lý cảnh báo: lọc theo loại tấn công, mức độ nghiêm trọng; đánh dấu trạng thái (mới/đang xử lý/đã xử lý/báo động giả).

Truy vết chi tiết luồng nghi vấn: đặc trưng luồng, IP/cổng nguồn-đích, giao thức, thời điểm, độ tin cậy của mô hình.

Thống kê: biểu đồ xu hướng tấn công theo thời gian, top IP tấn công, dịch vụ bị nhắm tới nhiều nhất.

b. Quản trị hệ thống (Admin)

Quản lý người dùng và phân quyền: tạo/khoá tài khoản, phân vai trò (Admin/Analyst/Viewer).

Xem log hoạt động: ai đăng nhập, ai xử lý cảnh báo nào, khi nào.

c. Module học máy

Nhận vector đặc trưng theo lô, trả về nhãn dự đoán và độ tin cậy.

d. Gom cụm cảnh báo (event correlation)

Một đợt tấn công thật thường sinh ra hàng nghìn luồng riêng lẻ trong vài giây — ví dụ một đợt SYN Flood từ 200 IP có thể tạo ra 5.000 luồng. Nếu báo mỗi luồng một cảnh báo, dashboard sẽ ngập thông tin, không dùng được. Cần một bước riêng: gom các luồng cùng loại tấn công, cùng đích, xảy ra trong cùng cửa sổ thời gian (10-30 giây) thành một cảnh báo duy nhất trước khi hiển thị. Đây là một hạng mục có khối lượng riêng, không phải một dòng phụ trong module học máy — cần ước lượng công sức và giao cụ thể (gợi ý: gộp vào module Backend/API, vì logic này nằm giữa bước suy luận và bước lưu/cảnh báo, không thuộc về mô hình).

Mở rộng nếu còn thời gian:

Cấu hình ngưỡng cảnh báo, danh sách trắng IP nội bộ.

Phản hồi nhãn cho mô hình (đánh dấu báo động giả) để phục vụ huấn luyện lại.

Quản lý sensor, quản lý phiên bản mô hình, quản lý cấu hình hệ thống, audit log chi tiết.


### 9. Về công cụ sử dụng

Hạng mục

Công nghệ dự kiến

Mô phỏng hạ tầng mạng

VMware, pfSense, Windows Server (AD), Ubuntu Server

Thu thập & phân tích lưu lượng

tcpdump, Wireshark, Zeek, CICFlowMeter

Sinh lưu lượng tấn công

hping3, nmap, masscan, hydra, medusa, slowhttptest

Xử lý dữ liệu & học máy

Python, Pandas, NumPy, Scikit-learn, XGBoost, LightGBM, imbalanced-learn, TensorFlow/PyTorch, Optuna

Môi trường thực nghiệm

Google Colab

Backend

Python + FastAPI

Cơ sở dữ liệu

PostgreSQL

Frontend

React + Vite + Tailwind CSS

Triển khai

Docker, Docker Compose

Quản lý mã nguồn & công việc

Git/GitHub


### 10. Tiêu chí đánh giá

a. Đánh giá mô hình học máy

Precision, Recall, F1-score theo từng lớp tấn công, và F1-macro tổng hợp (ưu tiên hơn Accuracy do dữ liệu mất cân bằng giữa BENIGN và các lớp tấn công).

Tỉ lệ báo động giả (False Positive Rate) theo từng lớp.

Ma trận nhầm lẫn (Confusion Matrix) để xác định các cặp lớp dễ bị nhầm (ví dụ Port Scan bị nhận nhầm thành DDoS).

ROC-AUC/PR-AUC dạng macro-average one-vs-rest (do bài toán 4 lớp, không phải nhị phân).

Thời gian huấn luyện của từng mô hình; thời gian suy luận trung bình trên một lô 1.000 luồng (mục IV.5.c).

Đánh giá trên tập test giữ riêng (hold-out) và trên dữ liệu tự sinh từ lab (mục IV.4.c) để đo mức suy giảm hiệu năng ngoài phân bố huấn luyện.

Mở rộng nếu còn thời gian: đánh giá thêm trên UNSW-NB15 theo pipeline trích xuất đặc trưng riêng (mục IV.4.b, IV.5.d).

b. Đánh giá hệ thống

Thời gian phát hiện (detection latency): từ lúc tấn công bắt đầu đến khi cảnh báo xuất hiện trên dashboard, đo trên các kịch bản tấn công thực nghiệm tại lab (mục IV.4.c). Kết quả sẽ phản ánh cả độ trễ xử lý theo lô (5-10 giây/chu kỳ, mục 6), không phải độ trễ tức thời.

Năng lực xử lý: số luồng/giây mà pipeline xử lý được trong điều kiện traffic của lab — đo ở quy mô thực nghiệm sẵn có, không thực hiện kiểm tra tải công nghiệp.

Tỉ lệ phát hiện đúng theo từng kịch bản tấn công tại lab (đối chiếu với bảng kịch bản ở mục IV.4.c).

Mức tiêu thụ tài nguyên (CPU, RAM) của sensor và dịch vụ suy luận trong quá trình chạy demo.


### 11. Khắc phục các hạn chế của đề tài liên quan

Qua phân tích các đề tài liên quan, có thể nhận thấy các nghiên cứu ứng dụng học máy trong phát hiện xâm nhập mạng gần đây đã đạt kết quả rất tốt trên các tập dữ liệu chuẩn hoặc môi trường mô phỏng hẹp. Tuy nhiên, các hệ thống này chủ yếu tập trung vào việc thử nghiệm thuật toán ngoại tuyến và đánh giá độ chính xác đơn thuần, chưa gắn liền với bài toán giám sát luồng lưu lượng thực tế, chưa tối ưu chi phí tính toán và chưa giải quyết triệt để bài toán giảm thiểu cảnh báo sai trong môi trường mạng doanh nghiệp. Qua đó đề tài tập trung khắc phục các hạn chế sau:

Mở rộng phạm vi phát hiện đa dạng hành vi tấn công: Không giới hạn ở một hình thức tấn công đơn lẻ (như chỉ phát hiện DDoS trên môi trường SDN), hệ thống tập trung phát hiện đồng thời 3 nhóm hành vi nguy cơ phổ biến nhất trên mạng doanh nghiệp gồm DDoS/DoS, quét cổng do thám (Port Scan) và dò mật khẩu xác thực (Brute Force).

Xây dựng cơ chế phát hiện và phân loại kết hợp: Khắc phục hạn chế chỉ dừng lại ở phân loại nhị phân (Bình thường/Tấn công), đề tài kết hợp mô hình phân loại đa lớp để định danh chính xác từng loại tấn công cụ thể, có thể bổ sung thêm nhánh học không giám sát (mục IV.5.d) để nhận diện các lưu lượng dị biệt chưa từng xuất hiện trong tập huấn luyện nếu còn thời gian.

Tối ưu hóa tài nguyên tính toán và độ trễ suy luận: Thay vì sử dụng các mô hình mạng đồ thị (GNN) hay học sâu phức tạp đòi hỏi phần cứng lớn, đề tài tiếp cận theo các đặc trưng thống kê của luồng mạng (Flow-based) kết hợp các thuật toán cây quyết định tối ưu (XGBoost, Random Forest), đảm bảo tốc độ suy luận nhanh và tiêu thụ ít tài nguyên hệ thống.

Triển khai quy trình giám sát gần thời gian thực: Vượt qua giới hạn phân tích dữ liệu ngoại tuyến (offline) trên file có sẵn, đề tài xây dựng pipeline hoàn chỉnh từ khâu thu thập lưu lượng qua cổng Mirror/SPAN trên switch, trích xuất đặc trưng luồng theo cửa sổ thời gian đến suy luận và đưa ra cảnh báo theo chu kỳ xử lý.

Giảm thiểu nguy cơ rò rỉ dữ liệu (Data Leakage): Loại bỏ các trường thông tin định danh như địa chỉ IP, cổng dịch vụ và nhãn thời gian trước khi huấn luyện, giảm nguy cơ mô hình "học vẹt" địa chỉ mạng của kẻ tấn công thay vì học đúng đặc trưng hành vi luồng thực tế.

Kiểm chứng chéo và đánh giá khả năng tổng quát hóa: Không phụ thuộc vào một bộ dữ liệu công khai duy nhất, đề tài kết hợp kiểm chứng chéo giữa tập dữ liệu chuẩn quốc tế với lưu lượng thực tế sinh ra từ môi trường mạng Lab doanh nghiệp mô phỏng, giúp đánh giá khách quan độ sụt giảm hiệu năng khi áp dụng vào thực tế.

Giảm thiểu tình trạng quá tải cảnh báo (Alert Fatigue): Đặt chỉ số cảnh báo sai (FPR) làm tiêu chí đánh giá bắt buộc, kết hợp thuật toán gom cụm nhiều luồng mạng liên tiếp thành một sự kiện tấn công thống nhất, giúp đội ngũ vận hành dễ dàng theo dõi và không bị ngập tràn thông báo rời rạc.

Tăng cường tính minh bạch và hỗ trợ ra quyết định an ninh: Không coi mô hình là "hộp đen", hệ thống hiển thị đầy đủ thông tin bằng chứng (IP nguồn/đích, dịch vụ mục tiêu, độ tin cậy) cho mỗi cảnh báo, có thể bổ sung trực quan hoá mức độ đóng góp của các đặc trưng chính (Feature Importance) nếu triển khai trang phân tích mô hình (mục IV.7), và gửi thông báo qua Telegram/Email để hỗ trợ người quản trị xử lý sự cố kịp thời.

Đóng gói giải pháp thành hệ thống hoàn chỉnh: Thay vì chỉ dừng ở các đoạn mã thử nghiệm, toàn bộ giải pháp được đóng gói hoàn chỉnh bằng Docker/Docker Compose, tích hợp giao diện Dashboard chuyên nghiệp phục vụ công tác giám sát an ninh mạng thực tế.


## V. Kế hoạch thực hiện

STT

Công việc

1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

1

Nghiên cứu lý thuyết, khảo sát tài liệu liên quan

✕

✕

✕

2

Khảo sát yêu cầu, phân tích bài toán, xác định phạm vi

✕

✕

✕

3

Xây dựng lab mô phỏng mạng doanh nghiệp & kịch bản tấn công

✕

✕

✕

4

Thu thập dữ liệu, tiền xử lý, trích xuất & chọn lọc đặc trưng

✕

✕

✕

✕

5

Huấn luyện, tinh chỉnh, so sánh và lựa chọn mô hình

✕

✕

✕

✕

✕

6

Thiết kế kiến trúc hệ thống & cơ sở dữ liệu

✕

✕

✕

7

Xây dựng pipeline xử lý dữ liệu dòng & dịch vụ suy luận

✕

✕

✕

✕

8

Xây dựng backend: API, CSDL, cảnh báo, phân quyền

✕

✕

✕

✕

✕

9

Xây dựng frontend dashboard giám sát & báo cáo

✕

✕

✕

✕

✕

10

Tích hợp hệ thống, kiểm thử chức năng

✕

✕

✕

11

Triển khai thử nghiệm trên lab, đánh giá hiệu quả

✕

✕

✕

12

Viết báo cáo

✕

✕

✕

✕

✕

✕

✕

✕

✕

✕

✕

✕

✕

✕

✕

13

Hoàn thiện hệ thống & báo cáo, chuẩn bị bảo vệ

✕

✕


## VI. Phân công công việc

Người thực hiện

Công việc

Đoàn Lê Đức Anh


### 1. Xây dựng môi trường mạng Lab mô phỏng và cấu hình các phân vùng mạng (VLAN, DMZ, Firewall).


### 2. Xây dựng kịch bản và thực thi tấn công thử nghiệm (DDoS, Port Scan, Brute Force).


### 3. Triển khai công cụ bắt gói tin, thu thập và gán nhãn dữ liệu lưu lượng (.pcap).


### 4. Hoàn thiện báo cáo.

Phùng Ngọc Linh


### 1. Thu thập, xử lý và làm sạch các tập dữ liệu mạng (CIC-IDS2017, Lab traffic).


### 2. Trích xuất đặc trưng luồng mạng bằng CICFlowMeter.


### 3. Phân tích khám phá dữ liệu (EDA), loại bỏ dữ liệu rò rỉ nhãn và lựa chọn đặc trưng tối ưu.


### 4. Xử lý mất cân bằng lớp và chuẩn hóa dữ liệu đầu vào.


### 5. Hoàn thiện báo cáo.

Nguyễn Văn Khải


### 1. Huấn luyện các mô hình Machine Learning có giám sát và không giám sát (Random Forest, XGBoost, Isolation Forest).


### 2. Tinh chỉnh siêu tham số và đánh giá hiệu năng mô hình (Accuracy, F1-score, FPR).


### 3. Đánh giá chéo dữ liệu và phân tích mức độ quan trọng của đặc trưng (Feature Importance).


### 4. Đóng gói mô hình tối ưu sang file phục vụ triển khai.


### 5. Hoàn thiện báo cáo.

Nguyễn Huy Hoàng


### 1. Phân tích yêu cầu và thiết kế kiến trúc Backend, cơ sở dữ liệu.


### 2. Xây dựng dịch vụ suy luận mô hình (Inference Service) bằng FastAPI.


### 3. Xây dựng hệ thống tiếp nhận dữ liệu luồng, cơ chế gộp cảnh báo và gửi thông báo (Telegram/Email).


### 4. Xây dựng hệ thống REST API và WebSocket phục vụ giao diện giám sát.


### 5. Hoàn thiện báo cáo.

Trương Nguyễn Đức Anh


### 1. Thiết kế giao diện người dùng và xây dựng Dashboard giám sát bằng React.


### 2. Trực quan hóa dữ liệu lưu lượng mạng, danh sách cảnh báo và kết quả đánh giá mô hình.


### 3. Đóng gói và triển khai toàn bộ hệ thống bằng Docker/Docker Compose.


### 4. Xây dựng checklist và thực hiện kiểm thử chức năng, đo độ trễ hệ thống.


### 5. Hoàn thiện báo cáo.


## VII. Tài liệu tham khảo

Bộ dữ liệu

Canadian Institute for Cybersecurity, Intrusion Detection Evaluation Dataset (CICIDS2017). https://www.unb.ca/cic/datasets/ids-2017.html

Canadian Institute for Cybersecurity, CSE-CIC-IDS2018 on AWS. https://www.unb.ca/cic/datasets/ids-2018.html

Canadian Institute for Cybersecurity, DDoS Evaluation Dataset (CIC-DDoS2019). https://www.unb.ca/cic/datasets/ddos-2019.html

UNSW Canberra Cyber, The UNSW-NB15 Dataset. https://research.unsw.edu.au/projects/unsw-nb15-dataset

Công cụ & thư viện

CICFlowMeter — công cụ trích xuất đặc trưng luồng mạng từ pcap. https://github.com/ahlashkari/CICFlowMeter

Zeek Network Security Monitor Documentation. https://docs.zeek.org

Suricata User Guide. https://docs.suricata.io

Scikit-learn User Guide. https://scikit-learn.org/stable/user_guide.html

XGBoost Documentation. https://xgboost.readthedocs.io

FastAPI Documentation. https://fastapi.tiangolo.com

Apache Kafka Documentation. https://kafka.apache.org/documentation

Tiêu chuẩn & tài liệu chuyên môn

NIST SP 800-94, Guide to Intrusion Detection and Prevention Systems.

MITRE ATT&CK Framework — chiến thuật Reconnaissance (Port Scan), Credential Access (Brute Force), Impact (Network Denial of Service). https://attack.mitre.org

OWASP Top 10 — phần liên quan tới tấn công xác thực.


## VIII. Chữ ký

Hà Nội, ngày … tháng … năm 2026

Ý kiến của GVHD

Sinh viên

(Ký và ghi rõ họ tên)

