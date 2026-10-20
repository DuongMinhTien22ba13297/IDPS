# Báo cáo Triển khai Tuần 2

**Topic:** Design and Implementation of a Machine Learning-Based Intrusion Detection and Prevention System  
**Mục tiêu giai đoạn:** Xây dựng quy trình tiền xử lý dữ liệu và chia tách dữ liệu cho bộ dataset chuẩn CIC-IDS2017, làm nền tảng cho việc tối ưu hóa và huấn luyện mô hình ML.

---

## 1. Giới thiệu & Lý do chọn
Theo đề xuất dự án (`proposal.docx`), tiền xử lý dữ liệu là bước nền tảng quan trọng nhất của toàn bộ hệ thống IDPS.  

Bộ dữ liệu CIC-IDS2017 gốc có hơn 2.8 triệu mẫu, 15 nhãn tấn công khác nhau, chứa rất nhiều dữ liệu nhiễu, giá trị vô hạn (Infinity), NaN, và đặc biệt là mất cân bằng nghiêm trọng (imbalanced data) – lớp BENIGN chiếm hơn 80% tổng số mẫu. Nếu không xử lý tốt ở giai đoạn này, mô hình ML sẽ bị bias nặng, dẫn đến tỷ lệ False Positive cao – điều mà các IDS truyền thống thường gặp phải.

**Mục tiêu cụ thể của Tuần 2:**
- Tự động hóa toàn bộ quy trình tiền xử lý (không cần can thiệp thủ công).
- Giảm độ phức tạp của bài toán phân loại bằng cách gộp nhãn hợp lý.
- **Tránh rò rỉ dữ liệu (Data Leakage):** Trì hoãn việc cân bằng dữ liệu (SMOTE x10) và lựa chọn đặc trưng động, chỉ thực hiện trong quá trình huấn luyện và tối ưu hóa siêu tham số (Fold-level CV).
- **Đầu ra:** Hai tập dữ liệu Train (80%) và Test (20%) sạch, được gắn nhãn chuẩn hóa và sẵn sàng cho pipeline tối ưu hóa.

Toàn bộ công việc đã được đóng gói trong một script Python duy nhất: `src/data_preprocessing.py`.

---

## 2. Các bước triển khai chi tiết

### 2.1. Hợp nhất & Làm sạch dữ liệu (Data Ingestion & Cleaning)
- Bộ dữ liệu gốc gồm 8 file CSV phân mảnh (`Monday-WorkingHours.pcap_ISCX.csv`, `Tuesday-WorkingHours.pcap_ISCX.csv`...).
- Script tự động thực hiện:
  - Đọc tuần tự tất cả 8 file với encoding `utf-8`, bỏ qua bad lines.
  - Gom thành một DataFrame thống nhất (> 2.830.000 dòng).
  - Loại bỏ hoàn toàn các cột metadata không mang tính chất hành vi (không dùng cho mô hình real-time):
    - `Flow ID`, `Source IP`, `Destination IP`, `Source Port`, `Timestamp`, `External IP`.
  - Ép toàn bộ dữ liệu về kiểu numeric.
  - Chuyển giá trị `Infinity` / `-Infinity` → `NaN`.
  - Xóa toàn bộ dòng chứa `NaN` để đảm bảo vector đặc trưng sạch 100%.

### 2.2. Gộp nhãn tương đồng (Label Mapping / Standardization)
Dataset gốc có 15 nhãn → được chuẩn hóa và gộp thành 6 nhãn chính nhằm tăng mật độ dữ liệu và giảm độ phức tạp cho mô hình:
- **BENIGN**: Lành tính
- **DoS/DDoS**: DoS Hulk, DDoS, DoS GoldenEye, DoS slowloris, DoS Slowhttptest
- **PortScan**: PortScan
- **Brute Force**: FTP-Patator, SSH-Patator
- **Web Attack**: Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection
- **Botnet**: Bot

*Lưu ý: Lớp `Exploitation / Rare` (Infiltration, Heartbleed) được loại bỏ hoàn toàn khỏi tập dữ liệu do số mẫu quá ít, tránh gây mất cân bằng nghiêm trọng và làm nhiễu mô hình.*

### 2.3. Cân bằng dữ liệu (Deferred Resampling) & Chia tách dữ liệu chống rò rỉ (Anti-Leakage)
Sử dụng thư viện `imbalanced-learn`:
- **a. Không thực hiện SMOTE hay Undersampling tập trung** ở bước Preprocessing này để tránh Data Leakage.
- **b. Chia tách dữ liệu**: Dữ liệu thô sau khi làm sạch được chia tách thành tập Train (80%) và Test (20%) có phân tầng (Stratified Split) độc lập.
- **c. Trì hoãn SMOTE:** Việc cân bằng dữ liệu bằng SMOTE x10 (cho các lớp thiểu số: `Brute Force`, `Web Attack`, `Botnet`, `PortScan`) được trì hoãn và chỉ thực hiện động trên Train Fold trong pha huấn luyện/tối ưu hóa siêu tham số (K-Fold CV).

---

## 3. Kết quả đạt được

### 3.1. Phân phối dữ liệu trước & sau resampling
Tổng số mẫu sau tiền xử lý và loại bỏ nhãn hiếm: **1.449.860 mẫu** (Tập Train 80%: **1.159.887 mẫu**, Tập Test 20%: **289.973 mẫu**).

### 3.2. File đầu ra
- **Đường dẫn:** `datasets/cic2017_train_80_preprocessed.csv` và `datasets/cic2017_test_20_preprocessed.csv`
- **Kích thước:** Train ~350 MB, Test ~88 MB
- **Tình trạng:** Sẵn sàng đưa vào quá trình tối ưu hóa Bayesian (`optimize_models_bayesian.py`) và huấn luyện sản xuất.

---

## 4. Đóng góp của Tuần 2 đối với toàn bộ dự án
- Giải quyết triệt để nguyên nhân chính gây False Positive cao ở IDS truyền thống.
- Tạo nền tảng dữ liệu sạch cho cả mô hình Binary (Attack/Benign) và mô hình Multi-class (6 loại tấn công).
- Đảm bảo pipeline real-time sau này (`realtime_extractor.py`) chỉ cần trích xuất đặc trưng → đưa thẳng vào mô hình mà không cần xử lý thêm.
- Hoàn toàn tự động (1-click): chỉ cần chạy `python src/data_preprocessing.py` là xong toàn bộ quy trình tiền xử lý.

---

## 5. Khó khăn đã vượt qua
- Xử lý file CSV khổng lồ (hơn 2.8 triệu dòng) mà không làm crash RAM (bằng cách tối ưu hóa kiểu dữ liệu).
- Xử lý ký tự rác và bad lines trong file Web Attack.
- Thiết kế chiến lược resampling custom theo từng nhóm thay vì áp dụng chung một kỹ thuật tĩnh.

---

## 6. Kết luận & Bước tiếp theo
Tuần 2 đã hoàn thành xuất sắc 100% mục tiêu đề ra. Bộ dữ liệu đã được tối ưu hóa hoàn toàn, sẵn sàng cho giai đoạn xây dựng “bộ não” ML.
