# Báo Cáo Chi Tiết Script: `src/evaluate_multiclass.py`

## 1. Thông Tin Chung
- **Tên script**: [evaluate_multiclass.py](file:///c:/IDPS/src/evaluate_multiclass.py)
- **Mục tiêu**: Đánh giá và tìm kiếm siêu tham số tối ưu cho các mô hình học máy phân loại đa lớp (7 lớp tấn công và lành tính). Thiết lập cơ sở đánh giá độ chính xác phân loại chi tiết các loại hiểm họa mạng trên bộ dữ liệu CIC-IDS-2017.

---

## 2. Chức Năng Chính
`evaluate_multiclass.py` phục vụ cho việc nghiên cứu và đánh giá năng lực nhận diện sâu của hệ thống IDPS:
- **Phân loại 7 danh mục đe dọa**: Đánh giá khả năng phân loại lưu lượng mạng vào đúng một trong các lớp: `BENIGN`, `Botnet`, `Brute Force`, `DoS/DDoS`, `Exploitation / Rare`, `PortScan`, `Web Attack`.
- **Tìm kiếm tham số đa lớp**: Sử dụng `RandomizedSearchCV` và 3-fold StratifiedKFold để tối ưu hóa siêu tham số của các thuật toán RandomForest, XGBoost và LightGBM.
- **Tối ưu hóa chỉ số Macro F1**: Xếp hạng và tuyển chọn mô hình dựa trên chỉ số **Macro F1-Score** để đảm bảo mô hình hoạt động tốt đồng đều trên tất cả các lớp, kể cả các lớp thiểu số cực hiếm (như Exploitation / Rare) thay vì chỉ ưu tiên lớp đa số (BENIGN).
- **Trực quan hóa ma trận nhầm lẫn**: Vẽ ma trận nhầm lẫn kích thước $7 \times 7$ trực tiếp dưới dạng bảng văn bản căn chỉnh cột, giúp nhà phân tích phát hiện nhanh mô hình đang nhầm lẫn giữa các loại tấn công nào.

---

## 3. Đầu Vào (Input)
- **Tham số dòng lệnh (Command Line Arguments)**:
  - `--train_path` (str): Đường dẫn file CSV tập huấn luyện đã tiền xử lý.
  - `--test_path` (str): Đường dẫn file CSV tập kiểm thử đã tiền xử lý.
  - `--models` (list): Danh sách các mô hình cần thử nghiệm (mặc định: `RandomForest`, `XGBoost`, `LightGBM`).
  - `--n_iter` (int): Số tổ hợp tham số sẽ chạy thử ngẫu nhiên (mặc định: 10).
  - `--n_jobs` (int): Số CPU core được sử dụng để chạy song song (mặc định: 1).
  - `--sample_train` (float): Tỉ lệ lấy mẫu từ tập Train để tăng tốc độ chạy thử (mặc định: 1.0).
  - `--save_model` (cờ): Nếu bật, lưu mô hình tốt nhất ra file `.pkl`.
  - `--output` (str): File lưu toàn bộ kết quả log (mặc định: `f:/IDPS/results/result_evaluate_multiclass.txt`).

---

## 4. Đầu Ra (Output)
- **Log file chi tiết**: Lưu giữ mọi kết quả hiển thị trên terminal vào file `.txt` được cấu hình qua `--output`.
- **Bảng so sánh đa lớp**: So sánh các mô hình dựa trên các chỉ số: Macro F1, Weighted F1, Macro Recall, Macro Precision, MCC, và Latency (µs/packet).
- **Classification Report chi tiết**: Cung cấp Precision, Recall, F1-score và số lượng mẫu thực tế (support) cho từng lớp trong số 7 lớp phân loại.
- **Confusion Matrix đa chiều**: Ma trận $7 \times 7$ mô tả chi tiết dòng thực tế (Actual) vs cột dự đoán (Predicted).
- **File mô hình (tùy chọn)**: File `best_multiclass_[tên_model].pkl` chứa pipeline mô hình đa lớp hoàn chỉnh.

---

## 5. Cơ Chế Hoạt Động

### 5.1 Mã hóa nhãn và Đồng bộ hóa

1. **Mã hóa nhãn chuỗi văn bản (`LabelEncoder`)**:
   Do mô hình XGBoost và LightGBM yêu cầu nhãn đầu vào là dạng số nguyên liên tục bắt đầu từ 0, script sử dụng lớp `LabelEncoder` của Scikit-Learn:
   - Fit trên nhãn của tập Train để học danh sách 7 lớp.
   - Ánh xạ nhãn chuỗi (ví dụ: `BENIGN` -> 0, `Botnet` -> 1, `Brute Force` -> 2, v.v...) cho cả tập Train và tập Test để đảm bảo tính nhất quán.
2. **Feature Alignment**:
   Thực hiện đồng bộ hóa các cột đặc trưng mạng (sắp xếp thứ tự bảng chữ cái A-Z, điền giá trị 0 cho NaN/Inf) tương tự như phiên bản nhị phân để đảm bảo dữ liệu đầu vào của hai tập khớp nhau hoàn toàn về mặt cấu trúc.

### 5.2 Tìm kiếm siêu tham số đa lớp

Quá trình tìm kiếm ngẫu nhiên (`RandomizedSearchCV`) sử dụng tập hợp các siêu tham số phù hợp cho bài toán đa lớp. 
Đối với XGBoost, mục tiêu được đặt là `objective='multi:softmax'` hoặc `objective='multi:softprob'` kết hợp với số lượng lớp `num_class=7`.
Đối với LightGBM, cấu hình mục tiêu là `objective='multiclass'`.

Các mô hình được đánh giá chéo qua các phép đo Macro (Macro Average) để tính toán điểm số F1 trung bình không phụ thuộc vào kích thước lớp. Mô hình tốt nhất được refit dựa trên thang điểm `F1_macro`.

### 5.3 Cách đọc Confusion Matrix $7 \times 7$ được in ra

Bảng Confusion Matrix được in ra dưới dạng văn bản có cấu trúc cột cố định:
```text
  Actual \ Pred          BENIGN     Botnet Brute Force   DoS/DDoS Exploit...   PortScan Web Att...
  ------------------------------------------------------------------------------------------------
  BENIGN                340,210         15          32         84          5         12          8
  Botnet                      4        980           0          1          0          0          0
  Brute Force                 2          0       1,450          0          0          0          0
  ...
```
- **Hàng ngang**: Thể hiện nhãn thực tế (Actual).
- **Cột dọc**: Thể hiện nhãn mô hình dự đoán (Predicted).
- **Đường chéo chính**: (Ví dụ: 340,210 của BENIGN, 980 của Botnet, 1,450 của Brute Force) thể hiện số lượng mẫu được dự đoán chính xác (True Positives). Các phần tử nằm ngoài đường chéo thể hiện sai số nhầm lẫn giữa các lớp.
