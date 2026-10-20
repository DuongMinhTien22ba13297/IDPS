Viewed split_train_test.py:1-27
Ran command: `dir /s /b *.py`
Ran command: `Get-ChildItem -Recurse -Filter *.py | Select-Object FullName`
Viewed data_preprocessing.py:1-239
Viewed offline_training.py:1-222

Báo cáo này tổng hợp luồng dữ liệu của hệ thống **Zero-Touch IDPS**, từ việc trích xuất đặc trưng từ file PCAP thô cho đến khi xây dựng các mô hình học máy hoàn chỉnh.

### **Sơ đồ luồng dữ liệu (Data Pipeline)**

Dựa trên phân tích các file log trong thư mục `results/`, luồng dữ liệu được chia làm 6 giai đoạn chính:

#### **Giai đoạn 1: Trích xuất đặc trưng (PCAP Feature Extraction)**
*   **File thực thi:** `src/extract_pcap_features.py`
*   **Công cụ:** Sử dụng thư viện **NFStream** để đảm bảo tính đồng nhất về đặc trưng giữa quá trình huấn luyện (offline) và nhận dạng thời gian thực (real-time).
*   **Dữ liệu đầu vào:** 5 file PCAP gốc từ bộ dữ liệu CIC-IDS-2017 (Monday to Friday).
*   **Xử lý:** Duyệt qua từng gói tin, gom nhóm thành các flow và trích xuất 30 đặc trưng quan trọng.
*   **Kết quả:** Tổng cộng **3,351,784 flows** được trích xuất và lưu tại `datasets/nfs_csv/`.

#### **Giai đoạn 2: Gán nhãn dữ liệu (Flow Labeling)**
*   **File thực thi:** `src/label_flows.py`
*   **Xử lý:** 
    *   Đối chiếu các luồng mạng với danh sách tấn công từ dataset gốc dựa trên 5-tuple (IP nguồn/đích, Port nguồn/đích, Protocol) và Timestamp.
    *   Xử lý sai lệch múi giờ (Timezone Offset: -3h) để gán nhãn chính xác.
*   **Kết quả:** File dữ liệu tổng hợp đã gán nhãn `datasets/cic2017_nfs_labeled.csv`.

#### **Giai đoạn 3: Làm sạch và Chia tách (Cleaning & Splitting)**
*   **File thực thi:** `src/split_train_test.py`
*   **Xử lý:**
    *   **Data Purging:** Loại bỏ toàn bộ các dòng trùng lặp (Duplicates) để tránh hiện tượng học vẹt và đảm bảo tính khách quan. Từ 3.35M dòng ban đầu, hệ thống lọc lại còn **1,276,622 flows duy nhất**.
    *   Làm sạch dữ liệu: Loại bỏ các giá trị lỗi (`Inf`, `NaN`).
    *   **Stratified Split:** Chia dữ liệu theo tỷ lệ **80% Train / 20% Test** (Train: 1,021,296 | Test: 255,325).
*   **Kết quả:** `cic2017_train_80.csv` và `cic2017_test_20.csv`.

#### **Giai đoạn 4: Gom nhóm và Tiền xử lý (Grouping & Preprocessing)**
*   **File thực thi:** `src/data_preprocessing.py`
*   **Xử lý:**
    *   **Gom nhóm nhãn (Label Mapping):** Ánh xạ 15 loại nhãn chi tiết thành 7 danh mục chính: `BENIGN`, `DoS/DDoS`, `Exploitation/Rare`, `Brute Force`, `PortScan`, `Web Attack`, `Botnet`.
    *   **Xử lý mất cân bằng (SMOTE 10x):** Áp dụng kỹ thuật sinh dữ liệu nhân tạo cho các lớp thiểu số (ví dụ: Botnet từ 479 mẫu lên 4,790 mẫu).
*   **Kết quả:** Tập Train sau xử lý đạt ~1.18M dòng (tăng thêm 158,724 mẫu synthetic).

#### **Giai đoạn 5: Huấn luyện mô hình (Offline Training)**
*   **File thực thi:** `src/offline_training.py`
*   **Kiến trúc Zero-Touch:** Huấn luyện 2 tầng mô hình XGBoost:
    1.  **Active Model (Binary):** Chuyên trách phát hiện ATTACK vs BENIGN.
        *   **Hiệu năng:** Accuracy **99.9%**, FPR (Báo động giả) cực thấp **0.105%**.
    2.  **Classification Model (Multi-class):** Phân loại chi tiết 7 loại tấn công.
        *   **Hiệu năng:** F1-Score đạt từ **0.80 đến 1.00** cho các lớp (Botnet đạt 0.80, các lớp khác gần như tuyệt đối).
*   **Kết quả:** Các model `active_model.pkl`, `classification_model.pkl` và `label_encoder.pkl`.

#### **Giai đoạn 6: Triển khai và Phòng vệ (Deployment & Defense)**
*   **Các thành phần liên quan:**
    *   `src/realtime_extractor.py`: Trích xuất flows trực tiếp từ card mạng (ens33).
    *   `src/threat_evaluator.py`: Dự đoán mức độ đe dọa bằng mô hình đã huấn luyện.
    *   `src/autodefense_daemon.py`: Tự động kích hoạt chặn IP qua `iptables` khi phát hiện tấn công.

### **Tóm tắt quy trình**
> **Raw PCAP** $\rightarrow$ **Feature Extraction (NFStream)** $\rightarrow$ **Labeling** $\rightarrow$ **Purging (Unique Only)** $\rightarrow$ **Grouping & SMOTE** $\rightarrow$ **Dual-layer XGBoost** $\rightarrow$ **Real-time Defense**.