# Báo Cáo Tiến Độ Tuần 4

## Zero-Touch IDPS: Feature Extraction & Real-time ML Prediction

**Thời gian:** 24/04/2026 - 07/05/2026  
**Trạng thái:** Hoàn thành  

---

## 1. Giới thiệu

Tuần 4 tập trung vào việc thiết kế cấu trúc huấn luyện chính thức và tích hợp hệ thống **Feature Extraction** & **Real-time ML Prediction**. Trọng tâm là đóng gói "Bộ não ML" và triển khai các scripts lõi cho việc chạy thực tế:

| Script | Chức năng |
| :--- | :--- |
| `train_production_models.py` | Huấn luyện mô hình XGBoost Binary (tầng 1) và Multiclass (tầng 2) chính thức sử dụng bộ siêu tham số tối ưu từ Optuna. |
| `realtime_extractor.py` | Trích xuất 15 đặc trưng tối ưu thời gian thực từ live traffic hoặc PCAP bằng NFStream. |
| `threat_evaluator.py` | ML Inference Engine kết hợp song song cả 2 tầng mô hình để đưa ra quyết định cảnh báo hoặc block. |

---

## 2. Script 1: train_production_models.py

### 2.1 Mục đích
Huấn luyện hai mô hình XGBoost chính thức cho hệ thống IDPS theo kiến trúc phân tầng:
- **Tầng 1 (Active Model):** Phân loại nhị phân - phát hiện nhanh Lành tính (BENIGN) vs Tấn công (ATTACK).
- **Tầng 2 (Classification Model):** Phân loại đa lớp - phân tích chi tiết loại hình tấn công (6 nhãn).

### 2.2 Input/Output
- **Input:** `datasets/cic2017_train_80_preprocessed.csv`, `datasets/cic2017_test_20_preprocessed.csv` (Đã loại bỏ lớp `Exploitation / Rare`).
- **Output:** `models/active_model.pkl`, `models/classification_model.pkl`, `models/label_encoder.pkl`.

### 2.3 Danh sách 15 Đặc Trưng Tối Ưu Cho Mô Hình
Mô hình XGBoost sản xuất được cấu hình chạy trên 15 đặc trưng (sắp xếp A-Z):
1. `ACK Flag Count`
2. `Bwd IAT Max`
3. `Bwd IAT Std`
4. `Bwd Packet Length Mean`
5. `Bwd Packet Length Std`
6. `Bwd Packets/s`
7. `Flow Bytes/s`
8. `Fwd IAT Min`
9. `Fwd Packet Length Max`
10. `Fwd Packet Length Mean`
11. `Fwd Packet Length Std`
12. `PSH Flag Count`
13. `Packet Length Mean`
14. `Total Fwd Packets`
15. `Total Length of Fwd Packets`

### 2.4 Classes được mã hóa (6 Lớp)
```
BENIGN       → 0
Botnet       → 1
Brute Force  → 2
DoS/DDoS     → 3
PortScan     → 4
Web Attack   → 5
```

### 2.5 Siêu tham số tối ưu (XGBoost)
Bộ tham số tối ưu thu được từ Bayesian Optimization (Optuna 30 trials) được áp dụng trực tiếp:
- `max_depth`: 7
- `learning_rate`: 0.09735
- `n_estimators`: 114
- `subsample`: 0.8322
- `colsample_bytree`: 0.8021
- `tree_method`: `hist` (giúp huấn luyện nhanh trên tập dữ liệu lớn)
- `random_state`: 42

---

## 3. Script 2: realtime_extractor.py

### 3.1 Mục đích
Trích xuất vector đặc trưng thời gian thực (15 đặc trưng) từ luồng gói tin sống. Đóng vai trò làm cầu nối chuyển đổi dữ liệu thô từ card mạng sang định dạng tương thích với mô hình đã huấn luyện.

### 3.2 Cấu trúc hoạt động
- Sử dụng thư viện `nfstream` cấu hình `statistical_analysis=True`.
- Xây dựng 2 NFStream Plugins tùy chỉnh:
  - `TCPWindowPlugin`: Trích xuất kích thước TCP Window Size của chiều forward và backward để làm fingerprint cho hệ điều hành/kịch bản kết nối.
  - `ConnectionRatePlugin` (kết hợp `ConnectionTracker` dùng sliding window 10s): Đo đạc tần suất kết nối từ một IP đến một cổng dịch vụ để phát hiện hành vi PortScan hoặc Brute Force.
- Trình trích xuất tự động nhân các chỉ số thời gian với 1000 để chuyển đổi đơn vị từ mili-giây (NFStream) sang vi-giây (CIC-IDS-2017), đảm bảo độ tương thích đặc trưng 100%.

---

## 4. Script 3: threat_evaluator.py

### 4.1 Mục đích
ML Inference Engine thực hiện dự đoán thời gian thực cho từng luồng mạng thông qua **Chiến lược Dự đoán Song song (Dual Inference Strategy)**:
- Nhận vector 15 đặc trưng đầu vào, kiểm tra tính hợp lệ của shape `(15,)` và xử lý các giá trị NaN/Inf bất thường.
- Chạy song song qua **Active Model** (Binary: Lành tính vs Tấn công) và **Classification Model** (Multiclass: Phân loại 6 nhãn).
- Quyết định cuối cùng dựa trên điểm tin cậy cao nhất (`MAX` strategy) giữa xác suất tấn công của mô hình nhị phân và `1.0 - P(BENIGN)` của mô hình đa lớp để tăng độ nhạy phát hiện.

---

## 5. Kết quả Huấn luyện & Đánh giá trên Hold-out Test 20%

### 5.1 Tầng 1: Active Model (Binary Classifier)
- **Độ chính xác (Accuracy):** 99.403%
- **F1-Score (Weighted):** 99.407%
- **Tỷ lệ báo động giả (FPR):** 0.700%
- **Tỷ lệ bỏ sót (FNR):** 0.120%
- **Độ trễ phản hồi (Latency):** 0.000287 ms/flow (0.29 µs)

### 5.2 Tầng 2: Classification Model (Multi-class Classifier)
- **Độ chính xác (Accuracy):** 99.409%
- **F1-Score (Macro):** 97.486%
- **F1-Score (Weighted):** 99.413%
- **Recall (Macro):** 98.475%
- **Độ trễ phản hồi (Latency):** 0.001276 ms/flow (1.28 µs)

**Báo cáo phân loại chi tiết:**
```
              precision    recall  f1-score   support

       BENIGN       1.00      0.99      1.00    238158
       Botnet       0.99      1.00      1.00       120
  Brute Force       0.93      1.00      0.96      1277
     DoS/DDoS       0.97      1.00      0.98     49994
     PortScan       0.93      0.93      0.93        42
   Web Attack       0.97      0.99      0.98       382
```

---

## 6. Danh sách các file hoàn thành trong Tuần 4
1. [train_production_models.py](file:///c:/IDPS/src/train_production_models.py): Huấn luyện mô hình sản xuất.
2. [realtime_extractor.py](file:///c:/IDPS/src/realtime_extractor.py): Trích xuất đặc trưng thời gian thực (15 features).
3. [threat_evaluator.py](file:///c:/IDPS/src/threat_evaluator.py): Đánh giá mối đe dọa (15 features).
4. [auto_firewall.py](file:///c:/IDPS/src/auto_firewall.py): Tự động ngăn chặn bằng iptables.
5. [ip_manager.py](file:///c:/IDPS/src/ip_manager.py): Quản lý danh sách Blacklist/Whitelist.
6. [autodefense_daemon.py](file:///c:/IDPS/src/autodefense_daemon.py): Daemon cốt lõi điều phối toàn bộ luồng xử lý.
