# Báo cáo Tiến độ Tuần 3: Zero-Touch IDPS Project

**Thời gian:** 17/04/2026 - 23/04/2026  
**Người thực hiện:** Antigravity (AI Coding Assistant)  
**Trạng thái:** Hoàn thành tối ưu hóa và xác định cấu hình mô hình ML (Phase 1.5).

---

## 1. Mục tiêu Tuần 3
Trong tuần này, trọng tâm của dự án là xây dựng và hoàn thiện quy trình huấn luyện, tối ưu hóa siêu tham số cho "Bộ não ML" (Offline Training) với các mục tiêu:
- **Ngăn chặn rò rỉ dữ liệu (Data Leakage)**: Thiết lập quy trình chọn lọc đặc trưng động và cân bằng dữ liệu nghiêm ngặt trong từng fold của K-Fold Cross-Validation.
- **Tối ưu hóa siêu tham số (Hyperparameter Tuning)**: Áp dụng phương pháp tối ưu hóa Bayesian (sử dụng thư viện Optuna) để tìm cấu hình siêu tham số và số lượng đặc trưng ($k$) tối ưu cho 3 thuật toán ứng viên: **XGBoost**, **LightGBM**, và **Random Forest**.
- **Đánh giá và chốt mô hình**: So sánh hiệu năng F1-Macro và độ trễ phản hồi (latency/flow) trên tập kiểm thử Hold-out Test 20% độc lập để lựa chọn mô hình sản xuất tối ưu nhất.

---

## 2. Nội dung Thực hiện

### 2.1. Chuẩn bị Dữ liệu & Cắt tập dữ liệu
- **Dataset**: `cic2017_train_80_preprocessed.csv` (80% làm tập Train/Tuning) và `cic2017_test_20_preprocessed.csv` (20% làm tập Hold-out Test độc lập) sau khi đã làm sạch và xóa trùng lặp dữ liệu (Duplicate Leakage).
- **Candidate Pool**: 50 đặc trưng tương thích hoàn toàn với trình trích xuất thời gian thực `nfstream`.
- **Nhãn phân loại**: 6 nhãn chính (BENIGN, Botnet, Brute Force, DoS/DDoS, PortScan, Web Attack). Nhãn `Exploitation / Rare` (Infiltration, Heartbleed) đã được loại bỏ hoàn toàn do số lượng mẫu quá ít, gây mất cân bằng nặng và nhiễu mô hình.

### 2.2. Quy trình Tối ưu hóa Bayesian & Chống rò rỉ dữ liệu (Anti-Leakage CV)
Chúng tôi triển khai script `optimize_models_bayesian.py` sử dụng **Optuna** chạy **30 trials** cho mỗi thuật toán với chiến lược **Stratified 5-Fold Cross-Validation** khép kín trong từng fold:
1. **Fold Splitting**: Tách biệt hoàn toàn Train Fold và Validation Fold.
2. **Dynamic Feature Selection**: Huấn luyện một Base Model trên Train Fold để tính toán Feature Importance. Sắp xếp đặc trưng và chọn số lượng đặc trưng $k$ tối thiểu để đạt **ngưỡng tích lũy 95%** độ quan trọng. Cắt giảm đặc trưng trên cả Train Fold và Validation Fold theo danh sách này.
3. **SMOTE x10 Fold-Level**: Áp dụng thuật toán SMOTE nhân 10 lần mẫu (x10) cho các lớp thiểu số (`Brute Force`, `Web Attack`, `Botnet`, `PortScan`) **chỉ trên Train Fold đã cắt giảm**. Tập Validation Fold được giữ nguyên bản 100% để chấm điểm khách quan.
4. **Model Tuning**: Huấn luyện mô hình chính và tối ưu hóa điểm số **F1-Macro Avg** trên Validation Fold.

---

## 3. Kết quả Đạt được (Đánh giá trên Hold-out Test 20%)

Dưới đây là bảng so sánh hiệu năng thực tế của 3 mô hình tối ưu sau khi chạy Bayesian Optimization:

| Mô Hình | Số Lượng Features (k) | F1-Macro | F1-Weighted | Precision-Macro | Recall-Macro | Latency (ms/flow) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LIGHTGBM** | 5 | 86.58% | 98.95% | 81.74% | 96.11% | 0.003392 (3.39 µs) |
| **XGBOOST** | **15** | **97.56%** | **99.41%** | **96.33%** | **98.86%** | **0.001397 (1.40 µs)** |
| **RANDOM FOREST** | 22 | 91.62% | 99.33% | 88.82% | 97.33% | 0.001714 (1.71 µs) |

### Nhận xét quan trọng:
- **XGBoost (15 features)** giành chiến thắng tuyệt đối với điểm **F1-Macro đạt 97.56%** và tốc độ phản hồi cực nhanh chỉ **1.40 µs/flow** (0.001397 ms). Đây là mô hình được lựa chọn để đưa vào sản xuất cho hệ thống Zero-Touch IDPS.
- **Random Forest (22 features)** cho kết quả khá tốt (F1-Macro 91.62%) nhưng yêu cầu số lượng đặc trưng nhiều hơn và độ trễ cao hơn XGBoost.
- **LightGBM (5 features)** tối giản hóa số đặc trưng cực tốt (chỉ dùng 5 features) và có tốc độ huấn luyện nhanh, nhưng điểm số F1-Macro thấp hơn (86.58%) do mất mát thông tin khi cắt giảm quá sâu.

---

## 4. Phân tích chi tiết theo loại tấn công (Mô hình sản xuất XGBoost)

Mô hình XGBoost (15 features) đạt khả năng nhận diện xuất sắc trên tất cả các kịch bản tấn công kiểm thử thực tế:
- **BENIGN (Lành tính)**: Precision 100%, Recall 99%, F1-Score 1.00 (Chỉ có ~1% báo động giả).
- **DoS/DDoS**: Precision 97%, Recall 100%, F1-Score 0.98.
- **Brute Force**: Precision 93%, Recall 100%, F1-Score 0.96.
- **Web Attack**: Precision 97%, Recall 99%, F1-Score 0.98 (Đã cải thiện cực mạnh nhờ SMOTE x10).
- **Botnet**: Precision 100%, Recall 100%, F1-Score 1.00.
- **PortScan**: Precision 91%, Recall 95%, F1-Score 0.93.

---

## 5. Kết luận & Kế hoạch Tuần 4

### Kết luận
Tuần 3 đã hoàn thành xuất sắc mục tiêu tối ưu hóa và chống rò rỉ dữ liệu. Chúng ta đã xác định được mô hình tối ưu nhất là **XGBoost** chạy trên bộ **15 đặc trưng** quan trọng nhất. Cấu hình này đáp ứng hoàn hảo tiêu chuẩn bảo mật: **F1-Macro cao (>97%)** và **Độ trễ thấp (<1.5 µs)** để triển khai thời gian thực.

### Kế hoạch Tuần 4 (Phase 2)
1. **Lưu trữ mô hình (Model Packaging)**: Đóng gói và lưu trữ các file mô hình `active_model.pkl` (Binary), `classification_model.pkl` (Multi-class), và `label_encoder.pkl`.
2. **Triển khai Real-time Sniffer**: Viết module `realtime_extractor.py` tích hợp `nfstream` cấu hình lấy đúng 15 đặc trưng tối ưu.
3. **Phát triển Daemon**: Hoàn thiện `autodefense_daemon.py` làm trung tâm điều phối, nạp live flow từ sniffer đưa vào đánh giá bằng mô hình ML.

---
**Tài liệu & Artifacts liên quan:**
- Báo cáo thực nghiệm tối ưu hóa: `results/bayesian_optimization_report.txt`
- Báo cáo kiểm toán Data Leakage: `results/methodology_leakage_report.md`
- Script thực hiện Bayesian Optimization: `src/optimize_models_bayesian.py`
