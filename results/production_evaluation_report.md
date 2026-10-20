# Báo Cáo Đánh Giá Hiệu Năng Mô Hình IDPS Sản Xuất (Production)

> **Thông tin thực nghiệm**
> - **Thời gian xuất báo cáo**: 2026-06-27 19:46:59
> - **Thuật toán sử dụng**: XGBoost
> - **Số lượng đặc trưng sử dụng**: **15 đặc trưng** (lọc theo ngưỡng 95% Cumulative Importance)
> - **Chiến lược cân bằng dữ liệu**: SMOTE x10 chỉ trên Train Fold
> - **Lớp nhãn bị lược bỏ**: `Exploitation / Rare` (do mẫu quá ít gây nhiễu)

## 1. Kết Quả Mô Hình Tầng 1: Active Model (Phân loại nhị phân)

Active Model có nhiệm vụ phát hiện nhanh xem một luồng mạng có phải là mã độc hại hay lành tính.

| Chỉ số đánh giá | Giá trị đạt được |
| :--- | :---: |
| **Độ chính xác (Accuracy)** | **99.442%** |
| **F1-Score (Weighted)** | **99.444%** |
| **Tỉ lệ báo động giả (FPR)** | **0.743%** |
| **Tỉ lệ bỏ sót tấn công (FNR)** | **0.082%** |
| **Thời gian phản hồi (Latency)** | **0.000261 ms/flow** |

### Ma trận nhầm lẫn nhị phân:

- **True Negative (TN - Lành tính đoán đúng)**: 235,996 luồng
- **True Positive (TP - Tấn công đoán đúng)**: 92,414 luồng
- **False Positive (FP - Báo động giả)**: 1,766 luồng
- **False Negative (FN - Bỏ sót)**: 76 luồng

## 2. Kết Quả Mô Hình Tầng 2: Classification Model (Phân loại đa lớp)

Classification Model có nhiệm vụ phân tích sâu các luồng mạng độc hại để xác định chính xác loại tấn công.

| Chỉ số đánh giá | Giá trị đạt được |
| :--- | :---: |
| **Độ chính xác (Accuracy)** | **99.433%** |
| **F1-Score (Macro)** | **98.489%** |
| **F1-Score (Weighted)** | **99.436%** |
| **Precision (Macro)** | **97.415%** |
| **Recall (Macro)** | **99.623%** |
| **Thời gian phản hồi (Latency)** | **0.001285 ms/flow** |

### Báo cáo phân loại chi tiết từng lớp nhãn:

```
              precision    recall  f1-score   support

      BENIGN       1.00      0.99      1.00    237762
      Botnet       0.97      1.00      0.99       147
 Brute Force       0.93      1.00      0.96      1277
    DoS/DDoS       0.97      1.00      0.99     58731
    PortScan       1.00      1.00      1.00     31911
  Web Attack       0.97      0.99      0.98       424

    accuracy                           0.99    330252
   macro avg       0.97      1.00      0.98    330252
weighted avg       0.99      0.99      0.99    330252
```

## 3. Danh Sách 15 Đặc Trưng Tối Ưu Cho XGBoost

Dưới đây là danh sách 15 đặc trưng đã được sử dụng để huấn luyện mô hình sản xuất, được sắp xếp A-Z:

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
