# Report: CIC-IDS-2017 Dataset Splitting (80% Train / 20% Test)

**Ngày thực hiện:** 2026-04-29
**Trạng thái:** Hoàn thành (✅ DONE)
**Mục tiêu:** Chia 8 file CSV gốc từ bộ dữ liệu CIC-IDS-2017 thành tập Train (80%) và Test (20%) theo phương pháp Stratified Split (giữ nguyên tỷ lệ từng loại tấn công), chỉ lọc lấy Top 30 features quan trọng.

---

## 1. Thông tin đầu vào (Input)

- **Thư mục gốc:** `f:\IDPS\datasets\MachineLearningCSV\MachineLearningCVE\`
- **Danh sách file:** 8 file CSV chia theo ngày làm việc (Monday - Friday).
- **Cấu hình đặc trưng:** Top 30 features được định nghĩa trong `datasets/top30features.txt`.
- **Yêu cầu kỹ thuật:**
    1. Gộp tất cả 8 file CSV gốc.
    2. Lọc Top 30 features quan trọng + cột `Label`.
    3. Loại bỏ các dòng chứa giá trị lỗi (`Inf`, `NaN`) và các dòng **TRÙNG LẶP** (`drop_duplicates`) để tránh rò rỉ dữ liệu.
    4. Chia Stratified Split 80/20 theo nhãn `Label`.
---

## 2. Quá trình thực hiện và Lệnh (Commands)

### Bước 1: Phân tích phân bố Label gốc
Sử dụng lệnh Python để kiểm tra số lượng mẫu của từng loại tấn công trước khi xử lý:
```powershell
python -X utf8 -c "import pandas as pd, glob; files = glob.glob(r'f:\IDPS\datasets\MachineLearningCSV\MachineLearningCVE\*.csv'); dfs = [pd.read_csv(f, low_memory=False, encoding='latin-1') for f in files]; df = pd.concat(dfs, ignore_index=True); df.columns = df.columns.str.strip(); print(df['Label'].value_counts().to_string())"
```

### Bước 2: Tạo script xử lý `split_train_test.py`
Script được thiết kế để đọc tuần tự, làm sạch tên cột, lọc feature và thực hiện chia tách bằng `sklearn.model_selection.train_test_split`.
- **File:** `f:\IDPS\datasets\split_train_test.py`

### Bước 3: Thực thi Script
Lệnh chạy script chính thức:
```powershell
python -X utf8 "f:\IDPS\datasets\split_train_test.py"
```

---

## 3. Kết quả đầu ra (Output & Logs)

### Nhật ký thực thi (Execution Log)
```text
[1/6] Đang đọc 8 file CSV...
    ✓ Monday-WorkingHours.pcap_ISCX.csv: 529,918 dòng
    ... (tất cả 8 file)
    → Tổng sau gộp: 2,830,743 dòng, 79 cột

[2/6] Lọc Top 30 features + Label...
    → Giữ lại 30 features + 1 cột Label

[3/6] Loại bỏ dòng lỗi (Inf/NaN) và Trùng lặp (Duplicates)...
    → Đã loại bỏ 315,381 dòng (Lỗi/Trùng lặp)
    → Còn lại (Unique patterns): 2,515,362 dòng

[5/6] Đang chia Train/Test (80/20) stratified theo Label...
    → Train: 2,012,289 dòng (80.0%)
    → Test:  503,073 dòng (20.0%)

[6/6] Đang lưu file CSV...
    ✓ Train: f:\IDPS\datasets\cic2017_train_80.csv (352.1 MB)
    ✓ Test:  f:\IDPS\datasets\cic2017_test_20.csv (88.0 MB)
```

### Xác nhận tỷ lệ phân bố (Stratification Verification)
Tỷ lệ 80/20 được đảm bảo chính xác cho tất cả các loại tấn công:

| Loại tấn công | Train (80%) | Test (20%) | Tỷ lệ Train |
| :--- | :--- | :--- | :--- |
| **BENIGN** | 1,671,783 | 417,947 | 80.0% |
| **DoS Hulk** | 138,277 | 34,569 | 80.0% |
| **DDoS** | 102,411 | 25,603 | 80.0% |
| **PortScan** | 72,555 | 18,139 | 80.0% |
| **DoS GoldenEye** | 8,229 | 2,057 | 80.0% |
| **FTP-Patator** | 4,745 | 1,186 | 80.0% |
| **DoS slowloris** | 4,221 | 1,055 | 80.0% |
| **DoS Slowhttptest** | 4,182 | 1,046 | 80.0% |
| **SSH-Patator** | 2,575 | 644 | 80.0% |
| **Bot** | 1,558 | 390 | 80.0% |
| **Web Attack - Brute Force** | 1,176 | 294 | 80.0% |
| **Web Attack - XSS** | 522 | 130 | 80.1% |
| **Infiltration** | 29 | 7 | 80.6% |
| **Web Attack - Sql Injection** | 17 | 4 | 81.0% |
| **Heartbleed** | 9 | 2 | 81.8% |

---

## 4. Tổng kết
- Hệ thống đã sẵn sàng 2 file dữ liệu sạch đã được gán nhãn và chia tách khoa học: `\IDPS\datasets\cic2017_train_80.csv` và `\IDPS\datasets\cic2017_test_20.csv`
- Dữ liệu này có thể được đưa vào `src/data_preprocessing.py` để gom nhóm nhãn, SMOTE 10x & Test Set Mapping.

