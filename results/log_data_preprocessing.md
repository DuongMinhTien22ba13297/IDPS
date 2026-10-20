# Report: Data Preprocessing — Gom nhóm nhãn, SMOTE 10x & Test Set Mapping

**Ngày tạo:** 2026-04-30
**Ngày cập nhật:** 2026-04-30
**Trạng thái:** Hoàn thành (✅ DONE)
**Script:** `src/data_preprocessing.py`

---

## 1. Lịch sử thay đổi

| Phiên bản | Ngày | Nội dung |
|:---|:---|:---|
| v1.0 | 2026-04-30 | Tạo mới: xử lý tập train (mapping + SMOTE 10x) |
| v1.1 | 2026-04-30 | Bổ sung: xử lý tập test (chỉ mapping, không SMOTE) |

---

## 2. Chức năng

Tiền xử lý đồng thời 2 tập dữ liệu CIC-IDS-2017 đã chia sẵn:

**Tập Train:**
1. **Gom nhóm nhãn (Label Mapping):** Gom 15 nhãn tấn công gốc thành 6 danh mục chính + BENIGN.
2. **SMOTE Oversampling 10x:** Tăng số mẫu cho 4 lớp thiểu số.
3. **Không undersample BENIGN** — xử lý mất cân bằng còn lại bằng `class_weight` trong XGBoost ở bước `offline_training.py`.

**Tập Test:**
1. **Chỉ mapping nhãn** — dùng cùng bảng mapping với train.
2. **Không SMOTE** — test set phản ánh phân bố thực tế, không được augment.

---

## 3. Input / Output

| Mục | File | Kích thước | Số dòng |
|:---|:---|---:|---:|
| **Train Input** | `datasets/cic2017_train_80.csv` | 352.1 MB | 2,012,289 |
| **Train Output** | `datasets/cic2017_train_80_preprocessed.csv` | 375.60 MB | 2,107,968 |
| **Test Input** | `datasets/cic2017_test_20.csv` | 88.0 MB | 503,073 |
| **Test Output** | `datasets/cic2017_test_20_preprocessed.csv` | 88.10 MB | 503,073 |

Các file input đã được xử lý trước đó (xem `log_dataset_splitting.md`):
- Gộp 8 file CSV gốc từ CIC-IDS-2017
- Lọc Top 30 features + Label
- Loại bỏ Inf/NaN
- Stratified Split 80/20

---

## 4. Bảng Mapping nhãn (dùng chung cho train và test)

| Nhãn gốc | → Danh mục |
|:---|:---|
| BENIGN | **BENIGN** |
| DoS Hulk, DDoS, DoS GoldenEye, DoS slowloris, DoS Slowhttptest | **DoS/DDoS** |
| PortScan | **PortScan** |
| FTP-Patator, SSH-Patator | **Brute Force** |
| Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection | **Web Attack** |
| Bot | **Botnet** |
| Infiltration, Heartbleed | **Exploitation / Rare** |

---

## 5. Chiến lược Resampling

| Danh mục | Train | Test | Lý do |
|:---|:---|:---|:---|
| BENIGN | Giữ nguyên | Giữ nguyên | Xử lý bằng `class_weight` trong XGBoost |
| DoS/DDoS | Giữ nguyên | Giữ nguyên | Lớp attack lớn nhất |
| PortScan | Giữ nguyên | Giữ nguyên | 127K mẫu — đủ lớn |
| Brute Force | SMOTE 10x | Giữ nguyên | Tăng representation cho minority |
| Web Attack | SMOTE 10x | Giữ nguyên | Tăng representation cho minority |
| Botnet | SMOTE 10x | Giữ nguyên | Tăng representation cho minority |
| Exploitation / Rare | SMOTE 10x | Giữ nguyên | Kết hợp Suricata rules |

**SMOTE parameters:** `k_neighbors=5`, `random_state=42`

---

## 6. Lệnh thực thi

```powershell
# Cài đặt dependency (nếu chưa có)
pip install imbalanced-learn

# Chạy script (xử lý cả train và test)
python -X utf8 src/data_preprocessing.py
```

---

## 7. Log thực thi

```text
=================================================================
 ZERO-TOUCH IDPS — PREPROCESSING: GOM NHÓM NHÃN + SMOTE 10x
=================================================================

[TRAIN SET]
[1/3] Đang đọc file CSV...
  → Đã đọc: 2,012,289 dòng × 31 cột
  → Đang gom nhóm nhãn (Mapping labels)...

  Phân bố nhãn sau khi gom nhóm:
    BENIGN                    :  1,671,783 (83.08%)
    DoS/DDoS                  :    257,320 (12.79%)
    PortScan                  :     72,555 ( 3.61%)
    Brute Force               :      7,320 ( 0.36%)
    Web Attack                :      1,715 ( 0.09%)
    Botnet                    :      1,558 ( 0.08%)
    Exploitation / Rare       :         38 ( 0.00%)
    TỔNG                      :  2,012,289

[2/3] Đang thực hiện SMOTE Oversampling...
  → Brute Force: 7,320 → 73,200 (×10)
  → Web Attack: 1,715 → 17,150 (×10)
  → Botnet: 1,558 → 15,580 (×10)
  → Exploitation / Rare: 38 → 380 (×10)

  → k_neighbors = 5 (auto-adjusted, min minority samples = 38)
  → Đang chạy SMOTE...

  Phân bố nhãn SAU khi SMOTE:
    BENIGN                    :  1,671,783 (79.31%)
    DoS/DDoS                  :    257,320 (12.21%)
    Brute Force               :     73,200 ( 3.47%) (SMOTE)
    PortScan                  :     72,555 ( 3.44%)
    Web Attack                :     17,150 ( 0.81%) (SMOTE)
    Botnet                    :     15,580 ( 0.74%) (SMOTE)
    Exploitation / Rare       :        380 ( 0.02%) (SMOTE)
    TỔNG                      :  2,107,968
    → Thêm 95,679 mẫu synthetic

[3/3] Đang lưu file train...
  → Output: F:\IDPS\datasets\cic2017_train_80_preprocessed.csv
  → Kích thước: 375.60 MB
  → Số dòng: 2,107,968

[TEST SET]

=================================================================
 XỬ LÝ TẬP TEST (chỉ mapping nhãn, không SMOTE)
=================================================================
[1/3] Đang đọc file CSV...
  → Đã đọc: 503,073 dòng × 31 cột
  → Đang gom nhóm nhãn (Mapping labels)...

  Phân bố nhãn sau khi gom nhóm:
    BENIGN                    :    417,947 (83.08%)
    DoS/DDoS                  :     64,330 (12.79%)
    PortScan                  :     18,139 ( 3.61%)
    Brute Force               :      1,830 ( 0.36%)
    Web Attack                :        428 ( 0.09%)
    Botnet                    :        390 ( 0.08%)
    Exploitation / Rare       :          9 ( 0.00%)
    TỔNG                      :    503,073

[2/2] Đang lưu file test đã xử lý...
  → Output: F:\IDPS\datasets\cic2017_test_20_preprocessed.csv
  → Kích thước: 88.10 MB
  → Số dòng: 503,073

=================================================================
 HOÀN TẤT PREPROCESSING (TRAIN + TEST)!
=================================================================
```

---

## 8. Kết quả

### Tập Train: Phân bố trước và sau SMOTE

| Danh mục | Trước | Sau SMOTE | Thay đổi |
|:---|---:|---:|:---|
| BENIGN | 1,671,783 (83.08%) | 1,671,783 (79.31%) | Giữ nguyên |
| DoS/DDoS | 257,320 (12.79%) | 257,320 (12.21%) | Giữ nguyên |
| PortScan | 72,555 (3.61%) | 72,555 (3.44%) | Giữ nguyên |
| Brute Force | 7,320 (0.36%) | 73,200 (3.47%) | +65,880 synthetic |
| Web Attack | 1,715 (0.09%) | 17,150 (0.81%) | +15,435 synthetic |
| Botnet | 1,558 (0.08%) | 15,580 (0.74%) | +14,022 synthetic |
| Exploitation / Rare | 38 (0.00%) | 380 (0.02%) | +342 synthetic |
| **TỔNG** | **2,012,289** | **2,107,968** | **+95,679** |

### Tập Test: Phân bố sau mapping (không SMOTE)

| Danh mục | Số mẫu | Tỷ lệ |
|:---|---:|---:|
| Danh mục | Số mẫu | Tỷ lệ |
|:---|---:|---:|
| BENIGN | 417,947 | 83.08% |
| DoS/DDoS | 64,330 | 12.79% |
| PortScan | 18,139 | 3.61% |
| Brute Force | 1,830 | 0.36% |
| Web Attack | 428 | 0.09% |
| Botnet | 390 | 0.08% |
| Exploitation / Rare | 9 | 0.00% |
| **TỔNG** | **503,073** | **100%** |

> Tỷ lệ phân bố test giống hệt train (stratified split 80/20) — xác nhận tính nhất quán.

---

## 9. Kết luận

- ✅ Gom nhóm thành công 15 nhãn gốc → 7 danh mục (6 attack + BENIGN) cho cả train và test.
- ✅ SMOTE 10x cho 4 lớp thiểu số trên tập train, thêm 95,679 mẫu synthetic.
- ✅ Tập test **không bị augment** — phản ánh đúng phân bố thực tế, đảm bảo evaluation fair.
- ✅ Cùng hàm `map_label()` cho cả train và test — đảm bảo mapping nhất quán, không bao giờ lệch.
- ✅ Không có data leakage (SMOTE chỉ áp dụng trên train, test đã tách trước).
- ⚠️ BENIGN vẫn chiếm ~76% trên train — cần `sample_weight='balanced'` khi training XGBoost trong `offline_training.py`.
- ⚠️ Exploitation / Rare trên test chỉ có 9 mẫu — cần Suricata rules để bù đắp ở production.
- 📌 Cả hai file output sẵn sàng cho bước tiếp theo:`src/evaluate_fn.py` và `src/offline_training.py`.
