"""
=============================================================================
Tên file   : split_train_test.py
Chức năng  : Chia bộ dữ liệu CIC-IDS-2017 thành 80% Train / 20% Test
             theo phương pháp Stratified Split (chia theo tỷ lệ từng loại
             tấn công, bao gồm cả BENIGN).
Input      : Thư mục datasets/MachineLearningCSV/MachineLearningCVE/ (8 file CSV gốc)
Output     :
   - datasets/cic2017_train_80.csv  (80% mỗi loại tấn công)
   - datasets/cic2017_test_20.csv   (20% mỗi loại tấn công)
Lưu ý     : 
   1. Chỉ giữ lại Top 57 features + cột Label.
   2. Loại bỏ các dòng chứa Inf / NaN.
   3. Loại bỏ toàn bộ dòng TRÙNG LẶP (drop_duplicates) trước khi split 
      để đảm bảo tính khách quan và tránh rò rỉ dữ liệu (data leakage).
=============================================================================
"""

import os
import sys
import glob
import gc
import time

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Đảm bảo in ra terminal đúng định dạng UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# =============================================================================
# CẤU HÌNH
# =============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

INPUT_FILE   = os.path.join(SCRIPT_DIR, "cic2017_nfs_labeled_57features.csv")
OUTPUT_TRAIN = os.path.join(SCRIPT_DIR, "cic2017_train_80.csv")
OUTPUT_TEST  = os.path.join(SCRIPT_DIR, "cic2017_test_20.csv")

TEST_SIZE    = 0.2
RANDOM_STATE = 42

# Các cột định danh cần loại bỏ trước khi chia dữ liệu (để tránh data leakage / overfitting)
COLS_TO_DROP = [
    'Source IP', 'Destination IP', 'Timestamp', 'Flow ID', 'Destination Port',
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms'
]

LABEL_COL = "Label"

# =============================================================================
# HÀM CHÍNH
# =============================================================================

def main():
    start_time = time.time()

    print("=" * 70)
    print("  CHIA BỘ DỮ LIỆU CIC-IDS-2017: 80% TRAIN / 20% TEST")
    print("  (Stratified Split theo từng loại tấn công)")
    print("=" * 70)

    # ------------------------------------------------------------------
    # 1. Đọc file CSV đã gán nhãn
    # ------------------------------------------------------------------
    if not os.path.exists(INPUT_FILE):
        print(f"[-] Không tìm thấy file {INPUT_FILE}. Hãy chạy trích xuất và gán nhãn trước!")
        return

    print(f"\n[1/6] Đang đọc file CSV: {INPUT_FILE}...")
    chunks_benign = []
    chunks_attack = []
    cols_to_drop_set = set(c.strip() for c in COLS_TO_DROP)
    
    rows_total_raw = 0
    
    for chunk in pd.read_csv(INPUT_FILE, chunksize=100000, low_memory=False):
        # Xóa khoảng trắng thừa ở tên cột để dễ xử lý
        chunk.columns = chunk.columns.str.strip()
        rows_total_raw += len(chunk)
        
        # Bỏ cột metadata sớm
        cols_present = [c for c in chunk.columns if c in cols_to_drop_set]
        if cols_present:
            chunk.drop(columns=cols_present, inplace=True)
            
        # Ép kiểu numeric cho các cột features ngay để giảm memory (dùng float32)
        feature_cols = [c for c in chunk.columns if c != LABEL_COL]
        for col in feature_cols:
            chunk[col] = pd.to_numeric(chunk[col], errors='coerce').astype('float32')
            
        # Thay Inf → NaN rồi drop ngay trên chunk
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)
        
        # Làm sạch cột Label trước khi tách dữ liệu
        chunk[LABEL_COL] = chunk[LABEL_COL].astype(str).str.strip()
        
        # Tách BENIGN và Attack ngay trên chunk
        c_benign = chunk[chunk[LABEL_COL].str.upper() == 'BENIGN']
        c_attack = chunk[chunk[LABEL_COL].str.upper() != 'BENIGN']
        
        # Drop duplicates cho BENIGN ngay trên chunk để giảm dung lượng sớm
        c_benign = c_benign.drop_duplicates()
        
        chunks_benign.append(c_benign)
        chunks_attack.append(c_attack)
        
        del chunk, c_benign, c_attack
        gc.collect()
            
    print(f"    → Đang gộp các chunks BENIGN...")
    df_benign = pd.concat(chunks_benign, ignore_index=True)
    del chunks_benign
    gc.collect()
    
    print(f"    → Đang gộp các chunks Attack...")
    df_attacks = pd.concat(chunks_attack, ignore_index=True)
    del chunks_attack
    gc.collect()
    
    print(f"    → Tổng số dòng thô ban đầu: {rows_total_raw:,}")

    # ------------------------------------------------------------------
    # 2. Loại bỏ cột định danh (Metadata) để tránh Overfitting
    # ------------------------------------------------------------------
    print(f"\n[2/6] Lọc bỏ các cột định danh (Metadata) (Đã thực hiện sớm trên chunk)...")
    print(f"    → Giữ lại {df_benign.shape[1] - 1} features + 1 cột Label")

    # ------------------------------------------------------------------
    # 3. Loại bỏ dòng Inf / NaN & Trùng lặp (Drop Duplicates)
    # ------------------------------------------------------------------
    print(f"\n[3/6] Loại bỏ trùng lặp lần cuối trên lớp BENIGN...")

    rows_benign_before = len(df_benign)
    df_benign.drop_duplicates(inplace=True)
    rows_benign_after = len(df_benign)
    
    print(f"    → Lớp BENIGN: Giảm từ {rows_benign_before:,} xuống còn {rows_benign_after:,} dòng.")
    print(f"    → Giữ nguyên toàn bộ {len(df_attacks):,} dòng dữ liệu tấn công.")
    
    df_all = pd.concat([df_benign, df_attacks], ignore_index=True)
    df_all.reset_index(drop=True, inplace=True)

    rows_removed = rows_total_raw - len(df_all)
    print(f"    → Tổng đã loại bỏ {rows_removed:,} dòng (Lỗi/Trùng lặp BENIGN)")
    print(f"    → Còn lại để chia train/test: {len(df_all):,} dòng")

    # ------------------------------------------------------------------
    # 4. Thống kê phân bố Label TRƯỚC split
    # ------------------------------------------------------------------
    print(f"\n[4/6] Phân bố Label (Unique) trước khi split:")
    label_counts = df_all[LABEL_COL].value_counts()
    print(f"    {'Label':<35} {'Số lượng':>10}   {'Tỷ lệ':>7}")
    print(f"    {'─' * 55}")
    for label, count in label_counts.items():
        pct = count / len(df_all) * 100
        print(f"    {label:<35} {count:>10,}   {pct:>6.2f}%")
    print(f"    {'─' * 55}")
    print(f"    {'TỔNG':<35} {len(df_all):>10,}   100.00%")

    # ------------------------------------------------------------------
    # 5. Stratified Split 80/20
    # ------------------------------------------------------------------
    print(f"\n[5/6] Đang chia Train/Test (80/20) stratified theo Label...")

    # Lọc bỏ các class có ít hơn 2 mẫu để tránh lỗi ValueError của train_test_split
    valid_labels = label_counts[label_counts >= 2].index
    if len(valid_labels) < len(label_counts):
        invalid_labels = label_counts[label_counts < 2].index.tolist()
        print(f"    [!] Cảnh báo: Loại bỏ các nhãn có ít hơn 2 mẫu (không thể stratify): {invalid_labels}")
        df_all = df_all[df_all[LABEL_COL].isin(valid_labels)]

    df_train, df_test = train_test_split(
        df_all,
        test_size=TEST_SIZE,
        stratify=df_all[LABEL_COL],
        random_state=RANDOM_STATE
    )

    print(f"    → Train: {len(df_train):,} dòng")
    print(f"    → Test:  {len(df_test):,} dòng")

    del df_all
    gc.collect()

    # ------------------------------------------------------------------
    # 6. Lưu file CSV & xác nhận tỷ lệ
    # ------------------------------------------------------------------
    print(f"\n[6/6] Đang lưu file CSV...")

    df_train.to_csv(OUTPUT_TRAIN, index=False)
    train_size_mb = os.path.getsize(OUTPUT_TRAIN) / (1024 * 1024)
    print(f"    ✓ Train: {OUTPUT_TRAIN} ({train_size_mb:.1f} MB)")

    df_test.to_csv(OUTPUT_TEST, index=False)
    test_size_mb = os.path.getsize(OUTPUT_TEST) / (1024 * 1024)
    print(f"    ✓ Test:  {OUTPUT_TEST} ({test_size_mb:.1f} MB)")

    # Xác nhận tỷ lệ mỗi loại attack trong train vs test
    train_counts = df_train[LABEL_COL].value_counts()
    test_counts  = df_test[LABEL_COL].value_counts()

    print(f"\n{'─' * 75}")
    print(f"  XÁC NHẬN TỶ LỆ PHÂN BỐ TỪNG LOẠI TẤN CÔNG SAU KHI SPLIT")
    print(f"{'─' * 75}")
    print(f"  {'Label':<30} {'Train':>8} {'Test':>8} {'Train%':>8} {'Test%':>8}")
    print(f"  {'─' * 65}")

    all_labels = sorted(set(list(train_counts.index) + list(test_counts.index)))
    for label in all_labels:
        tr = train_counts.get(label, 0)
        te = test_counts.get(label, 0)
        total = tr + te
        tr_pct = tr / total * 100 if total > 0 else 0
        te_pct = te / total * 100 if total > 0 else 0
        print(f"  {label:<30} {tr:>8,} {te:>8,} {tr_pct:>7.1f}% {te_pct:>7.1f}%")

    elapsed = time.time() - start_time
    print(f"\n{'=' * 70}")
    print(f"  HOÀN TẤT sau {elapsed:.1f} giây!")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
