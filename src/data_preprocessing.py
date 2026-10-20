"""
=============================================================================
Tên file   : data_preprocessing.py
Mục tiêu   : Chuẩn bị dữ liệu cho việc huấn luyện mô hình học máy. 
             Thực hiện gom nhóm nhãn (Label Mapping).
Input      :
  - datasets/cic2017_train_80.csv : Tập dữ liệu huấn luyện (80%).
  - datasets/cic2017_test_20.csv  : Tập dữ liệu kiểm thử (20%).
Output     :
  - datasets/cic2017_train_80_preprocessed.csv : Dữ liệu train đã mapping nhãn.
  - datasets/cic2017_test_20_preprocessed.csv  : Dữ liệu test đã mapping nhãn.
Quy trình  :
  1. Load dữ liệu: Đọc các file CSV đã qua bước làm sạch sơ bộ.
  2. Label Mapping: Gom 15 nhãn tấn công gốc thành 6 danh mục (BENIGN, DoS/DDoS, 
     PortScan, Botnet, Web Attack, Brute Force).
     Lưu ý: Nhãn 'Infiltration' và 'Heartbleed' được map vào 'Unknown' 
     và loại bỏ khỏi dataset.
  3. Lưu trữ: Ghi dữ liệu đã xử lý ra các file CSV mới để dùng cho huấn luyện.
=============================================================================
"""
import sys
import gc
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

# Đảm bảo in ra terminal đúng định dạng UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Ignore warnings
warnings.filterwarnings("ignore")

# ============ CONSTANTS ============
PROJECT_ROOT    = Path(__file__).resolve().parent.parent
OUTPUT_DIR      = PROJECT_ROOT / "datasets"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Train
TRAIN_INPUT     = PROJECT_ROOT / "datasets" / "cic2017_train_80.csv"
TRAIN_OUTPUT    = OUTPUT_DIR / "cic2017_train_80_preprocessed.csv"

# Test
TEST_INPUT      = PROJECT_ROOT / "datasets" / "cic2017_test_20.csv"
TEST_OUTPUT     = OUTPUT_DIR / "cic2017_test_20_preprocessed.csv"




# ============ LABEL MAPPING ============
def map_label(label):
    """Gom 15 nhãn gốc CIC-IDS-2017 thành 6 danh mục chính + BENIGN.
    
    Lớp 'Exploitation / Rare' (Infiltration, Heartbleed) đã bị loại khỏi pipeline
    do số lượng mẫu quá ít, ảnh hưởng tiêu cực đến chất lượng model.
    Chúng được map vào 'Unknown' để tự động bị lọc ra.
    """
    if pd.isna(label):
        return 'Unknown'
    l = str(label).strip()
    if 'PortScan' in l:
        return 'PortScan'
    if 'DoS' in l or 'DDoS' in l:
        return 'DoS/DDoS'
    if 'Web Attack' in l:
        return 'Web Attack'
    if 'Patator' in l:
        return 'Brute Force'
    if 'Bot' in l:
        return 'Botnet'
    if 'Infiltration' in l or 'Heartbleed' in l:
        # Nhãn này đã bị loại khỏi pipeline (số mẫu quá ít, gây mất cân bằng nặng).
        # Map sang Unknown để bị lọc ra ngay sau đó.
        return 'Unknown'
    if 'BENIGN' in l:
        return 'BENIGN'
    return 'Unknown'


# ============ LOAD DATA ============
def load_data(input_file: Path):
    """Đọc file CSV đã sạch và áp dụng mapping nhãn."""
    print("Đang đọc file CSV...")
    if not input_file.exists():
        raise FileNotFoundError(f"Không tìm thấy file: {input_file}")

    data = pd.read_csv(input_file, low_memory=False)
    print(f"  → Đã đọc: {len(data):,} dòng × {len(data.columns)} cột")

    # Tìm cột Label
    label_col = next((c for c in data.columns if c.strip().lower() == "label"), None)
    if not label_col:
        raise ValueError("Không tìm thấy cột 'Label' trong dataset!")

    # Áp dụng mapping nhãn
    print("  → Đang gom nhóm nhãn (Mapping labels)...")
    data[label_col] = data[label_col].apply(map_label)

    # Loại bỏ Unknown nếu có
    unknown_count = (data[label_col] == 'Unknown').sum()
    if unknown_count > 0:
        print(f"  → Loại bỏ {unknown_count:,} dòng nhãn 'Unknown'")
        data = data[data[label_col] != 'Unknown'].reset_index(drop=True)

    print(f"\n  Phân bố nhãn sau khi gom nhóm:")
    label_counts = data[label_col].value_counts()
    for cls, count in label_counts.items():
        pct = count / len(data) * 100
        print(f"    {cls:25s} : {count:>10,} ({pct:5.2f}%)")
    print(f"    {'TỔNG':25s} : {len(data):>10,}")

    return data, label_col





# ============ PROCESS TEST SET ============
def process_test(input_file: Path, output_file: Path):
    """Chỉ mapping nhãn cho test set."""
    print("\n" + "=" * 65)
    print(" XỬ LÝ TẬP TEST (chỉ mapping nhãn)")
    print("=" * 65)

    data, label_col = load_data(input_file)

    print(f"\nĐang lưu file test...")
    print(f"  → Output: {output_file}")
    data.to_csv(output_file, index=False)

    file_size_mb = output_file.stat().st_size / (1024 * 1024)
    print(f"  → Kích thước: {file_size_mb:.2f} MB")
    print(f"  → Số dòng: {len(data):,}")
    del data
    gc.collect()


# ============ MAIN ============
def main():
    print("=" * 65)
    print(" ZERO-TOUCH IDPS — PREPROCESSING: GOM NHÓM NHÃN")
    print("=" * 65)

    try:
        # ── TRAIN ──────────────────────────────────────────────────
        print("\n[TRAIN SET]")
        data, label_col = load_data(TRAIN_INPUT)

        print(f"\nĐang lưu file train...")
        print(f"  → Output: {TRAIN_OUTPUT}")
        data.to_csv(TRAIN_OUTPUT, index=False)
        train_size_mb = TRAIN_OUTPUT.stat().st_size / (1024 * 1024)
        train_rows    = len(data)
        print(f"  → Kích thước: {train_size_mb:.2f} MB")
        print(f"  → Số dòng: {train_rows:,}")
        del data
        gc.collect()

        # ── TEST ───────────────────────────────────────────────────
        print("\n[TEST SET]")
        process_test(TEST_INPUT, TEST_OUTPUT)

        print("\n" + "=" * 65)
        print(" HOÀN TẤT PREPROCESSING (TRAIN + TEST)!")
        print("=" * 65)

    except Exception as e:
        print(f"\n[LỖI NGHIÊM TRỌNG] Quá trình tiền xử lý thất bại: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
