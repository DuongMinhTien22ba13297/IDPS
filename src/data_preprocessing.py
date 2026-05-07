"""
=============================================================================
Tên file: data_preprocessing.py
Chức năng: Tiền xử lý dữ liệu thô từ CIC-IDS-2017 (tổng hợp file, làm sạch, gom nhóm nhãn, xử lý mất cân bằng dữ liệu).
Input: Các file .csv thô nằm trong thư mục `datasets/MachineLearningCSV/MachineLearningCVE/`.
Output: Một file csv duy nhất đã được xử lý cân bằng dữ liệu: `datasets/cic_ids2017_preprocessed.csv`.
Quy trình chi tiết:
  1. Gộp tất cả các file CSV thô.
  2. Xóa các giá trị rác (NaN, Inf) và các cột metadata (IP, Port, Timestamp).
  3. Gom nhóm (Mapping) các nhãn tấn công thành các danh mục chính.
  4. Undersampling lớp BENIGN và SMOTE Oversampling các lớp thiểu số.
=============================================================================
"""
#Data preprocessing : resample imbalanced data
import os
import gc
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE

# Ignore warnings
warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_ROOT / "datasets" / "MachineLearningCSV" / "MachineLearningCVE"
OUTPUT_DIR = PROJECT_ROOT / "datasets"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = OUTPUT_DIR / "cic_ids2017_preprocessed.csv"

def map_label(label):
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
        return 'Exploitation / Rare'
    if 'BENIGN' in l:
        return 'BENIGN'
    return 'Unknown'

def load_and_clean_data(dataset_dir: Path):
    print("[1/5] Dang doc va gop cac file CSV...")
    csv_files = sorted(dataset_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"Khong tim thay CSV tai: {dataset_dir}")

    frames = []
    for csv_path in csv_files:
        try:
            # Handle encoding issues (Web Attack characters)
            df = pd.read_csv(csv_path, low_memory=False, encoding="utf-8", on_bad_lines='skip')
            frames.append(df)
            print(f"  -> Da tai: {csv_path.name} ({len(df):,} dong)")
        except Exception as e:
            print(f"  -> [LOI] Khong the doc {csv_path.name}: {e}")

    data = pd.concat(frames, ignore_index=True)
    del frames
    gc.collect()
    
    # Strip column names
    data.columns = [c.strip() for c in data.columns]
    
    print("[2/5] Dang lam sach du lieu (Xoa missing/inf va cot metadata)...")
    
    # Identify Label column
    label_col = next((c for c in data.columns if c.lower() == "label"), None)
    if not label_col:
        raise ValueError("Khong tim thay cot 'Label' trong dataset!")

    # Map labels
    print("  -> Dang gop cac nhan (Mapping labels)...")
    data[label_col] = data[label_col].apply(map_label)
    
    # Remove Unknown if any
    data = data[data[label_col] != 'Unknown'].reset_index(drop=True)

    # Drop metadata columns
    cols_to_drop = []
    meta_keywords = ["flow id", "source ip", "destination ip", "source port", "timestamp", "src_ip", "dst_ip"]
    for col in data.columns:
        if col.lower() in meta_keywords:
            cols_to_drop.append(col)
            
    data.drop(columns=cols_to_drop, inplace=True, errors="ignore")
    
    # Clean NaN and Inf
    print("  -> Dang loai bo gia tri Inf/NaN...")
    features = [c for c in data.columns if c != label_col]
    
    for col in features:
        data[col] = pd.to_numeric(data[col], errors="coerce")
    
    # Replace infinite values with nan
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Drop rows with NaN
    data.dropna(inplace=True)
    data.reset_index(drop=True, inplace=True)
    
    print(f"  -> Kich thuoc sau khi lam sach: {len(data):,} dong.")
    return data, label_col

def resample_data(data, label_col):
    print("[3/5] Dang thuc hien Custom Resampling...")
    
    X = data.drop(columns=[label_col])
    y = data[label_col]
    
    label_counts = y.value_counts()
    print("\nPhan phoi label TRUOC khi resample:")
    print(label_counts)
    
    dos_count = label_counts.get('DoS/DDoS', 0)
    if dos_count == 0:
        dos_count = label_counts.max() # fallback
        
    print(f"\n  -> Lay moc muc tieu (DoS/DDoS): {dos_count:,} mau.")
    
    # 1. Undersampling BENIGN
    under_strategy = {}
    for cls, count in label_counts.items():
        if cls == 'BENIGN':
            # Giam manh lop BENIGN xuong bang DoS/DDoS
            under_strategy[cls] = min(count, dos_count)
        else:
            # Giu nguyen cac lop khac trong buoc nay
            under_strategy[cls] = count
            
    print("  -> Dang thuc hien Undersampling (RandomUnderSampler)...")
    rus = RandomUnderSampler(sampling_strategy=under_strategy, random_state=42)
    X_res, y_res = rus.fit_resample(X, y)
    
    # 2. Oversampling (SMOTE) cho cac lop cuc hiem
    # Chon muc tieu de oversample, vd: 50,000 mau de du trong luong
    target_minority_size = min(dos_count, 100000) if dos_count > 0 else 50000
    
    current_counts = y_res.value_counts()
    over_strategy = {}
    
    minority_classes = ['Web Attack', 'Brute Force', 'Botnet', 'Exploitation / Rare']
    
    # Kiem tra so luong mau toi thieu de SMOTE (can it nhat k_neighbors + 1, thuong la 6)
    min_samples = current_counts[current_counts.index.isin(minority_classes)].min()
    k_neighbors = min(5, min_samples - 1) if min_samples > 1 else 1
    
    for cls, count in current_counts.items():
        if cls in minority_classes:
            over_strategy[cls] = max(count, target_minority_size)
            
    if over_strategy:
        print(f"  -> Dang thuc hien Oversampling (SMOTE) voi k_neighbors={k_neighbors}...")
        smote = SMOTE(sampling_strategy=over_strategy, random_state=42, k_neighbors=k_neighbors)
        X_res, y_res = smote.fit_resample(X_res, y_res)
    else:
        print("  -> Khong co lop thieu so nao can Oversample.")
        
    print("\nPhan phoi label SAU khi resample:")
    print(y_res.value_counts())
    
    # Gom lai thanh DataFrame
    df_resampled = pd.concat([X_res, y_res], axis=1)
    return df_resampled

def main():
    print("="*60)
    print(" ZERO-TOUCH IDPS - GIAI DOAN 1: TIEN XU LY DU LIEU (1-CLICK)")
    print("="*60)
    
    try:
        data, label_col = load_and_clean_data(DATASET_DIR)
        df_resampled = resample_data(data, label_col)
        
        print(f"\n[4/5] Dang luu dataset da tien xu ly vao {OUTPUT_FILE}...")
        df_resampled.to_csv(OUTPUT_FILE, index=False)
        print(f"  -> Kich thuoc file dau ra: {OUTPUT_FILE.stat().st_size / (1024*1024):.2f} MB")
        
        print("\n[5/5] Hoan tat Giai doan 1!")
        print("="*60)
    except Exception as e:
        print(f"\n[LOI NGHIEM TRONG] Qua trinh tien xu ly that bai: {e}")

if __name__ == "__main__":
    main()
