#!/usr/bin/env python3
"""
=============================================================================
Tên file: offline_training.py
Chức năng: Huấn luyện 2 mô hình XGBoost (Active Model & Classification Model)
           theo kiến trúc Zero-Touch IDPS.
Input: File CSV đã tiền xử lý f:\\IPS\\datasets\\cic_ids2017_preprocessed(30).csv.
Output: 
  - models/active_model.pkl (Binary Classification)
  - models/classification_model.pkl (Multi-class Classification)
  - models/label_encoder.pkl (Label Encoder cho Multi-class)
=============================================================================
"""

import os
import gc
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score
)
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# =============================================================================
# 1. CẤU HÌNH ĐƯỜNG DẪN VÀ HẰNG SỐ
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "datasets" / "cic_ids2017_preprocessed(30).csv"

MODEL_DIR = PROJECT_ROOT / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

ACTIVE_MODEL_PATH = MODEL_DIR / "active_model.pkl"
CLASSIFICATION_MODEL_PATH = MODEL_DIR / "classification_model.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"

RANDOM_STATE = 42

# Siêu tham số XGBoost từ architecture.md
XGB_PARAMS = {
    'n_estimators': 200,
    'max_depth': 10,
    'learning_rate': 0.2,
    'subsample': 0.7,
    'colsample_bytree': 0.9,
    'scale_pos_weight': 1,
    'n_jobs': -1,
    'random_state': RANDOM_STATE,
    'verbosity': 1,
    'tree_method': 'hist' # Sử dụng histogram-based algorithm cho tốc độ nhanh hơn trên dữ liệu lớn
}

# =============================================================================
# 2. HÀM TẢI VÀ TIỀN XỬ LÝ DỮ LIỆU
# =============================================================================

def load_data(csv_path: Path):
    print(f"[1/5] Dang tai du lieu tu: {csv_path.name}...")
    if not csv_path.exists():
        raise FileNotFoundError(f"Khong tim thay tap du lieu tai: {csv_path}")

    # Tải toàn bộ dữ liệu
    data = pd.read_csv(csv_path, low_memory=False, encoding="utf-8")
    print(f"  -> Tong cong: {len(data):,} dong")

    # Xử lý Label
    label_col = "Label"
    if label_col not in data.columns:
        # Thử tìm cột có chứa chữ 'label' (không phân biệt hoa thường)
        label_col = next((c for c in data.columns if "label" in c.strip().lower()), None)
        if not label_col:
            raise ValueError("Khong tim thay cot 'Label' trong dataset!")

    print("[2/5] Dang chuan bi Target cho 2 mo hinh...")
    
    # 1. Target Binary cho active_model (BENIGN = 0, ATTACK = 1)
    target_binary = (data[label_col].str.strip().str.upper() != "BENIGN").astype(np.int8)
    
    # 2. Target Multi-class cho classification_model
    le = LabelEncoder()
    target_multi = le.fit_transform(data[label_col].str.strip())
    
    # Xoá cột Label khỏi Features
    X = data.drop(columns=[label_col])
    del data
    gc.collect()

    print("[3/5] Dang ep kieu dac trung (Features) thanh float32...")
    # Cast về Float32, clean Inf/NaN
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    valid_mask = ~X.isnull().any(axis=1)
    X = X[valid_mask].reset_index(drop=True)
    target_binary = target_binary[valid_mask].reset_index(drop=True)
    target_multi = target_multi[valid_mask]
    
    X = X.astype(np.float32)
    gc.collect()

    print(f"  -> Kich thuoc sau cung: {len(X):,} dong, {X.shape[1]} features")

    # Lưu LabelEncoder
    joblib.dump(le, LABEL_ENCODER_PATH)
    print(f"  -> Da luu LabelEncoder tai: {LABEL_ENCODER_PATH}")

    # Split Train/Test chung cho cả 2 mô hình (80/20)
    print("[4/5] Dang chia tap Train/Test (80/20)...")
    indices = np.arange(len(X))
    X_train, X_test, idx_train, idx_test = train_test_split(
        X, indices, test_size=0.2, stratify=target_binary, random_state=RANDOM_STATE
    )
    
    y_bin_train, y_bin_test = target_binary.iloc[idx_train], target_binary.iloc[idx_test]
    y_mul_train, y_mul_test = target_multi[idx_train], target_multi[idx_test]

    return X_train, X_test, y_bin_train, y_bin_test, y_mul_train, y_mul_test, le.classes_


# =============================================================================
# 3. QUY TRÌNH HUẤN LUYỆN CHÍNH
# =============================================================================

def main():
    print("#" * 70)
    print("#  ZERO-TOUCH IDPS -- OFFLINE MODEL TRAINING (XGBOOST)")
    print("#" * 70)

    start_time = time.time()

    # 1. Load Data
    X_train, X_test, y_bin_train, y_bin_test, y_mul_train, y_mul_test, class_names = load_data(DATASET_PATH)
    
    print("\n[5/5] Huan luyen mo hinh XGBoost...")
    print("  -> Cac hyperparameter duoc ap dung:")
    for k, v in XGB_PARAMS.items():
        print(f"     - {k}: {v}")
    
    # ---------------------------------------------------------
    # Huan luyen Active Model (Binary)
    # ---------------------------------------------------------
    print("\n" + "-" * 50)
    print(" [A] DANG HUAN LUYEN ACTIVE MODEL (BINARY)")
    print("-" * 50)
    
    active_params = XGB_PARAMS.copy()
    active_params['objective'] = 'binary:logistic'
    
    active_model = xgb.XGBClassifier(**active_params)
    active_model.fit(X_train, y_bin_train)
    
    print("\n -> Danh gia Active Model (Test Set):")
    y_bin_pred = active_model.predict(X_test)
    
    cm_bin = confusion_matrix(y_bin_test, y_bin_pred)
    tn, fp, fn, tp = cm_bin.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"                   Du doan BENIGN      Du doan ATTACK")
    print(f"Thuc te BENIGN     {tn:>8,}            {fp:>8,} (FP: {fpr*100:.3f}%)")
    print(f"Thuc te ATTACK     {fn:>8,}            {tp:>8,} (FN: {fnr*100:.3f}%)")
    print(f"  - Accuracy:         {accuracy_score(y_bin_test, y_bin_pred):.4f}")
    print(f"  - F1-Score:         {f1_score(y_bin_test, y_bin_pred, average='weighted'):.4f}")
    
    joblib.dump(active_model, ACTIVE_MODEL_PATH, compress=3)
    print(f"[OK] Da luu active_model.pkl ({ACTIVE_MODEL_PATH.stat().st_size / 1024 / 1024:.2f} MB)")
    
    del active_model, y_bin_pred
    gc.collect()
    
    # ---------------------------------------------------------
    # Huan luyen Classification Model (Multi-class)
    # ---------------------------------------------------------
    print("\n" + "-" * 50)
    print(" [B] DANG HUAN LUYEN CLASSIFICATION MODEL (MULTI-CLASS)")
    print("-" * 50)
    
    multi_params = XGB_PARAMS.copy()
    multi_params['objective'] = 'multi:softprob'
    multi_params['num_class'] = len(class_names)
    multi_params.pop('scale_pos_weight', None) # scale_pos_weight chi dung cho binary
    
    classification_model = xgb.XGBClassifier(**multi_params)
    classification_model.fit(X_train, y_mul_train)
    
    print("\n -> Danh gia Classification Model (Test Set):")
    y_mul_pred = classification_model.predict(X_test)
    
    print("\n[Classification Report]")
    print(classification_report(y_mul_test, y_mul_pred, target_names=class_names))
    print(f"  - Accuracy:         {accuracy_score(y_mul_test, y_mul_pred):.4f}")
    
    joblib.dump(classification_model, CLASSIFICATION_MODEL_PATH, compress=3)
    print(f"[OK] Da luu classification_model.pkl ({CLASSIFICATION_MODEL_PATH.stat().st_size / 1024 / 1024:.2f} MB)")
    
    total_time = time.time() - start_time
    print("\n" + "#" * 70)
    print(f" HOAN TAT TOAN BO TIEN TRINH SAU {total_time:.1f} GIAY!")
    print("#" * 70)


if __name__ == "__main__":
    main()
