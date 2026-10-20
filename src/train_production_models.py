# -*- coding: utf-8 -*-
"""
=============================================================================
Tên file   : train_production_models.py
Tác dụng   : Huấn luyện các mô hình sản xuất chính thức (Production Models)
             cho hệ thống IDPS sử dụng thuật toán XGBoost với 15 đặc trưng tối ưu
             và bộ tham số tìm được từ Bayesian Optimization.
             - Loại bỏ lớp 'Exploitation / Rare' khỏi cả tập Train và Test.
             - Áp dụng SMOTE x10 cho các lớp Brute Force, Web Attack, Botnet, PortScan.
             - Lưu đè active_model.pkl, classification_model.pkl và label_encoder.pkl.
Input      :
  - datasets/cic2017_train_80_preprocessed.csv : Dữ liệu train 80% đã tiền xử lý.
  - datasets/cic2017_test_20_preprocessed.csv  : Dữ liệu test 20% đã tiền xử lý.
Output     :
  - models/active_model.pkl          : Mô hình Binary phân loại Lành tính / Tấn công.
  - models/classification_model.pkl  : Mô hình Multi-class phân loại cụ thể tấn công.
  - models/label_encoder.pkl         : Bộ mã hóa nhãn lớp tương ứng.
Ngày tạo   : 2026-06-22
Ngày sửa   : 2026-06-22
Lí do sửa  : Chốt chọn mô hình XGBoost với 15 đặc trưng và tham số tối ưu từ Optuna.
=============================================================================
"""

import os
import sys
import time
import gc
import warnings
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
from imblearn.over_sampling import SMOTE

# Tắt các cảnh báo không cần thiết
warnings.filterwarnings("ignore")

# Đảm bảo in ra terminal đúng định dạng UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# =============================================================================
# CẤU HÌNH ĐƯỜNG DẪN & SIÊU THAM SỐ
# =============================================================================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_PATH = os.path.join(PROJECT_ROOT, "datasets", "cic2017_train_80_preprocessed.csv")
TEST_PATH = os.path.join(PROJECT_ROOT, "datasets", "cic2017_test_20_preprocessed.csv")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

ACTIVE_MODEL_PATH = os.path.join(MODEL_DIR, "active_model.pkl")
CLASSIFICATION_MODEL_PATH = os.path.join(MODEL_DIR, "classification_model.pkl")
LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")

# 15 đặc trưng tối ưu đã chọn cho XGBoost (sắp xếp A-Z)
OPTIMAL_FEATURES = [
    'ACK Flag Count',
    'Bwd IAT Max',
    'Bwd IAT Std',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Bwd Packets/s',
    'Flow Bytes/s',
    'Fwd IAT Min',
    'Fwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'PSH Flag Count',
    'Packet Length Mean',
    'Total Fwd Packets',
    'Total Length of Fwd Packets'
]

# Bộ tham số tối ưu thu được từ Bayesian Optimization
XGB_BEST_PARAMS = {
    'max_depth': 7,
    'learning_rate': 0.09735101666143689,
    'n_estimators': 114,
    'subsample': 0.8322356487650451,
    'colsample_bytree': 0.8021641140719096,
    'random_state': 42,
    'n_jobs': -1
}

# Các lớp áp dụng SMOTE x10
SMOTE_CLASSES = ['Brute Force', 'Web Attack', 'Botnet', 'PortScan']

def main():
    print("=" * 80)
    print("   HUẤN LUYỆN MÔ HÌNH SẢN XUẤT CHÍNH THỨC (XGBOOST - 15 FEATURES)   ")
    print("=" * 80)
    
    t_start = time.time()
    
    print("\n[1/5] Đang đọc dữ liệu Train & Test theo từng chunk để tối ưu RAM...")
    cols_to_load = OPTIMAL_FEATURES + ['Label']
    
    # Đọc Train Set theo chunk
    train_chunks = []
    for chunk in pd.read_csv(TRAIN_PATH, usecols=cols_to_load, chunksize=100000, low_memory=False):
        # Lọc ngay lớp 'Exploitation / Rare' trên từng chunk
        chunk = chunk[chunk['Label'] != 'Exploitation / Rare']
        train_chunks.append(chunk)
    df_train = pd.concat(train_chunks, ignore_index=True)
    del train_chunks
    gc.collect()
    
    # Đọc Test Set theo chunk
    test_chunks = []
    for chunk in pd.read_csv(TEST_PATH, usecols=cols_to_load, chunksize=100000, low_memory=False):
        chunk = chunk[chunk['Label'] != 'Exploitation / Rare']
        test_chunks.append(chunk)
    df_test = pd.concat(test_chunks, ignore_index=True)
    del test_chunks
    gc.collect()
    
    print(f"  → Dữ liệu Train: {len(df_train):,} dòng | Dữ liệu Test: {len(df_test):,} dòng")
    
    X_train = df_train[OPTIMAL_FEATURES]
    y_train = df_train['Label']
    
    X_test = df_test[OPTIMAL_FEATURES]
    y_test = df_test['Label']
    
    # Chuẩn bị nhãn
    # Nhãn Binary (BENIGN = 0, Tấn công = 1)
    y_bin_train = (y_train != 'BENIGN').astype(int).values
    y_bin_test = (y_test != 'BENIGN').astype(int).values
    
    # Mã hóa nhãn Multi-class
    le = LabelEncoder()
    y_train_encoded = le.fit_transform(y_train)
    y_test_encoded = le.transform(y_test)
    
    # Lưu Label Encoder
    joblib.dump(le, LABEL_ENCODER_PATH)
    print(f"  ✓ Đã lưu Label Encoder tại: {LABEL_ENCODER_PATH}")
    print(f"  → Danh sách các lớp nhãn: {list(le.classes_)}")
    
    # ------------------------------------------------------------------
    # 2. Huấn luyện tầng 1: Active Model (Binary)
    # ------------------------------------------------------------------
    print("\n[2/5] Đang huấn luyện Active Model (Binary)...")
    active_params = XGB_BEST_PARAMS.copy()
    active_params['objective'] = 'binary:logistic'
    active_params['eval_metric'] = 'logloss'
    
    active_model = xgb.XGBClassifier(**active_params)
    
    t0 = time.time()
    active_model.fit(X_train, y_bin_train)
    print(f"  → Hoàn tất huấn luyện Active Model trong: {time.time() - t0:.2f} giây.")
    
    # Đánh giá Active Model
    y_bin_pred = active_model.predict(X_test)
    print(f"  → F1-Score (Binary - Weighted): {f1_score(y_bin_test, y_bin_pred, average='weighted'):.5f}")
    print(f"  → Accuracy (Binary): {accuracy_score(y_bin_test, y_bin_pred):.5f}")
    
    cm_bin = confusion_matrix(y_bin_test, y_bin_pred)
    tn, fp, fn, tp = cm_bin.ravel()
    print(f"  → Confusion Matrix (Binary): TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
    
    # Lưu Active Model
    joblib.dump(active_model, ACTIVE_MODEL_PATH, compress=3)
    print(f"  ✓ Đã lưu Active Model tại: {ACTIVE_MODEL_PATH}")
    
    del active_model, y_bin_pred
    gc.collect()
    
    # ------------------------------------------------------------------
    # 3. Cân bằng dữ liệu bằng SMOTE x10 cho Classification Model
    # ------------------------------------------------------------------
    print("\n[3/5] Áp dụng SMOTE x10 cho các nhãn thiểu số (Multi-class)...")
    counts = pd.Series(y_train_encoded).value_counts()
    smote_class_ids = [le.transform([cls])[0] for cls in SMOTE_CLASSES if cls in le.classes_]
    benign_id = le.transform(['BENIGN'])[0]
    
    sampling_strategy = {}
    for cid in smote_class_ids:
        if cid in counts:
            orig_cnt = counts[cid]
            target_cnt = orig_cnt * 10
            benign_cnt = counts.get(benign_id, 1)
            # Clip target_cnt không vượt quá BENIGN count
            if target_cnt > benign_cnt:
                target_cnt = benign_cnt
            sampling_strategy[cid] = target_cnt
            
    print(f"  → Chi tiết mục tiêu SMOTE: {sampling_strategy}")
    
    # Dynamic k_neighbors
    min_cnt = min(counts[cid] for cid in sampling_strategy.keys() if cid in counts)
    k_neighbors = min(5, min_cnt - 1)
    if k_neighbors < 1:
        k_neighbors = 1
        
    smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42, k_neighbors=k_neighbors)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train_encoded)
    
    print(f"  → Kích thước dữ liệu Train sau SMOTE: {len(X_train_res):,} dòng")
    
    # ------------------------------------------------------------------
    # 4. Huấn luyện tầng 2: Classification Model (Multi-class)
    # ------------------------------------------------------------------
    print("\n[4/5] Đang huấn luyện Classification Model (Multi-class)...")
    cls_params = XGB_BEST_PARAMS.copy()
    cls_params['objective'] = 'multi:softprob'
    cls_params['num_class'] = len(le.classes_)
    cls_params['eval_metric'] = 'mlogloss'
    
    classification_model = xgb.XGBClassifier(**cls_params)
    
    t0 = time.time()
    classification_model.fit(X_train_res, y_train_res)
    print(f"  → Hoàn tất huấn luyện Classification Model trong: {time.time() - t0:.2f} giây.")
    
    # Đánh giá Classification Model
    y_mul_pred = classification_model.predict(X_test)
    print("\n  → Classification Report (Hold-out Test Set 20%):")
    print(classification_report(y_test_encoded, y_mul_pred, target_names=le.classes_))
    
    # Lưu Classification Model
    joblib.dump(classification_model, CLASSIFICATION_MODEL_PATH, compress=3)
    print(f"  ✓ Đã lưu Classification Model tại: {CLASSIFICATION_MODEL_PATH}")
    
    # ------------------------------------------------------------------
    # 5. Hoàn tất quy trình
    # ------------------------------------------------------------------
    total_time = time.time() - t_start
    print("\n" + "=" * 80)
    print(f" HOÀN TẤT TOÀN BỘ TIẾN TRÌNH HUẤN LUYỆN TRONG {total_time:.2f} GIÂY!")
    print(" Các mô hình sản xuất đã sẵn sàng phục vụ chạy thời gian thực!")
    print("=" * 80)

if __name__ == "__main__":
    main()
