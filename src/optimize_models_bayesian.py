# -*- coding: utf-8 -*-
"""
=============================================================================
Tên file   : optimize_models_bayesian.py
Tác dụng   : Thực hiện Bayesian Optimization (Optuna) kết hợp Stratified 5-Fold
             Cross-Validation để tìm ra siêu tham số và số lượng đặc trưng (k)
             tối ưu nhất cho 3 mô hình: XGBoost, Random Forest, LightGBM.
             Áp dụng các biện pháp nghiêm ngặt để chống Data Leakage (Rò rỉ dữ liệu):
             - Tính toán đặc trưng quan trọng (Feature Importance) trong từng fold.
             - Áp dụng SMOTE tăng 10 lần mẫu (x10) cho các lớp thiểu số chỉ trên Train Fold sau khi cắt features.
             - Đánh giá đơn mục tiêu bằng F1-Macro.
             - Đo đạc Latency suy luận ở tập Hold-out Test độc lập cuối cùng.
Input      :
  - datasets/cic2017_train_80_preprocessed.csv : Tập dữ liệu train 80% đã tiền xử lý.
  - datasets/cic2017_test_20_preprocessed.csv  : Tập dữ liệu test 20% đã tiền xử lý.
Output     :
  - results/bayesian_optimization_report.txt : Báo cáo chi tiết kết quả tối ưu.
  - results/optuna_history_[model].png : Biểu đồ lịch sử tối ưu hóa của các mô hình.
Ngày tạo   : 2026-06-22
Ngày sửa   : 2026-06-22
Lí do sửa  : Triển khai theo thiết kế chống rò rỉ dữ liệu và cấu hình SMOTE x10.
=============================================================================
"""

import os
import sys
import time
import gc
import warnings
import numpy as np
import pandas as pd
import optuna
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report
from imblearn.over_sampling import SMOTE

# Tắt các cảnh báo không cần thiết
warnings.filterwarnings("ignore")
optuna.logging.set_verbosity(optuna.logging.WARNING)

# Đảm bảo in ra terminal đúng định dạng UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# =============================================================================
# CẤU HÌNH ĐƯỜNG DẪN & THÔNG SỐ
# =============================================================================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_PATH = os.path.join(PROJECT_ROOT, "datasets", "cic2017_train_80_preprocessed.csv")
TEST_PATH = os.path.join(PROJECT_ROOT, "datasets", "cic2017_test_20_preprocessed.csv")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

REPORT_PATH = os.path.join(RESULTS_DIR, "bayesian_optimization_report.txt")

# Định nghĩa các lớp cần áp dụng SMOTE x10
SMOTE_CLASSES = ['Brute Force', 'Web Attack', 'Botnet', 'PortScan']

# Danh sách 57 đặc trưng gốc trong file preprocessed (cần loại bỏ các đặc trưng không line-rate/không tương thích)
DROPPED_FEATURES = {
    'Fwd Header Length', 'Bwd Header Length', 'act_data_pkt_fwd',
    'CWE Flag Count', 'ECE Flag Count', 'Bwd PSH Flags', 'Bwd URG Flags'
}

# =============================================================================
# HÀM BỔ TRỢ: LOAD DỮ LIỆU & LỌC ĐẶC TRƯNG
# =============================================================================
def load_datasets():
    print("[1/5] Đang đọc dữ liệu train & test preprocessed...")
    t0 = time.time()
    
    df_train = pd.read_csv(TRAIN_PATH, low_memory=False)
    df_test = pd.read_csv(TEST_PATH, low_memory=False)
    
    # Loại bỏ hoàn toàn lớp 'Exploitation / Rare' theo yêu cầu
    df_train = df_train[df_train['Label'] != 'Exploitation / Rare'].reset_index(drop=True)
    df_test = df_test[df_test['Label'] != 'Exploitation / Rare'].reset_index(drop=True)
    
    print(f"  → Đã load Train Set (đã lọc): {len(df_train):,} dòng | Test Set (đã lọc): {len(df_test):,} dòng")
    
    # Gom danh sách đặc trưng ứng viên (Candidate features)
    all_columns = df_train.columns.tolist()
    candidate_features = [col for col in all_columns if col != 'Label' and col not in DROPPED_FEATURES]
    
    print(f"  → Số đặc trưng ban đầu: {len(all_columns) - 1}")
    print(f"  → Loại bỏ {len(DROPPED_FEATURES)} đặc trưng không tương thích NFStream.")
    print(f"  → Số đặc trưng ứng viên (Candidate pool) còn lại: {len(candidate_features)}")
    
    # Phân tách X, y
    X_train = df_train[candidate_features]
    y_train = df_train['Label']
    
    X_test = df_test[candidate_features]
    y_test = df_test['Label']
    
    print(f"  Thời gian load: {time.time() - t0:.2f} giây.")
    return X_train, y_train, X_test, y_test, candidate_features

def get_tuning_subset(X_train, y_train):
    """
    Tạo tập con tối ưu (Tuning Subset) để tăng tốc Optuna:
    Giữ lại toàn bộ mẫu thiểu số, chỉ giảm mẫu của BENIGN và DoS/DDoS.
    """
    print("[2/5] Tạo tập con Tuning để tăng tốc tối ưu hóa (giữ nguyên lớp hiếm)...")
    df_temp = X_train.copy()
    df_temp['Label'] = y_train.values
    
    # Phân nhóm nhãn
    df_benign = df_temp[df_temp['Label'] == 'BENIGN']
    df_dos = df_temp[df_temp['Label'] == 'DoS/DDoS']
    df_rare = df_temp[~df_temp['Label'].isin(['BENIGN', 'DoS/DDoS'])]
    
    # Lấy mẫu ngẫu nhiên có kiểm soát
    n_benign = min(80000, len(df_benign))
    n_dos = min(20000, len(df_dos))
    
    df_benign_sampled = df_benign.sample(n=n_benign, random_state=42)
    df_dos_sampled = df_dos.sample(n=n_dos, random_state=42)
    
    df_tuning = pd.concat([df_benign_sampled, df_dos_sampled, df_rare], ignore_index=True)
    
    X_tuning = df_tuning.drop(columns=['Label'])
    y_tuning = df_tuning['Label']
    
    print(f"  → Phân bố nhãn trong tập Tuning ({len(df_tuning):,} dòng):")
    counts = y_tuning.value_counts()
    for cls, cnt in counts.items():
        print(f"    - {cls:22s}: {cnt:,}")
        
    return X_tuning, y_tuning

# =============================================================================
# HÀM MỤC TIÊU CHO OPTUNA (CV CHỐNG DATA LEAKAGE & SMOTE X10)
# =============================================================================
def make_objective(model_name, X_tuning, y_tuning, candidate_features, le):
    # Chuyển đổi y_tuning sang dạng số
    y_tuning_encoded = pd.Series(le.transform(y_tuning), index=y_tuning.index)
    
    # Lấy ID của các lớp cần SMOTE
    smote_class_ids = [le.transform([cls])[0] for cls in SMOTE_CLASSES if cls in le.classes_]
    benign_id = le.transform(['BENIGN'])[0]
    
    def objective(trial):
        # 1. Gợi ý siêu tham số tùy theo mô hình
        if model_name == 'xgboost':
            params = {
                'max_depth': trial.suggest_int('max_depth', 3, 10),
                'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.2, log=True),
                'n_estimators': trial.suggest_int('n_estimators', 50, 150),
                'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                'random_state': 42,
                'n_jobs': -1,
                'eval_metric': 'mlogloss'
            }
        elif model_name == 'lightgbm':
            params = {
                'max_depth': trial.suggest_int('max_depth', 3, 15),
                'num_leaves': trial.suggest_int('num_leaves', 8, 128),
                'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.2, log=True),
                'n_estimators': trial.suggest_int('n_estimators', 50, 150),
                'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                'random_state': 42,
                'n_jobs': -1,
                'verbosity': -1
            }
        else:  # random_forest
            params = {
                'max_depth': trial.suggest_int('max_depth', 5, 25),
                'n_estimators': trial.suggest_int('n_estimators', 50, 150),
                'min_samples_split': trial.suggest_int('min_samples_split', 2, 10),
                'min_samples_leaf': trial.suggest_int('min_samples_leaf', 1, 5),
                'random_state': 42,
                'n_jobs': -1
            }
            
        # Thiết lập 5-Fold Cross Validation
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        fold_scores = []
        
        for train_idx, val_idx in skf.split(X_tuning, y_tuning_encoded):
            X_train, X_val = X_tuning.iloc[train_idx].copy(), X_tuning.iloc[val_idx].copy()
            y_train, y_val = y_tuning_encoded.iloc[train_idx].copy(), y_tuning_encoded.iloc[val_idx].copy()
            
            # --- BƯỚC CHỐNG LEAKAGE 1: Tìm Feature Importance CHỈ trên Train Fold ---
            # Sử dụng mô hình tương ứng để lấy Feature Importance
            if model_name == 'xgboost':
                from xgboost import XGBClassifier
                base_model = XGBClassifier(n_estimators=30, max_depth=6, random_state=42, n_jobs=-1, eval_metric='mlogloss')
            elif model_name == 'lightgbm':
                from lightgbm import LGBMClassifier
                base_model = LGBMClassifier(n_estimators=30, max_depth=6, random_state=42, n_jobs=-1, verbosity=-1)
            else:
                base_model = ExtraTreesClassifier(n_estimators=30, max_depth=10, random_state=42, n_jobs=-1)
            base_model.fit(X_train[candidate_features], y_train)
            
            # --- BƯỚC CHỐNG LEAKAGE 2: Chọn đặc trưng có tổng độ quan trọng tích lũy đạt 95% ---
            importances = base_model.feature_importances_
            feature_imp_df = pd.DataFrame({
                'feature': candidate_features,
                'importance': importances
            }).sort_values(by='importance', ascending=False)
            
            feature_imp_df['cum_sum'] = feature_imp_df['importance'].cumsum()
            feature_imp_df['prev_cum_sum'] = feature_imp_df['cum_sum'].shift(1, fill_value=0.0)
            top_k_features = feature_imp_df[feature_imp_df['prev_cum_sum'] < 0.95]['feature'].tolist()
            if len(top_k_features) < 5:
                top_k_features = feature_imp_df['feature'].head(5).tolist()
            
            # --- BƯỚC CHỐNG LEAKAGE 3: Cắt giảm đặc trưng ---
            X_train_sliced = X_train[top_k_features]
            X_val_sliced = X_val[top_k_features]
            
            # --- BƯỚC CHỐNG LEAKAGE 4: Áp dụng SMOTE x10 CHỈ trên Train Fold đã cắt ---
            counts = y_train.value_counts()
            sampling_strategy = {}
            for cid in smote_class_ids:
                if cid in counts:
                    orig_cnt = counts[cid]
                    target_cnt = orig_cnt * 10
                    # Giới hạn target_cnt không vượt quá số lượng mẫu lớp BENIGN trong Train Fold
                    benign_cnt = counts.get(benign_id, 1)
                    if target_cnt > benign_cnt:
                        target_cnt = benign_cnt
                    sampling_strategy[cid] = target_cnt
            
            if sampling_strategy:
                # Dynamic k_neighbors để tránh lỗi nếu số lượng mẫu quá bé
                min_cnt = min(counts[cid] for cid in sampling_strategy.keys() if cid in counts)
                k_neighbors = min(5, min_cnt - 1)
                if k_neighbors < 1:
                    k_neighbors = 1
                    
                smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42, k_neighbors=k_neighbors)
                X_train_res, y_train_res = smote.fit_resample(X_train_sliced, y_train)
            else:
                X_train_res, y_train_res = X_train_sliced, y_train
                
            # --- BƯỚC CHỐNG LEAKAGE 5: Huấn luyện mô hình chính và dự đoán trên Validation Fold ---
            if model_name == 'xgboost':
                from xgboost import XGBClassifier
                clf = XGBClassifier(**params)
                clf.fit(X_train_res, y_train_res)
                preds = clf.predict(X_val_sliced)
            elif model_name == 'lightgbm':
                from lightgbm import LGBMClassifier
                clf = LGBMClassifier(**params)
                clf.fit(X_train_res, y_train_res)
                preds = clf.predict(X_val_sliced)
            else:
                clf = RandomForestClassifier(**params)
                clf.fit(X_train_res, y_train_res)
                preds = clf.predict(X_val_sliced)
                
            # Đánh giá bằng F1-Macro
            score = f1_score(y_val, preds, average='macro')
            fold_scores.append(score)
            
        return np.mean(fold_scores)
        
    return objective

# =============================================================================
# HÀM BỔ TRỢ: ĐÁNH GIÁ MÔ HÌNH SAU TỐI ƯU HÓA (FINAL FIT & LATENCY TEST)
# =============================================================================
def evaluate_best_model(model_name, best_params, X_train, y_train, X_test, y_test, candidate_features, le):
    """
    Huấn luyện lại mô hình tốt nhất trên toàn bộ tập Train (80%) và đánh giá trên Test (20%).
    Đo đạc độ chính xác và Inference Latency.
    """
    print(f"\n[4/5] Huấn luyện lại và đánh giá mô hình {model_name.upper()} tốt nhất...")
    
    # 1. Tính toán Feature Importance trên toàn bộ tập Train để chọn Top k cuối cùng
    # Chuyển đổi nhãn sang số
    y_train_encoded = le.transform(y_train)
    y_test_encoded = le.transform(y_test)
    
    # Sử dụng mô hình tương ứng để lấy Feature Importance
    if model_name == 'xgboost':
        from xgboost import XGBClassifier
        base_model = XGBClassifier(n_estimators=50, max_depth=8, random_state=42, n_jobs=-1, eval_metric='mlogloss')
    elif model_name == 'lightgbm':
        from lightgbm import LGBMClassifier
        base_model = LGBMClassifier(n_estimators=50, max_depth=8, random_state=42, n_jobs=-1, verbosity=-1)
    else:
        base_model = ExtraTreesClassifier(n_estimators=50, max_depth=12, random_state=42, n_jobs=-1)
    base_model.fit(X_train[candidate_features], y_train_encoded)
    
    importances = base_model.feature_importances_
    feature_imp_df = pd.DataFrame({
        'feature': candidate_features,
        'importance': importances
    }).sort_values(by='importance', ascending=False)
    
    feature_imp_df['cum_sum'] = feature_imp_df['importance'].cumsum()
    feature_imp_df['prev_cum_sum'] = feature_imp_df['cum_sum'].shift(1, fill_value=0.0)
    final_top_k_features = feature_imp_df[feature_imp_df['prev_cum_sum'] < 0.95]['feature'].tolist()
    if len(final_top_k_features) < 5:
        final_top_k_features = feature_imp_df['feature'].head(5).tolist()
    best_k = len(final_top_k_features)
    print(f"  → {model_name.upper()} Best Features ({best_k}): {final_top_k_features}")
    
    # 2. Cắt giảm dữ liệu theo top k features
    X_train_sliced = X_train[final_top_k_features]
    X_test_sliced = X_test[final_top_k_features]
    
    # 3. Áp dụng SMOTE x10 trên toàn bộ Train Fold đã cắt giảm
    counts = pd.Series(y_train_encoded).value_counts()
    smote_class_ids = [le.transform([cls])[0] for cls in SMOTE_CLASSES if cls in le.classes_]
    benign_id = le.transform(['BENIGN'])[0]
    
    sampling_strategy = {}
    for cid in smote_class_ids:
        if cid in counts:
            orig_cnt = counts[cid]
            target_cnt = orig_cnt * 10
            benign_cnt = counts.get(benign_id, 1)
            if target_cnt > benign_cnt:
                target_cnt = benign_cnt
            sampling_strategy[cid] = target_cnt
            
    print(f"  → Cân bằng tập Train bằng SMOTE (x10 các lớp thiểu số)...")
    min_cnt = min(counts[cid] for cid in sampling_strategy.keys() if cid in counts)
    k_neighbors = min(5, min_cnt - 1)
    if k_neighbors < 1:
        k_neighbors = 1
        
    smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42, k_neighbors=k_neighbors)
    X_train_res, y_train_res = smote.fit_resample(X_train_sliced, y_train_encoded)
    
    # 4. Huấn luyện mô hình chính thức với siêu tham số tối ưu
    # Loại bỏ khoá 'k' ra khỏi siêu tham số nếu có
    model_params = {k: v for k, v in best_params.items() if k != 'k'}
    
    if model_name == 'xgboost':
        from xgboost import XGBClassifier
        clf = XGBClassifier(**model_params, random_state=42, n_jobs=-1, eval_metric='mlogloss')
    elif model_name == 'lightgbm':
        from lightgbm import LGBMClassifier
        clf = LGBMClassifier(**model_params, random_state=42, n_jobs=-1, verbosity=-1)
    else:
        clf = RandomForestClassifier(**model_params, random_state=42, n_jobs=-1)
        
    t_fit_start = time.time()
    clf.fit(X_train_res, y_train_res)
    fit_time = time.time() - t_fit_start
    print(f"  → Hoàn tất huấn luyện trong: {fit_time:.2f} giây.")
    
    # 5. Đo đạc thời gian suy luận (Inference Latency) trên Hold-out Test Set
    t_predict_start = time.time()
    preds = clf.predict(X_test_sliced)
    predict_time = time.time() - t_predict_start
    
    latency_ms_per_flow = (predict_time / len(X_test_sliced)) * 1000.0
    print(f"  → Dự đoán xong: {len(X_test_sliced):,} flows trong {predict_time:.4f} giây.")
    print(f"  → Latency trung bình: {latency_ms_per_flow:.4f} ms/flow.")
    
    # 6. Đánh giá chi tiết
    f1_macro = f1_score(y_test_encoded, preds, average='macro')
    f1_weighted = f1_score(y_test_encoded, preds, average='weighted')
    precision_macro = precision_score(y_test_encoded, preds, average='macro')
    recall_macro = recall_score(y_test_encoded, preds, average='macro')
    
    report = classification_report(y_test_encoded, preds, target_names=le.classes_, output_dict=True)
    report_str = classification_report(y_test_encoded, preds, target_names=le.classes_)
    print("  → Classification Report:")
    print(report_str)
    
    # Dọn dẹp bộ nhớ
    gc.collect()
    
    return {
        'model_name': model_name.upper(),
        'best_k': best_k,
        'best_features': final_top_k_features,
        'fit_time': fit_time,
        'latency_ms_per_flow': latency_ms_per_flow,
        'f1_macro': f1_macro,
        'f1_weighted': f1_weighted,
        'precision_macro': precision_macro,
        'recall_macro': recall_macro,
        'report_str': report_str,
        'report_dict': report
    }

# =============================================================================
# HÀM CHÍNH (MAIN PROCESS)
# =============================================================================
def main():
    print("=" * 80)
    print("  BẮT ĐẦU QUY TRÌNH TỐI ƯU MÔ HÌNH BẰNG BAYESIAN OPTIMIZATION (OPTUNA)  ")
    print("=" * 80)
    
    # 1. Load data
    X_train, y_train, X_test, y_test, candidate_features = load_datasets()
    
    # 2. Tạo tập con Tuning để tối ưu hóa nhanh
    X_tuning, y_tuning = get_tuning_subset(X_train, y_train)
    
    # Khởi tạo LabelEncoder
    le = LabelEncoder()
    le.fit(y_train) # Fit trên tập train gốc để đầy đủ các nhãn
    
    models = ['lightgbm', 'xgboost', 'random_forest']
    best_configurations = {}
    evaluation_results = {}
    
    # 3. Chạy Optuna tối ưu hóa cho từng mô hình
    print("\n[3/5] Khởi động Bayesian Optimization bằng Optuna...")
    for model_name in models:
        print(f"\n>>> Đang tối ưu hoá cho mô hình: {model_name.upper()}")
        t_opt_start = time.time()
        
        study = optuna.create_study(direction='maximize')
        objective_func = make_objective(model_name, X_tuning, y_tuning, candidate_features, le)
        
        # Chạy 30 trials để tìm bộ siêu tham số + k features
        study.optimize(objective_func, n_trials=30)
        
        opt_time = time.time() - t_opt_start
        print(f"  → Hoàn tất tối ưu {model_name.upper()} (30 trials) trong {opt_time:.2f} giây.")
        print(f"  → Best F1-Macro trung bình (5-Fold CV): {study.best_value:.4f}")
        print(f"  → Cấu hình tốt nhất: {study.best_params}")
        
        best_configurations[model_name] = study.best_params
        
        # Vẽ biểu đồ lịch sử tối ưu
        try:
            plt.figure(figsize=(10, 5))
            trials = study.trials
            scores = [t.value for t in trials if t.value is not None]
            plt.plot(scores, marker='o', color='royalblue', linestyle='-', linewidth=1.5)
            plt.title(f"Lịch sử tối ưu hóa Optuna - {model_name.upper()}", fontsize=13, fontweight='bold')
            plt.xlabel("Trial #", fontsize=11)
            plt.ylabel("5-Fold CV F1-Macro", fontsize=11)
            plt.grid(True, linestyle='--', alpha=0.6)
            plt.tight_layout()
            
            plot_path = os.path.join(RESULTS_DIR, f"optuna_history_{model_name}.png")
            plt.savefig(plot_path, dpi=300)
            plt.close()
            print(f"  ✓ Đã lưu biểu đồ: results/optuna_history_{model_name}.png")
        except Exception as e:
            print(f"  [!] Lỗi khi vẽ biểu đồ: {e}")
            
        # 4. Đánh giá cấu hình tốt nhất trên tập Hold-out Test
        eval_res = evaluate_best_model(
            model_name, study.best_params, 
            X_train, y_train, X_test, y_test, 
            candidate_features, le
        )
        evaluation_results[model_name] = eval_res
        
        # Dọn dẹp
        gc.collect()
        
    # 5. Xuất báo cáo kết quả chi tiết
    print(f"\n[5/5] Ghi báo cáo kết quả chi tiết ra file: {REPORT_PATH}...")
    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("           BÁO CÁO THỰC NGHIỆM TỐI ƯU HÓA SIÊU THAM SỐ VÀ ĐẶC TRƯNG\n")
        f.write("                 (BAYESIAN OPTIMIZATION & CROSS-VALIDATION)\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("1. THÔNG TIN CHUNG:\n")
        f.write(f"   - Thời gian thực hiện   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"   - File dữ liệu Train    : {TRAIN_PATH}\n")
        f.write(f"   - File dữ liệu Test     : {TEST_PATH}\n")
        f.write(f"   - Candidate Features    : {len(candidate_features)} (đã loại bỏ 7 đặc trưng không tương thích NFStream)\n")
        f.write("   - Chiến lược cân bằng   : SMOTE x10 các lớp [Brute Force, Web Attack, Botnet, PortScan] trong từng fold\n")
        f.write("   - Biện pháp chống Leak  : Chọn đặc trưng (ngưỡng 95% cumulative importance) và SMOTE độc lập bên trong từng Train Fold của K-Fold\n\n")
        
        f.write("2. BẢNG SO SÁNH HIỆU NĂNG MÔ HÌNH TRÊN TẬP HOLD-OUT TEST:\n")
        f.write("-" * 105 + "\n")
        f.write(f"| {'Mô Hình':15s} | {'Số Lượng Features (k)':22s} | {'F1-Macro':10s} | {'F1-Weighted':12s} | {'Precision-Macro':16s} | {'Recall-Macro':13s} | {'Latency (ms/flow)':18s} |\n")
        f.write("-" * 105 + "\n")
        for m in models:
            res = evaluation_results[m]
            f.write(f"| {res['model_name']:15s} | {res['best_k']:22d} | {res['f1_macro']:10.5f} | {res['f1_weighted']:12.5f} | {res['precision_macro']:16.5f} | {res['recall_macro']:13.5f} | {res['latency_ms_per_flow']:18.6f} |\n")
        f.write("-" * 105 + "\n\n")
        
        f.write("3. CẤU HÌNH CHI TIẾT CỦA TỪNG MÔ HÌNH TỐI ƯU:\n\n")
        for m in models:
            res = evaluation_results[m]
            params = best_configurations[m]
            f.write(f"### MÔ HÌNH {res['model_name']}:\n")
            f.write(f"   - Siêu tham số tối ưu  : {params}\n")
            f.write(f"   - Số đặc trưng tối ưu  : {res['best_k']}\n")
            f.write(f"   - Danh sách đặc trưng  : {res['best_features']}\n")
            f.write(f"   - Thời gian train (s)  : {res['fit_time']:.2f} s\n")
            f.write(f"   - Thời gian phản hồi   : {res['latency_ms_per_flow']:.6f} ms/flow\n")
            f.write("   - Báo cáo phân loại chi tiết:\n")
            f.write(res['report_str'])
            f.write("\n" + "="*50 + "\n\n")
            
    print("\n" + "=" * 80)
    print(" QUY TRÌNH HOÀN TẤT THÀNH CÔNG!")
    f.close()
    print(f" Kết quả chi tiết và biểu đồ đã được lưu trong thư mục: results/")
    print("=" * 80)

if __name__ == "__main__":
    main()
