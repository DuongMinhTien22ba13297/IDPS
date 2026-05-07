"""
=============================================================================
Tên file   : evaluate_fn.py
Mục tiêu   : Đánh giá mô hình (phân loại nhị phân BENIGN vs ATTACK) trên tập dữ liệu 2017.
             Cấu trúc giống hệt hyperparameter_tuning.py nhưng tập trung vào Evaluation.
Input      :
  --data_path      : File CSV dùng để TRAIN/TEST (mặc định: cic_ids2017_preprocessed(30).csv)
  --models         : Danh sách model cần đánh giá (mặc định: RandomForest XGBoost LightGBM)
  --n_iter         : Số tổ hợp tham số RandomizedSearchCV sẽ thử (mặc định: 10)
  --n_jobs         : Số luồng chạy song song trong CV (mặc định: 1)
  --sample_train   : Tỉ lệ lấy mẫu ngẫu nhiên từ toàn bộ data (0.0-1.0, mặc định: 1.0)
  --save_model     : Flag, nếu có sẽ lưu mô hình tốt nhất ra file .pkl
  --output         : Đường dẫn file kết quả (mặc định: result_hyperparameter.txt)
Output     :
  - In ra terminal + ghi vào file kết quả:
      * Dải tham số (param grid) đã thử nghiệm cho từng model
      * Top-5 tổ hợp tham số tốt nhất theo CV (Custom_IDPS score)
      * Metrics tổng hợp: Recall/DR, FPR, Precision, F1, MCC, Latency
      * Báo cáo chi tiết theo từng loại tấn công (DoS, Brute Force, v.v.)
  - (Tùy chọn) Các file mô hình: best_eval_<model>.pkl

Quy trình:
  1. Load dữ liệu từ file được chỉ định; giữ lại nhãn gốc (label_raw) để phân tích per-class.
  2. Chia tập Train/Test theo tỉ lệ 70/30 (stratified).
  3. Tuning tham số bằng RandomizedSearchCV + StratifiedKFold (3 folds).
  4. In param grid & top-N kết quả CV.
  5. Đánh giá trên tập test 30%: metrics tổng hợp + per-attack-class report.
  6. Ghi toàn bộ output vào result_hyperparameter.txt.
=============================================================================
"""

import sys
import time
import argparse
import warnings
import io
import os
from datetime import datetime

import pandas as pd
import numpy as np
import joblib

# --- Fix UnicodeEncodeError trên Windows ---
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    confusion_matrix, f1_score, make_scorer,
    matthews_corrcoef, recall_score, precision_score,
    classification_report
)
import xgboost as xgb
import lightgbm as lgb

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)


# =============================================================================
# 0. TEE — ghi đồng thời ra stdout và file
# =============================================================================

class Tee:
    """Redirect stdout ra cả terminal lẫn file."""
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.log      = open(filepath, 'w', encoding='utf-8')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()


# =============================================================================
# 1. CUSTOM METRICS
# =============================================================================

def fpr_score(y_true, y_pred):
    """Tính False Positive Rate: FP / (FP + TN)."""
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        return fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return 0.0


def custom_recall_priority_scorer(y_true, y_pred):
    """
    Scorer tùy chỉnh ưu tiên Recall (Detection Rate).
    Công thức: Recall - 5 * FPR
      - Phần thưởng: Recall cao → bắt được nhiều tấn công.
      - Hình phạt: FPR cao → báo nhầm nhiều (hệ số phạt = 5).
    """
    recall = recall_score(y_true, y_pred, zero_division=0)
    fpr    = fpr_score(y_true, y_pred)
    return recall - 5.0 * fpr


# Đăng ký các scorer
custom_scorer    = make_scorer(custom_recall_priority_scorer, greater_is_better=True)
recall_metric    = make_scorer(recall_score,       greater_is_better=True,  zero_division=0)
precision_metric = make_scorer(precision_score,    greater_is_better=True,  zero_division=0)
f1_metric        = make_scorer(f1_score,           greater_is_better=True,  zero_division=0)
fpr_metric       = make_scorer(fpr_score,          greater_is_better=False)
mcc_metric       = make_scorer(matthews_corrcoef,  greater_is_better=True)


# =============================================================================
# 2. LOAD & PREPROCESS DATA
# =============================================================================

def load_data(filepath, sample_ratio=1.0):
    """
    Đọc file CSV, trả về:
      - X          : features (float32, feature order đã sắp xếp A-Z)
      - y_binary   : nhãn nhị phân (0=BENIGN, 1=ATTACK)
      - y_raw      : nhãn gốc dạng string (để phân tích per-class)
    """
    print(f"\n[+] Đang load: {filepath}")

    if sample_ratio < 1.0:
        print(f"    -> Lấy mẫu theo tỉ lệ {sample_ratio} (nrows=5,000,000)...")
        df = pd.read_csv(filepath, low_memory=False, nrows=5_000_000)
        df = df.sample(frac=sample_ratio, random_state=42)
    else:
        df = pd.read_csv(filepath, low_memory=False)

    # Cột label (cột cuối cùng)
    label_col = df.columns[-1]
    y_raw     = df[label_col].astype(str).str.strip()
    y_binary  = (y_raw.str.upper() != "BENIGN").astype(np.int8)

    X = df.drop(columns=[label_col]).copy()
    X = X.apply(pd.to_numeric, errors='coerce')
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Đồng bộ thứ tự feature (loại bỏ duplicate, sắp A-Z)
    X = X.loc[:, ~X.columns.duplicated()]
    X = X.reindex(sorted(X.columns), axis=1)

    n_attack = int(y_binary.sum())
    n_benign = len(y_binary) - n_attack
    print(f"    Shape  : {X.shape}")
    print(f"    Labels : BENIGN={n_benign:,}  ATTACK={n_attack:,}")

    # Phân phối nhãn gốc
    print(f"\n    Phân phối nhãn gốc (top 15):")
    for lbl, cnt in y_raw.value_counts().head(15).items():
        pct = cnt / len(y_raw) * 100
        print(f"      {lbl:<40} {cnt:>8,}  ({pct:5.2f}%)")

    return X.astype(np.float32), y_binary, y_raw.reset_index(drop=True)


# =============================================================================
# 3. HYPERPARAMETER GRIDS & MODELS
# =============================================================================

def get_param_grid(model_name):
    if model_name == 'RandomForest':
        return {
            'clf__n_estimators'     : [100, 200, 300],
            'clf__max_depth'        : [10, 20, None],
            'clf__min_samples_split': [2, 5],
            'clf__min_samples_leaf' : [1, 2],
            'clf__max_features'     : ['sqrt', 'log2'],
            'clf__class_weight'     : ['balanced', 'balanced_subsample'],
        }
    elif model_name == 'XGBoost':
        return {
            'clf__n_estimators'    : [100, 200, 300],
            'clf__max_depth'       : [3, 6, 10],
            'clf__learning_rate'   : [0.05, 0.1, 0.2],
            'clf__subsample'       : [0.7, 0.9, 1.0],
            'clf__colsample_bytree': [0.7, 0.9, 1.0],
            'clf__scale_pos_weight': [1, 5, 10],
        }
    elif model_name == 'LightGBM':
        return {
            'clf__n_estimators' : [100, 200, 300],
            'clf__max_depth'    : [-1, 10, 20],
            'clf__learning_rate': [0.05, 0.1, 0.2],
            'clf__num_leaves'   : [31, 63, 127],
            'clf__subsample'    : [0.7, 0.9, 1.0],
            'clf__is_unbalance' : [True, False],
        }
    else:
        raise ValueError(f"Model không được hỗ trợ: {model_name}")


def get_model(model_name):
    if model_name == 'RandomForest':
        clf = RandomForestClassifier(n_jobs=-1, random_state=42)
    elif model_name == 'XGBoost':
        clf = xgb.XGBClassifier(
            eval_metric='logloss', n_jobs=-1, random_state=42, verbosity=0
        )
    elif model_name == 'LightGBM':
        clf = lgb.LGBMClassifier(n_jobs=-1, random_state=42, verbose=-1)
    else:
        raise ValueError(f"Model không được hỗ trợ: {model_name}")

    return Pipeline([
        ('scaler', StandardScaler()),
        ('clf',    clf)
    ])


# =============================================================================
# 4. HIỂN THỊ PARAM GRID & TOP CV RESULTS
# =============================================================================

def print_param_grid(model_name, param_grid):
    SEP = "=" * 70
    print(f"\n{SEP}")
    print(f"  PARAM GRID — {model_name}")
    print(SEP)
    total_combos = 1
    for key, vals in param_grid.items():
        param_name = key.replace('clf__', '')
        vals_str   = ', '.join(str(v) for v in vals)
        print(f"  {param_name:<25} : [{vals_str}]")
        total_combos *= len(vals)
    print(f"\n  Tổng tổ hợp có thể: {total_combos:,}  |  Sẽ thử ngẫu nhiên: n_iter lần")
    print(SEP)


def print_top_cv_results(search, top_n=5):
    """In top-N tổ hợp tham số tốt nhất theo CV Custom_IDPS score."""
    cv_results = pd.DataFrame(search.cv_results_)

    # Cột mean test score cho Custom_IDPS (refit metric)
    score_col = 'mean_test_Custom_IDPS'
    if score_col not in cv_results.columns:
        # fallback nếu multi-metric không có
        score_col = 'mean_test_score'

    cv_results = cv_results.sort_values(score_col, ascending=False).head(top_n)

    print(f"\n  TOP-{top_n} TỔ HỢP THAM SỐ (theo CV Custom_IDPS = Recall - 5×FPR):")
    print(f"  {'Rank':<5} {'CV Score':>10} {'Std':>8}   Params")
    print(f"  {'-'*65}")
    for rank, (_, row) in enumerate(cv_results.iterrows(), 1):
        std_col  = score_col.replace('mean_', 'std_')
        std_val  = row.get(std_col, float('nan'))
        params   = {k.replace('clf__', ''): v
                    for k, v in row['params'].items()}
        param_str = '  '.join(f"{k}={v}" for k, v in params.items())
        print(f"  #{rank:<4} {row[score_col]:>10.4f} {std_val:>8.4f}   {param_str}")


# =============================================================================
# 5. PER-ATTACK-CLASS REPORT
# =============================================================================

def print_per_attack_report(y_raw_test, y_pred_binary):
    """
    In báo cáo chi tiết theo từng loại tấn công cụ thể.
    Với mỗi nhãn tấn công, tính:
      - Tổng mẫu (Actual)
      - Detected (TP: model dự đoán ATTACK và đúng)
      - Missed   (FN: model dự đoán BENIGN nhưng là ATTACK)
      - Detection Rate (%)
    """
    SEP = "=" * 70
    print(f"\n{SEP}")
    print(f"  BÁO CÁO CHI TIẾT THEO LOẠI TẤN CÔNG")
    print(SEP)
    print(f"  {'Attack Type':<35} {'Actual':>8} {'Detected':>10} {'Missed':>8} {'DR%':>8}")
    print(f"  {'-'*65}")

    attack_types = sorted([lbl for lbl in y_raw_test.unique()
                           if lbl.upper() != 'BENIGN'])

    for attack in attack_types:
        mask     = (y_raw_test == attack)
        actual   = int(mask.sum())
        if actual == 0:
            continue
        detected = int((mask & (y_pred_binary == 1)).sum())
        missed   = actual - detected
        dr       = detected / actual * 100
        print(f"  {attack:<35} {actual:>8,} {detected:>10,} {missed:>8,} {dr:>7.2f}%")

    # Baris BENIGN (FPR reference)
    benign_mask = (y_raw_test.str.upper() == 'BENIGN')
    n_benign    = int(benign_mask.sum())
    fp_benign   = int((benign_mask & (y_pred_binary == 1)).sum())
    tn_benign   = n_benign - fp_benign
    fpr_b       = fp_benign / n_benign * 100 if n_benign > 0 else 0.0
    print(f"  {'-'*65}")
    print(f"  {'BENIGN (FP Reference)':<35} {n_benign:>8,} {'FP='+str(fp_benign):>10} {tn_benign:>8,} {'FPR='+f'{fpr_b:.2f}%':>8}")
    print(SEP)


# =============================================================================
# 6. MAIN
# =============================================================================

def main(args):
    # --- Load Data (giữ y_raw để phân tích per-class) ---
    X_all, y_all, y_raw_all = load_data(args.data_path, sample_ratio=args.sample_train)

    print(f"\n[+] Thực hiện chia Train/Test theo tỉ lệ 70/30 (stratified)...")
    idx = np.arange(len(X_all))
    idx_train, idx_test = train_test_split(
        idx, test_size=0.3, random_state=42, stratify=y_all
    )
    X_train = X_all.iloc[idx_train].reset_index(drop=True)
    X_test  = X_all.iloc[idx_test].reset_index(drop=True)
    y_train = y_all.iloc[idx_train].reset_index(drop=True)
    y_test  = y_all.iloc[idx_test].reset_index(drop=True)
    y_raw_test = y_raw_all.iloc[idx_test].reset_index(drop=True)

    print(f"    Train : {len(X_train):,} mẫu  |  Test : {len(X_test):,} mẫu")
    del X_all, y_all, y_raw_all  # Giải phóng RAM

    # --- Scoring dict ---
    scoring = {
        'Custom_IDPS': custom_scorer,
        'Recall'      : recall_metric,
        'Precision'   : precision_metric,
        'F1'          : f1_metric,
        'FPR'         : fpr_metric,
        'MCC'         : mcc_metric,
    }

    results_summary = []

    for model_name in args.models:
        param_grid = get_param_grid(model_name)

        # --- In param grid ---
        print_param_grid(model_name, param_grid)

        model = get_model(model_name)
        cv    = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

        search = RandomizedSearchCV(
            estimator           = model,
            param_distributions = param_grid,
            n_iter              = args.n_iter,
            scoring             = scoring,
            refit               = 'Custom_IDPS',
            cv                  = cv,
            verbose             = 1,
            random_state        = 42,
            n_jobs              = args.n_jobs,
            return_train_score  = False,
        )

        print(f"\n[+] Bắt đầu RandomizedSearchCV (n_iter={args.n_iter}, cv=3-fold)...")
        t0 = time.time()
        search.fit(X_train, y_train)
        tuning_time = time.time() - t0

        print(f"\n[OK] Hoàn tất sau {tuning_time/60:.1f} phút.")
        print(f"[+] CV Score tốt nhất (Custom_IDPS): {search.best_score_:.4f}")
        print(f"[+] Tham số tốt nhất:")
        for k, v in sorted(search.best_params_.items()):
            print(f"      {k.replace('clf__', ''):<25} = {v}")

        # --- Top CV results ---
        print_top_cv_results(search, top_n=5)

        # --- Đánh giá trên tập TEST (30%) ---
        best_model = search.best_estimator_
        t_inf      = time.time()
        y_pred     = best_model.predict(X_test)
        inf_us     = (time.time() - t_inf) / len(X_test) * 1_000_000

        cm             = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        recall         = tp / (tp + fn)      if (tp + fn) > 0 else 0.0
        fpr_val        = fp / (fp + tn)      if (fp + tn) > 0 else 0.0
        precision_val  = tp / (tp + fp)      if (tp + fp) > 0 else 0.0
        f1             = f1_score(y_test, y_pred, zero_division=0)
        mcc            = matthews_corrcoef(y_test, y_pred)

        SEP = "=" * 70
        print(f"\n{SEP}")
        print(f"  KẾT QUẢ TỔNG HỢP TRÊN TẬP TEST (30%): {model_name}")
        print(SEP)
        print(f"  Recall  (DR)  : {recall*100:.4f}%  ← {tp:,} / {tp+fn:,} tấn công phát hiện được")
        print(f"  FPR           : {fpr_val*100:.4f}%  ← {fp:,} / {fp+tn:,} benign bị báo nhầm")
        print(f"  Precision     : {precision_val:.4f}")
        print(f"  F1-Score      : {f1:.4f}")
        print(f"  MCC           : {mcc:.4f}")
        print(f"  Latency       : {inf_us:.2f} µs/packet")
        print(f"\n  Confusion Matrix:")
        print(f"                   Dự đoán BENIGN   Dự đoán ATTACK")
        print(f"  Thực tế BENIGN   {tn:>12,}   {fp:>12,}")
        print(f"  Thực tế ATTACK   {fn:>12,}   {tp:>12,}")
        print(SEP)

        # --- Classification report (binary) ---
        print("\n  Classification Report (Binary):")
        print(classification_report(
            y_test, y_pred,
            target_names=['BENIGN', 'ATTACK'],
            digits=4
        ))

        # --- Per-attack-class report ---
        print_per_attack_report(y_raw_test, y_pred)

        results_summary.append({
            'Model'      : model_name,
            'Recall'     : recall,
            'FPR'        : fpr_val,
            'Precision'  : precision_val,
            'F1'         : f1,
            'MCC'        : mcc,
            'Latency_us' : inf_us,
            'Best_Params': {k.replace('clf__', ''): v
                            for k, v in search.best_params_.items()},
        })

        if args.save_model:
            out_path = f"best_eval_{model_name.lower()}.pkl"
            joblib.dump(best_model, out_path)
            print(f"[+] Đã lưu mô hình: {out_path}")

    # --- Bảng tổng kết so sánh ---
    SEP = "=" * 80
    print(f"\n{SEP}")
    print(f"  BẢNG TỔNG HỢP SO SÁNH CÁC MODEL (Test 30%)")
    print(SEP)
    print(f"  {'Model':<15} {'Recall':>8} {'FPR':>9} {'Precision':>10} {'F1':>8} {'MCC':>8} {'Latency(µs)':>12}")
    print(f"  {'-'*75}")
    for r in results_summary:
        print(
            f"  {r['Model']:<15} "
            f"{r['Recall']*100:>7.2f}% "
            f"{r['FPR']*100:>8.4f}% "
            f"{r['Precision']:>10.4f} "
            f"{r['F1']:>8.4f} "
            f"{r['MCC']:>8.4f} "
            f"{r['Latency_us']:>11.2f}"
        )
    print(SEP)

    # --- Tham số tốt nhất của từng model ---
    print(f"\n  TÓM TẮT THAM SỐ TỐT NHẤT TỪNG MODEL:")
    print(f"  {'-'*75}")
    for r in results_summary:
        print(f"\n  [{r['Model']}]")
        for k, v in r['Best_Params'].items():
            print(f"    {k:<25} = {v}")


# =============================================================================
# 7. CLI ARGUMENTS
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate IDPS models on CIC-IDS-2017 30-feature dataset (70/30 split)"
    )
    parser.add_argument(
        '--data_path', type=str,
        default=r'f:/IPS/datasets/cic_ids2017_preprocessed(70).csv',
        help='File CSV dùng để train/test'
    )
    parser.add_argument(
        '--models', nargs='+',
        default=['RandomForest', 'XGBoost', 'LightGBM'],
        help='Danh sách model (mặc định: RandomForest XGBoost LightGBM)'
    )
    parser.add_argument(
        '--n_iter', type=int, default=10,
        help='Số tổ hợp RandomizedSearchCV thử (mặc định: 10)'
    )
    parser.add_argument(
        '--n_jobs', type=int, default=1,
        help='Số luồng song song trong CV (mặc định: 1)'
    )
    parser.add_argument(
        '--sample_train', type=float, default=1.0,
        help='Tỉ lệ lấy mẫu toàn bộ data trước khi chia 70/30 (mặc định: 1.0)'
    )
    parser.add_argument(
        '--save_model', action='store_true',
        help='Lưu mô hình tốt nhất ra file .pkl'
    )
    parser.add_argument(
        '--output', type=str,
        default=r'f:/IPS/results/result_hyperparameter(2).txt',
        help='Đường dẫn file lưu kết quả (mặc định: f:/IPS/results/result_hyperparameter(2).txt)'
    )

    args = parser.parse_args()

    # Tạo thư mục output nếu chưa có
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    # Khởi động Tee: ghi đồng thời ra terminal và file
    tee = Tee(args.output)
    sys.stdout = tee

    print("=" * 70)
    print(f"  EVALUATE_FN — CIC-IDS-2017 (70/30 Split, 30 Features)")
    print(f"  Bắt đầu : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Dataset  : {args.data_path}")
    print(f"  Models   : {', '.join(args.models)}")
    print(f"  n_iter   : {args.n_iter}  |  n_jobs : {args.n_jobs}")
    print(f"  Output   : {args.output}")
    print("=" * 70)

    try:
        main(args)
        print(f"\n[DONE] Kết thúc : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[DONE] Kết quả đã lưu vào: {args.output}")
    finally:
        sys.stdout = tee.terminal
        tee.close()
