# -*- coding: utf-8 -*-
"""
=============================================================================
Tên file   : run_botnet_excluded_experiment.py
Mục tiêu   : Chạy experiment CICIDS2017 năm lớp có temporal final-test,
             cross-validation, feature selection và kiểm toán artifact.
Input      : datasets/cic2017_nfs_labeled_57features.csv.
Output     : Data split, model, metric, log và hash trong experiments/<id>.
Ngày tạo   : 2026-09-08
Ngày sửa   : 2026-09-13
Lí do sửa  : Bổ sung Connection Count 10s past-only làm candidate feature;
             giữ nguyên khóa dedup gốc để so sánh công bằng với baseline.
=============================================================================
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import logging
import math
import os
import platform
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import optuna
import pandas as pd
import sklearn
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder

from connection_count import (
    CONNECTION_COUNT_FEATURE,
    CONNECTION_KEY_COLUMNS,
    CONNECTION_WINDOW_MS,
    compute_connection_counts,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPERIMENT_ID = "20260913_connection_count_10s_v2"
RAW_DATA = PROJECT_ROOT / "datasets" / "cic2017_nfs_labeled_57features.csv"

LABEL_COLUMN = "Label"
TIME_COLUMN = "bidirectional_first_seen_ms"
TEST_FRACTION = 0.20
RANDOM_SEED = 42
CV_SPLITS = 5
DEFAULT_TRIALS = 30
IMPORTANCE_THRESHOLD = 0.95
RUNTIME_THRESHOLD = 0.85
RF_N_JOBS = 1

METADATA_COLUMNS = {
    "Source IP", "Destination IP", "Timestamp", "Flow ID", "Destination Port",
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
}

DROPPED_FEATURES = {
    "Fwd Header Length", "Bwd Header Length", "act_data_pkt_fwd",
    "CWE Flag Count", "ECE Flag Count", "Bwd PSH Flags", "Bwd URG Flags",
}

SMOTE_CLASSES = ["Brute Force", "Web Attack"]
FINAL_CLASSES = ["BENIGN", "Brute Force", "DoS/DDoS", "PortScan", "Web Attack"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stage",
        required=True,
        choices=["prepare", "tune", "train-evaluate", "verify", "all"],
    )
    parser.add_argument("--experiment-id", default=DEFAULT_EXPERIMENT_ID)
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--rf-jobs", type=int, default=1)
    return parser.parse_args()


def experiment_paths(experiment_id: str) -> dict[str, Path]:
    root = PROJECT_ROOT / "experiments" / experiment_id
    paths = {
        "root": root,
        "data": root / "data",
        "models": root / "models",
        "results": root / "results",
        "logs": root / "logs",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def setup_logger(paths: dict[str, Path], stage: str) -> logging.Logger:
    logger = logging.getLogger(f"botnet_excluded.{stage}")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    file_handler = logging.FileHandler(paths["logs"] / f"{stage}.log", mode="a", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(stream)
    logger.addHandler(file_handler)
    return logger


def json_default(value):
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value)}")


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=json_default), encoding="utf-8")


def connection_count_contract() -> dict:
    """Schema persisted with artifacts to prevent training-serving skew."""
    return {
        "feature": CONNECTION_COUNT_FEATURE,
        "window_ms": CONNECTION_WINDOW_MS,
        "window_interval": "(t-window, t]",
        "includes_current_flow": True,
        "key_columns": list(CONNECTION_KEY_COLUMNS),
        "timestamp_column": TIME_COLUMN,
        "causal": True,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def record_environment(paths: dict[str, Path], stage: str) -> None:
    command = " ".join([sys.executable, *sys.argv])
    with (paths["logs"] / "command_history.log").open("a", encoding="utf-8") as handle:
        handle.write(f"{datetime.now(timezone.utc).isoformat()} | {command}\n")
    environment = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "command": command,
        "python": sys.version,
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
        "imbalanced_learn": __import__("imblearn").__version__,
        "xgboost": xgb.__version__,
        "lightgbm": lgb.__version__,
        "optuna": optuna.__version__,
        "joblib": joblib.__version__,
    }
    write_json(paths["logs"] / f"environment_{stage}.json", environment)


def map_label(raw_label: object) -> tuple[str | None, str]:
    label = str(raw_label).strip()
    if label.upper() == "BENIGN":
        return "BENIGN", "kept"
    if "Bot" in label:
        return None, "excluded_botnet"
    if "Infiltration" in label:
        return None, "excluded_infiltration"
    if "Heartbleed" in label:
        return None, "excluded_heartbleed"
    if "PortScan" in label:
        return "PortScan", "kept"
    if "DoS" in label or "DDoS" in label:
        return "DoS/DDoS", "kept"
    if "Web Attack" in label:
        return "Web Attack", "kept"
    if "Patator" in label:
        return "Brute Force", "kept"
    return None, "excluded_unknown"


def prepare_data(paths: dict[str, Path], logger: logging.Logger) -> None:
    started = time.time()
    logger.info("PREPARE started; input=%s", RAW_DATA)
    if not RAW_DATA.exists():
        raise FileNotFoundError(RAW_DATA)

    header = pd.read_csv(RAW_DATA, nrows=0).columns.str.strip().tolist()
    raw_features = [c for c in header if c not in METADATA_COLUMNS and c != LABEL_COLUMN]
    all_features = [*raw_features, CONNECTION_COUNT_FEATURE]
    candidate_features = [c for c in all_features if c not in DROPPED_FEATURES]
    usecols = [*CONNECTION_KEY_COLUMNS, TIME_COLUMN, *raw_features, LABEL_COLUMN]
    logger.info("Feature inventory: raw_numeric=%d, candidate=%d, dropped=%s", len(all_features), len(candidate_features), sorted(DROPPED_FEATURES))

    logger.info(
        "Computing %s with a past-only %d ms window and key=%s",
        CONNECTION_COUNT_FEATURE,
        CONNECTION_WINDOW_MS,
        CONNECTION_KEY_COLUMNS,
    )
    metadata = pd.read_csv(
        RAW_DATA,
        usecols=[*CONNECTION_KEY_COLUMNS, TIME_COLUMN],
        low_memory=False,
    )
    connection_counts = compute_connection_counts(metadata)
    del metadata
    gc.collect()
    logger.info(
        "%s computed: rows=%s min=%.0f median=%.0f p95=%.0f max=%.0f",
        CONNECTION_COUNT_FEATURE,
        f"{len(connection_counts):,}",
        np.nanmin(connection_counts),
        np.nanmedian(connection_counts),
        np.nanquantile(connection_counts, 0.95),
        np.nanmax(connection_counts),
    )

    benign_chunks: list[pd.DataFrame] = []
    attack_chunks: list[pd.DataFrame] = []
    raw_label_counts: Counter[str] = Counter()
    exclusion_counts: Counter[str] = Counter()
    rows_raw = 0
    rows_invalid_numeric = 0
    benign_valid_rows_before_dedup = 0

    row_offset = 0
    for chunk_no, chunk in enumerate(pd.read_csv(RAW_DATA, usecols=usecols, chunksize=100_000, low_memory=False), start=1):
        chunk.columns = chunk.columns.str.strip()
        rows_raw += len(chunk)
        next_offset = row_offset + len(chunk)
        chunk[CONNECTION_COUNT_FEATURE] = connection_counts[row_offset:next_offset]
        row_offset = next_offset
        raw_label_counts.update(chunk[LABEL_COLUMN].astype(str).str.strip().value_counts().to_dict())

        mapped = chunk[LABEL_COLUMN].map(map_label)
        chunk["_mapped_label"] = mapped.map(lambda item: item[0])
        chunk["_status"] = mapped.map(lambda item: item[1])
        exclusion_counts.update(chunk["_status"].value_counts().to_dict())
        chunk = chunk[chunk["_mapped_label"].notna()].copy()
        chunk[LABEL_COLUMN] = chunk.pop("_mapped_label")
        chunk.drop(columns=["_status"], inplace=True)

        before_numeric = len(chunk)
        chunk[TIME_COLUMN] = pd.to_numeric(chunk[TIME_COLUMN], errors="coerce")
        for column in all_features:
            chunk[column] = pd.to_numeric(chunk[column], errors="coerce").astype("float32")
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(subset=[TIME_COLUMN, *all_features], inplace=True)
        rows_invalid_numeric += before_numeric - len(chunk)
        chunk[TIME_COLUMN] = chunk[TIME_COLUMN].astype("int64")

        benign = chunk[chunk[LABEL_COLUMN] == "BENIGN"]
        benign_valid_rows_before_dedup += len(benign)
        # Giữ cùng tập mẫu với baseline: synthetic context feature không được
        # thay đổi định nghĩa duplicate của 58 feature flow gốc.
        benign = benign.drop_duplicates(subset=[*raw_features, LABEL_COLUMN])
        attacks = chunk[chunk[LABEL_COLUMN] != "BENIGN"]
        benign_chunks.append(benign)
        attack_chunks.append(attacks)
        if chunk_no % 5 == 0:
            logger.info("Read chunk %d; cumulative raw rows=%s", chunk_no, f"{rows_raw:,}")
        del chunk, benign, attacks, mapped
        gc.collect()

    if row_offset != len(connection_counts):
        raise RuntimeError(
            f"Connection count alignment mismatch: CSV={row_offset}, counts={len(connection_counts)}"
        )
    del connection_counts
    gc.collect()

    benign_df = pd.concat(benign_chunks, ignore_index=True)
    benign_before_global_dedup = len(benign_df)
    benign_df.drop_duplicates(subset=[*raw_features, LABEL_COLUMN], inplace=True)
    benign_after_global_dedup = len(benign_df)
    attack_df = pd.concat(attack_chunks, ignore_index=True)
    del benign_chunks, attack_chunks
    gc.collect()

    clean = pd.concat([benign_df, attack_df], ignore_index=True)
    del benign_df, attack_df
    gc.collect()
    clean = clean[[TIME_COLUMN, *candidate_features, LABEL_COLUMN]]
    connection_distribution = (
        clean.groupby(LABEL_COLUMN)[CONNECTION_COUNT_FEATURE]
        .describe(percentiles=[0.50, 0.95, 0.99])
        .reset_index()
    )
    connection_distribution.to_csv(
        paths["results"] / "connection_count_distribution.csv", index=False
    )

    development_parts: list[pd.DataFrame] = []
    final_parts: list[pd.DataFrame] = []
    split_rows = []
    for class_name in FINAL_CLASSES:
        group = clean[clean[LABEL_COLUMN] == class_name].sort_values(TIME_COLUMN, kind="mergesort")
        if group.empty:
            raise RuntimeError(f"Required class absent after cleaning: {class_name}")
        nominal_test = max(1, math.ceil(len(group) * TEST_FRACTION))
        nominal_boundary = len(group) - nominal_test
        boundary_time = int(group.iloc[nominal_boundary][TIME_COLUMN])
        dev = group[group[TIME_COLUMN] < boundary_time].copy()
        final = group[group[TIME_COLUMN] >= boundary_time].copy()
        if dev.empty or final.empty:
            raise RuntimeError(f"Temporal split failed for {class_name}")
        development_parts.append(dev)
        final_parts.append(final)
        split_rows.append({
            "class": class_name,
            "clean_total": len(group),
            "development": len(dev),
            "final_test": len(final),
            "final_test_ratio": len(final) / len(group),
            "boundary_timestamp_ms": boundary_time,
            "boundary_utc": datetime.fromtimestamp(boundary_time / 1000, tz=timezone.utc).isoformat(),
            "max_development_timestamp_ms": int(dev[TIME_COLUMN].max()),
            "min_final_timestamp_ms": int(final[TIME_COLUMN].min()),
        })
        logger.info("Temporal split %-12s total=%s dev=%s final=%s boundary=%s", class_name, f"{len(group):,}", f"{len(dev):,}", f"{len(final):,}", split_rows[-1]["boundary_utc"])

    development = pd.concat(development_parts, ignore_index=True)
    final_test = pd.concat(final_parts, ignore_index=True)
    del clean, development_parts, final_parts
    gc.collect()

    # Timestamp is retained only for the split audit and excluded from model features.
    development.drop(columns=[TIME_COLUMN], inplace=True)
    final_test.drop(columns=[TIME_COLUMN], inplace=True)
    development_path = paths["data"] / "development.csv"
    final_test_path = paths["data"] / "final_test.csv"
    development.to_csv(development_path, index=False)
    final_test.to_csv(final_test_path, index=False)

    pd.DataFrame(split_rows).to_csv(paths["results"] / "temporal_split_audit.csv", index=False)
    lineage = {
        "experiment_id": paths["root"].name,
        "input_file": str(RAW_DATA),
        "input_sha256": sha256_file(RAW_DATA),
        "raw_rows": rows_raw,
        "raw_label_counts": dict(raw_label_counts),
        "mapping_status_counts": dict(exclusion_counts),
        "invalid_numeric_rows_after_scope_filter": rows_invalid_numeric,
        "benign_rows_before_any_dedup": benign_valid_rows_before_dedup,
        "benign_rows_after_chunk_dedup": benign_before_global_dedup,
        "benign_rows_after_global_dedup": benign_after_global_dedup,
        "benign_duplicates_removed_within_chunks": benign_valid_rows_before_dedup - benign_before_global_dedup,
        "benign_duplicates_removed_across_chunks": benign_before_global_dedup - benign_after_global_dedup,
        "benign_duplicates_removed_total": benign_valid_rows_before_dedup - benign_after_global_dedup,
        "benign_dedup_basis": "Original raw flow features only; synthetic Connection Count excluded to preserve baseline sample membership",
        "candidate_features": candidate_features,
        "connection_count_definition": connection_count_contract(),
        "dropped_features": sorted(DROPPED_FEATURES),
        "excluded_ml_labels": ["Botnet", "Infiltration", "Heartbleed"],
        "split_strategy": "Per-mapped-class chronological 80/20 split; all equal boundary timestamps assigned to final test",
        "random_seed": RANDOM_SEED,
        "development_rows": len(development),
        "final_test_rows": len(final_test),
        "development_class_counts": development[LABEL_COLUMN].value_counts().to_dict(),
        "final_test_class_counts": final_test[LABEL_COLUMN].value_counts().to_dict(),
        "development_sha256": sha256_file(development_path),
        "final_test_sha256": sha256_file(final_test_path),
        "elapsed_seconds": time.time() - started,
    }
    write_json(paths["results"] / "data_lineage.json", lineage)
    logger.info("PREPARE complete; development=%s final_test=%s elapsed=%.1fs", f"{len(development):,}", f"{len(final_test):,}", time.time() - started)


def create_tuning_subset(X: pd.DataFrame, y: pd.Series) -> tuple[pd.DataFrame, pd.Series, dict]:
    frame = X.copy()
    frame[LABEL_COLUMN] = y.to_numpy()
    limits = {
        "BENIGN": 80_000,
        "DoS/DDoS": 20_000,
        "PortScan": 20_000,
        "Brute Force": None,
        "Web Attack": None,
    }
    parts = []
    selected_counts = {}
    for class_name in FINAL_CLASSES:
        group = frame[frame[LABEL_COLUMN] == class_name]
        limit = limits[class_name]
        if limit is not None and len(group) > limit:
            group = group.sample(n=limit, random_state=RANDOM_SEED)
        parts.append(group)
        selected_counts[class_name] = len(group)
    tuning = pd.concat(parts, ignore_index=True)
    return tuning.drop(columns=[LABEL_COLUMN]), tuning[LABEL_COLUMN], selected_counts


def make_base_model(model_name: str, larger: bool = False):
    estimators = 50 if larger else 30
    depth = 8 if larger else 6
    if model_name == "xgboost":
        return xgb.XGBClassifier(
            n_estimators=estimators, max_depth=depth, random_state=RANDOM_SEED,
            n_jobs=-1, eval_metric="mlogloss", tree_method="hist",
        )
    if model_name == "lightgbm":
        return lgb.LGBMClassifier(
            n_estimators=estimators, max_depth=depth, random_state=RANDOM_SEED,
            n_jobs=-1, verbosity=-1,
        )
    return ExtraTreesClassifier(
        n_estimators=estimators, max_depth=(12 if larger else 10),
        # joblib thread-pool creation is blocked in some managed Windows
        # environments; one worker keeps the run portable and reproducible.
        random_state=RANDOM_SEED, n_jobs=RF_N_JOBS,
    )


def select_features(model_name: str, X: pd.DataFrame, y: np.ndarray | pd.Series) -> tuple[list[str], list[dict]]:
    base = make_base_model(model_name, larger=False)
    base.fit(X, y)
    importances = np.asarray(base.feature_importances_, dtype=float)
    order = np.argsort(importances)[::-1]
    cumulative = np.cumsum(importances[order])
    count = int(np.searchsorted(cumulative, IMPORTANCE_THRESHOLD, side="left") + 1)
    count = max(5, min(count, X.shape[1]))
    selected = [X.columns[i] for i in order[:count]]
    ranking = [
        {
            "rank": rank + 1,
            "feature": X.columns[index],
            "importance": float(importances[index]),
            "cumulative_importance": float(cumulative[rank]),
            "selected": rank < count,
        }
        for rank, index in enumerate(order)
    ]
    return selected, ranking


def smote_resample(X: pd.DataFrame, y: np.ndarray, encoder: LabelEncoder) -> tuple[pd.DataFrame, np.ndarray, dict]:
    counts = pd.Series(y).value_counts()
    strategy = {}
    for class_name in SMOTE_CLASSES:
        class_id = int(encoder.transform([class_name])[0])
        original = int(counts[class_id])
        target = original * 10
        if target > original:
            strategy[class_id] = target
    if not strategy:
        return X, y, {}
    min_count = min(int(counts[class_id]) for class_id in strategy)
    neighbors = max(1, min(5, min_count - 1))
    sampler = SMOTE(sampling_strategy=strategy, random_state=RANDOM_SEED, k_neighbors=neighbors)
    X_resampled, y_resampled = sampler.fit_resample(X, y)
    readable = {str(encoder.inverse_transform([class_id])[0]): target for class_id, target in strategy.items()}
    return X_resampled, y_resampled, {"targets": readable, "k_neighbors": neighbors}


def suggest_params(trial: optuna.Trial, model_name: str) -> dict:
    if model_name == "xgboost":
        return {
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
            "n_estimators": trial.suggest_int("n_estimators", 50, 150),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
        }
    if model_name == "lightgbm":
        return {
            "max_depth": trial.suggest_int("max_depth", 3, 15),
            "num_leaves": trial.suggest_int("num_leaves", 8, 128),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
            "n_estimators": trial.suggest_int("n_estimators", 50, 150),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
        }
    return {
        "max_depth": trial.suggest_int("max_depth", 5, 25),
        "n_estimators": trial.suggest_int("n_estimators", 50, 150),
        "min_samples_split": trial.suggest_int("min_samples_split", 2, 10),
        "min_samples_leaf": trial.suggest_int("min_samples_leaf", 1, 5),
    }


def create_model(model_name: str, params: dict, *, binary: bool = False):
    common = dict(params)
    common.update({"random_state": RANDOM_SEED, "n_jobs": -1})
    if model_name == "xgboost":
        common.update({
            "objective": "binary:logistic" if binary else "multi:softprob",
            "eval_metric": "logloss" if binary else "mlogloss",
            "tree_method": "hist",
        })
        return xgb.XGBClassifier(**common)
    if model_name == "lightgbm":
        common.update({"verbosity": -1, "objective": "binary" if binary else "multiclass"})
        return lgb.LGBMClassifier(**common)
    common["n_jobs"] = RF_N_JOBS
    return RandomForestClassifier(**common)


def tune_models(paths: dict[str, Path], logger: logging.Logger, requested_trials: int) -> None:
    started = time.time()
    development_path = paths["data"] / "development.csv"
    if not development_path.exists():
        raise FileNotFoundError("Run --stage prepare first")
    frame = pd.read_csv(development_path, low_memory=False)
    features = [c for c in frame.columns if c != LABEL_COLUMN]
    X = frame[features]
    y = frame[LABEL_COLUMN]
    encoder = LabelEncoder().fit(y)
    if list(encoder.classes_) != sorted(FINAL_CLASSES):
        raise RuntimeError(f"Unexpected classes: {list(encoder.classes_)}")
    X_tuning, y_tuning, tuning_counts = create_tuning_subset(X, y)
    y_encoded = pd.Series(encoder.transform(y_tuning), index=y_tuning.index)
    logger.info("TUNING subset rows=%s counts=%s", f"{len(X_tuning):,}", tuning_counts)

    models = ["lightgbm", "random_forest", "xgboost"]
    summaries = []
    storage_path = (paths["results"] / "optuna.db").resolve().as_posix()
    storage_url = f"sqlite:///{storage_path}"

    for model_name in models:
        logger.info("OPTUNA model=%s requested_completed_trials=%d", model_name, requested_trials)

        def objective(trial: optuna.Trial) -> float:
            params = suggest_params(trial, model_name)
            cv = StratifiedKFold(n_splits=CV_SPLITS, shuffle=True, random_state=RANDOM_SEED)
            fold_scores = []
            fold_feature_counts = []
            fold_features = []
            for fold_no, (train_idx, validation_idx) in enumerate(cv.split(X_tuning, y_encoded), start=1):
                X_train = X_tuning.iloc[train_idx]
                X_validation = X_tuning.iloc[validation_idx]
                y_train = y_encoded.iloc[train_idx].to_numpy()
                y_validation = y_encoded.iloc[validation_idx].to_numpy()
                selected, _ = select_features(model_name, X_train, y_train)
                X_train_selected = X_train[selected]
                X_validation_selected = X_validation[selected]
                X_resampled, y_resampled, _ = smote_resample(X_train_selected, y_train, encoder)
                model = create_model(model_name, params)
                model.fit(X_resampled, y_resampled)
                prediction = model.predict(X_validation_selected)
                score = f1_score(y_validation, prediction, average="macro")
                fold_scores.append(float(score))
                fold_feature_counts.append(len(selected))
                fold_features.append(selected)
                del model, X_resampled, y_resampled
                gc.collect()
            trial.set_user_attr("fold_scores", fold_scores)
            trial.set_user_attr("fold_feature_counts", fold_feature_counts)
            trial.set_user_attr("fold_features", fold_features)
            trial.set_user_attr("cv_std", float(np.std(fold_scores, ddof=1)))
            return float(np.mean(fold_scores))

        sampler = optuna.samplers.TPESampler(seed=RANDOM_SEED)
        study = optuna.create_study(
            study_name=f"{paths['root'].name}_{model_name}",
            storage=storage_url,
            load_if_exists=True,
            direction="maximize",
            sampler=sampler,
        )
        completed = len([trial for trial in study.trials if trial.state == optuna.trial.TrialState.COMPLETE])
        remaining = max(0, requested_trials - completed)
        if remaining:
            def callback(_study, trial):
                logger.info("TRIAL model=%s number=%d value=%.6f", model_name, trial.number, trial.value)
            study.optimize(objective, n_trials=remaining, callbacks=[callback], gc_after_trial=True)
        best = study.best_trial
        fold_scores = [float(v) for v in best.user_attrs["fold_scores"]]
        summary = {
            "model": model_name,
            "best_trial": best.number,
            "cv_macro_f1_mean": float(np.mean(fold_scores)),
            "cv_macro_f1_std": float(np.std(fold_scores, ddof=1)),
            "fold_scores": fold_scores,
            "fold_feature_counts": best.user_attrs["fold_feature_counts"],
            "best_params": best.params,
            "completed_trials": len([trial for trial in study.trials if trial.state == optuna.trial.TrialState.COMPLETE]),
        }
        summaries.append(summary)
        study.trials_dataframe().to_csv(paths["results"] / f"optuna_trials_{model_name}.csv", index=False)
        logger.info("BEST model=%s CV macro-F1=%.6f +/- %.6f params=%s", model_name, summary["cv_macro_f1_mean"], summary["cv_macro_f1_std"], best.params)

    winner = max(summaries, key=lambda item: item["cv_macro_f1_mean"])
    payload = {
        "experiment_id": paths["root"].name,
        "selection_rule": "Highest five-fold development CV macro-F1 mean; final test not accessed during selection",
        "random_seed": RANDOM_SEED,
        "cv_splits": CV_SPLITS,
        "requested_trials_per_model": requested_trials,
        "tuning_subset_counts": tuning_counts,
        "smote_classes": SMOTE_CLASSES,
        "models": summaries,
        "winner": winner["model"],
        "winner_params": winner["best_params"],
        "elapsed_seconds": time.time() - started,
    }
    write_json(paths["results"] / "model_selection.json", payload)
    pd.DataFrame([
        {
            "model": item["model"],
            "cv_macro_f1_mean": item["cv_macro_f1_mean"],
            "cv_macro_f1_std": item["cv_macro_f1_std"],
            "best_trial": item["best_trial"],
            "completed_trials": item["completed_trials"],
            "fold_feature_counts": json.dumps(item["fold_feature_counts"]),
            "best_params": json.dumps(item["best_params"]),
        }
        for item in summaries
    ]).to_csv(paths["results"] / "model_selection_summary.csv", index=False)
    logger.info("TUNING complete; winner=%s elapsed=%.1fs", winner["model"], time.time() - started)


def metric_payload(y_true, y_pred, labels) -> dict:
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "f1_macro": f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0),
        "precision_macro": precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0),
        "recall_macro": recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0),
        "classification_report": classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }


def benchmark_predict(callable_predict, repeats: int = 5) -> dict:
    callable_predict()  # warm-up
    durations = []
    rows = None
    for _ in range(repeats):
        started = time.perf_counter()
        output = callable_predict()
        durations.append(time.perf_counter() - started)
        rows = len(output)
    per_flow_ms = np.asarray(durations) / rows * 1000.0
    return {
        "measurement": "amortized bulk inference; excludes feature extraction, serialization, flow timeout, Suricata and firewall actions",
        "warmup_runs": 1,
        "measured_runs": repeats,
        "batch_rows": rows,
        "total_seconds_each_run": durations,
        "mean_ms_per_flow": float(per_flow_ms.mean()),
        "std_ms_per_flow": float(per_flow_ms.std(ddof=1)),
        "median_ms_per_flow": float(np.median(per_flow_ms)),
    }


def train_and_evaluate(paths: dict[str, Path], logger: logging.Logger) -> None:
    started = time.time()
    selection_path = paths["results"] / "model_selection.json"
    if not selection_path.exists():
        raise FileNotFoundError("Run --stage tune first")
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    winner = selection["winner"]
    params = selection["winner_params"]
    logger.info("TRAIN-EVALUATE locked winner=%s params=%s", winner, params)

    development = pd.read_csv(paths["data"] / "development.csv", low_memory=False)
    features = [column for column in development.columns if column != LABEL_COLUMN]
    X_development = development[features]
    y_development = development[LABEL_COLUMN]
    encoder = LabelEncoder().fit(y_development)
    if list(encoder.classes_) != sorted(FINAL_CLASSES):
        raise RuntimeError(f"Unexpected final labels: {list(encoder.classes_)}")

    selected_features, ranking = select_features(winner, X_development, encoder.transform(y_development))
    pd.DataFrame(ranking).to_csv(paths["results"] / "final_feature_ranking.csv", index=False)
    X_development_selected = X_development[selected_features]
    logger.info("Locked features count=%d names=%s", len(selected_features), selected_features)

    y_multi_development = encoder.transform(y_development)
    y_binary_development = (y_development != "BENIGN").astype(int).to_numpy()

    binary_model = create_model(winner, params, binary=True)
    binary_model.fit(X_development_selected, y_binary_development)
    X_resampled, y_resampled, smote_info = smote_resample(X_development_selected, y_multi_development, encoder)
    multiclass_model = create_model(winner, params, binary=False)
    multiclass_model.fit(X_resampled, y_resampled)
    del X_resampled, y_resampled
    gc.collect()

    joblib.dump(binary_model, paths["models"] / "active_model.pkl", compress=3)
    joblib.dump(multiclass_model, paths["models"] / "classification_model.pkl", compress=3)
    joblib.dump(encoder, paths["models"] / "label_encoder.pkl", compress=3)
    write_json(paths["models"] / "model_metadata.json", {
        "experiment_id": paths["root"].name,
        "winner": winner,
        "params": params,
        "selected_features": selected_features,
        "classes": list(encoder.classes_),
        "smote": smote_info,
        "random_seed": RANDOM_SEED,
        "runtime_threshold": RUNTIME_THRESHOLD,
        "connection_count_contract": connection_count_contract(),
    })

    # Load the final test only after the model family, hyperparameters,
    # feature subset and fitted models have all been locked.
    final_test = pd.read_csv(paths["data"] / "final_test.csv", low_memory=False)
    X_final = final_test[selected_features]
    y_final = final_test[LABEL_COLUMN]
    y_multi_final = encoder.transform(y_final)
    y_binary_final = (y_final != "BENIGN").astype(int).to_numpy()

    binary_prediction = binary_model.predict(X_final).astype(int)
    multiclass_prediction_id = multiclass_model.predict(X_final).astype(int)
    multiclass_prediction = encoder.inverse_transform(multiclass_prediction_id)
    labels = list(encoder.classes_)

    binary_cm = confusion_matrix(y_binary_final, binary_prediction, labels=[0, 1])
    tn, fp, fn, tp = [int(value) for value in binary_cm.ravel()]
    binary_metrics = {
        "accuracy": accuracy_score(y_binary_final, binary_prediction),
        "f1_weighted": f1_score(y_binary_final, binary_prediction, average="weighted"),
        "fpr": fp / (fp + tn),
        "fnr": fn / (fn + tp),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "confusion_matrix": binary_cm.tolist(),
    }
    multiclass_metrics = metric_payload(y_final.to_numpy(), multiclass_prediction, labels)

    binary_probability = binary_model.predict_proba(X_final)[:, 1]
    multiclass_probability = multiclass_model.predict_proba(X_final)
    class_array = np.asarray(encoder.classes_)
    benign_index = int(np.where(class_array == "BENIGN")[0][0])
    fusion_score = np.maximum(binary_probability, 1.0 - multiclass_probability[:, benign_index])
    is_attack = fusion_score > RUNTIME_THRESHOLD
    multiclass_argmax = multiclass_probability.argmax(axis=1)
    attack_indices = np.delete(np.arange(len(class_array)), benign_index)
    best_attack = attack_indices[np.delete(multiclass_probability, benign_index, axis=1).argmax(axis=1)]
    final_indices = np.where(~is_attack, benign_index, np.where(multiclass_argmax != benign_index, multiclass_argmax, best_attack))
    fusion_prediction = class_array[final_indices]
    fusion_metrics = metric_payload(y_final.to_numpy(), fusion_prediction, labels)
    fusion_attack_cm = confusion_matrix(y_binary_final, is_attack.astype(int), labels=[0, 1])
    ftn, ffp, ffn, ftp = [int(value) for value in fusion_attack_cm.ravel()]
    fusion_metrics["attack_confusion_matrix"] = fusion_attack_cm.tolist()
    fusion_metrics["attack_fpr"] = ffp / (ffp + ftn)
    fusion_metrics["attack_fnr"] = ffn / (ffn + ftp)
    fusion_metrics["runtime_threshold"] = RUNTIME_THRESHOLD

    latency = {
        "binary_predict": benchmark_predict(lambda: binary_model.predict(X_final)),
        "multiclass_predict": benchmark_predict(lambda: multiclass_model.predict(X_final)),
        "binary_predict_proba": benchmark_predict(lambda: binary_model.predict_proba(X_final)),
        "multiclass_predict_proba": benchmark_predict(lambda: multiclass_model.predict_proba(X_final)),
    }

    results = {
        "experiment_id": paths["root"].name,
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_family": winner,
        "final_test_rows": len(final_test),
        "final_test_class_counts": y_final.value_counts().to_dict(),
        "selected_features": selected_features,
        "connection_count_contract": connection_count_contract(),
        "binary_component": binary_metrics,
        "multiclass_component": multiclass_metrics,
        "runtime_ml_fusion": fusion_metrics,
        "latency": latency,
        "elapsed_seconds": time.time() - started,
    }
    write_json(paths["results"] / "final_evaluation.json", results)
    pd.DataFrame(multiclass_metrics["confusion_matrix"], index=labels, columns=labels).to_csv(paths["results"] / "multiclass_component_confusion_matrix.csv")
    pd.DataFrame(fusion_metrics["confusion_matrix"], index=labels, columns=labels).to_csv(paths["results"] / "runtime_fusion_confusion_matrix.csv")
    pd.DataFrame(multiclass_metrics["classification_report"]).transpose().to_csv(paths["results"] / "multiclass_component_classification_report.csv")
    pd.DataFrame(fusion_metrics["classification_report"]).transpose().to_csv(paths["results"] / "runtime_fusion_classification_report.csv")

    write_report_artifacts(paths, selection, results)
    logger.info("FINAL binary TN=%d FP=%d FN=%d TP=%d", tn, fp, fn, tp)
    logger.info("FINAL multiclass macro-F1=%.6f weighted-F1=%.6f", multiclass_metrics["f1_macro"], multiclass_metrics["f1_weighted"])
    logger.info("FINAL runtime fusion macro-F1=%.6f attack-FPR=%.6f attack-FNR=%.6f", fusion_metrics["f1_macro"], fusion_metrics["attack_fpr"], fusion_metrics["attack_fnr"])
    logger.info("TRAIN-EVALUATE complete elapsed=%.1fs", time.time() - started)


def write_report_artifacts(paths: dict[str, Path], selection: dict, results: dict) -> None:
    summaries = selection["models"]
    report = [
        f"# Reproducible Experiment Report: {paths['root'].name}",
        "",
        "## Scope and protocol",
        "",
        "Botnet, Infiltration and Heartbleed were excluded from supervised ML training. "
        "The model family was selected exclusively by five-fold cross-validation on the development partition. "
        "The chronological final test partition was not used for model, hyperparameter or feature selection; predictions were generated once after the configuration was locked.",
        "Connection Count 10s was supplied as an ordinary candidate feature and was not forced into the selected subset. "
        "It counts flow starts for the same (source IP, destination IP, destination port, protocol) in the causal interval (t-10s, t], including the current flow.",
        "",
        "## Model selection on development data",
        "",
        "| Model | CV macro-F1 mean | CV SD | Best trial | Trials |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in summaries:
        report.append(f"| {item['model']} | {item['cv_macro_f1_mean']:.6f} | {item['cv_macro_f1_std']:.6f} | {item['best_trial']} | {item['completed_trials']} |")
    binary = results["binary_component"]
    multi = results["multiclass_component"]
    fusion = results["runtime_ml_fusion"]
    report.extend([
        "",
        f"Selected model: **{selection['winner']}**.",
        "",
        "## Final test",
        "",
        f"Final test rows: **{results['final_test_rows']:,}**.",
        "",
        "### Binary component",
        "",
        "| TN | FP | FN | TP | Accuracy | Weighted F1 | FPR | FNR |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {binary['tn']:,} | {binary['fp']:,} | {binary['fn']:,} | {binary['tp']:,} | {binary['accuracy']:.6f} | {binary['f1_weighted']:.6f} | {binary['fpr']:.6f} | {binary['fnr']:.6f} |",
        "",
        "### Multiclass component",
        "",
        f"Accuracy: {multi['accuracy']:.6f}; macro-F1: {multi['f1_macro']:.6f}; weighted-F1: {multi['f1_weighted']:.6f}.",
        "",
        "### Deployed dual-model ML decision rule",
        "",
        f"At threshold {RUNTIME_THRESHOLD:.2f}: accuracy {fusion['accuracy']:.6f}; macro-F1 {fusion['f1_macro']:.6f}; "
        f"attack FPR {fusion['attack_fpr']:.6f}; attack FNR {fusion['attack_fnr']:.6f}.",
        "",
        "Latency values in the JSON artifact are amortized bulk-inference measurements and are not end-to-end attack-detection latency.",
    ])
    (paths["results"] / "experiment_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    latex = [
        "% Auto-generated from final_evaluation.json",
        "\\begin{table}[H]",
        "\\centering",
        "\\caption{Development-Set Cross-Validation Model Selection}",
        "\\begin{tabular}{lrr}",
        "\\hline",
        "Model & CV Macro-F1 Mean & SD \\\\",
        "\\hline",
    ]
    for item in summaries:
        latex.append(f"{item['model'].replace('_', ' ').title()} & {item['cv_macro_f1_mean']:.5f} & {item['cv_macro_f1_std']:.5f} \\\\")
    latex.extend(["\\hline", "\\end{tabular}", "\\end{table}", ""])
    (paths["results"] / "tables_for_thesis.tex").write_text("\n".join(latex), encoding="utf-8")


def verify_artifacts(paths: dict[str, Path], logger: logging.Logger) -> None:
    required = [
        paths["results"] / "data_lineage.json",
        paths["results"] / "model_selection.json",
        paths["results"] / "final_evaluation.json",
        paths["models"] / "active_model.pkl",
        paths["models"] / "classification_model.pkl",
        paths["models"] / "label_encoder.pkl",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing artifacts: {missing}")
    encoder = joblib.load(paths["models"] / "label_encoder.pkl")
    if list(encoder.classes_) != sorted(FINAL_CLASSES):
        raise RuntimeError(f"Botnet exclusion verification failed: {list(encoder.classes_)}")
    metadata = json.loads(
        (paths["models"] / "model_metadata.json").read_text(encoding="utf-8")
    )
    if CONNECTION_COUNT_FEATURE in metadata.get("selected_features", []):
        if metadata.get("connection_count_contract") != connection_count_contract():
            raise RuntimeError("Connection Count contract trong metadata không khớp train")
    manifest = {
        "experiment_id": paths["root"].name,
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "classes": list(encoder.classes_),
        "artifacts": [
            {"path": str(path.relative_to(paths["root"])), "bytes": path.stat().st_size, "sha256": sha256_file(path)}
            for path in required
        ],
    }
    write_json(paths["results"] / "artifact_manifest.json", manifest)
    logger.info("VERIFY complete; classes=%s artifacts=%d", list(encoder.classes_), len(required))


def main() -> None:
    global RF_N_JOBS
    args = parse_args()
    RF_N_JOBS = args.rf_jobs
    paths = experiment_paths(args.experiment_id)
    logger = setup_logger(paths, args.stage)
    record_environment(paths, args.stage)
    logger.info("COMMAND %s", " ".join([sys.executable, *sys.argv]))
    if args.stage in {"prepare", "all"}:
        prepare_data(paths, logger)
    if args.stage in {"tune", "all"}:
        tune_models(paths, logger, args.trials)
    if args.stage in {"train-evaluate", "all"}:
        train_and_evaluate(paths, logger)
    if args.stage in {"verify", "all"}:
        verify_artifacts(paths, logger)


if __name__ == "__main__":
    main()
