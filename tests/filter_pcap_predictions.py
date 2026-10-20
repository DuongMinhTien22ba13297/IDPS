#!/usr/bin/env python3
"""
=============================================================================
Tên file   : filter_pcap_predictions.py
Mục tiêu   : Lọc predictions.csv theo timestamp ground truth và tính lại recall
             mà không phải chạy lại NFStream/model.
Input      : CSV dự đoán, biên first_seen_ms và nhãn ground truth.
Output     : CSV đã lọc và summary JSON trong một thư mục mới.
Ngày tạo   : 2026-09-13
Ngày sửa   : 2026-09-13
Lí do sửa  : Chuẩn hóa artifact đánh giá PCAP theo đúng label rule CICIDS2017.
=============================================================================
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np


def describe(values: list[float]) -> dict:
    array = np.asarray(values, dtype=np.float64)
    return {
        "min": float(np.min(array)),
        "mean": float(np.mean(array)),
        "median": float(np.quantile(array, 0.50)),
        "p95": float(np.quantile(array, 0.95)),
        "p99": float(np.quantile(array, 0.99)),
        "max": float(np.max(array)),
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Filter PCAP predictions by ground-truth first_seen_ms."
    )
    parser.add_argument("predictions", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--first-seen-min-ms", required=True, type=int)
    parser.add_argument("--first-seen-max-ms", required=True, type=int)
    parser.add_argument("--ground-truth", default="DoS/DDoS")
    args = parser.parse_args()

    if not args.predictions.is_file():
        raise FileNotFoundError(args.predictions)
    if args.first_seen_min_ms > args.first_seen_max_ms:
        raise ValueError("first_seen_min_ms phải <= first_seen_max_ms")
    args.output_dir.mkdir(parents=True, exist_ok=False)

    filtered_path = args.output_dir / "predictions_ground_truth.csv"
    summary_path = args.output_dir / "summary_ground_truth.json"
    decisions: Counter[str] = Counter()
    predicted_types: Counter[str] = Counter()
    confidences: list[float] = []
    dos_probabilities: list[float] = []
    selected = 0

    with args.predictions.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise ValueError("CSV không có header")
        with filtered_path.open("x", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=reader.fieldnames)
            writer.writeheader()
            for row in reader:
                first_seen_ms = int(row["first_seen_ms"])
                if not (
                    args.first_seen_min_ms
                    <= first_seen_ms
                    <= args.first_seen_max_ms
                ):
                    continue
                writer.writerow(row)
                selected += 1
                decisions[row["decision"]] += 1
                predicted_types[row["attack_type"]] += 1
                confidences.append(float(row["confidence"]))
                dos_probabilities.append(float(row["P_DoS_DDoS"]))

    if selected == 0:
        raise RuntimeError("Không có prediction nào nằm trong ground-truth window")

    summary = {
        "source_predictions": str(args.predictions.resolve()),
        "filtered_predictions": str(filtered_path.resolve()),
        "ground_truth": args.ground_truth,
        "first_seen_min_ms": args.first_seen_min_ms,
        "first_seen_max_ms_inclusive": args.first_seen_max_ms,
        "selected_flows": selected,
        "decision_counts": dict(decisions),
        "predicted_type_counts": dict(predicted_types),
        "attack_decision_recall": decisions["ATTACK"] / selected,
        "correct_type_recall": predicted_types[args.ground_truth] / selected,
        "confidence": describe(confidences),
        "p_dos_ddos": describe(dos_probabilities),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
