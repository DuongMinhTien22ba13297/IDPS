#!/usr/bin/env python3
"""
=============================================================================
Tên file   : evaluate_pcap_runtime.py
Mục tiêu   : Replay PCAP offline qua đúng runtime schema và hai model,
             sau đó tính recall cho một ground-truth flow selector.
Input      : PCAP, thư mục model/config và bộ lọc src/dst/dst-port/protocol.
Output     : CSV dự đoán từng flow và JSON tổng kết có phân bố xác suất.
Ngày tạo   : 2026-09-13
Ngày sửa   : 2026-09-13
Lí do sửa  : Hỗ trợ tự bật Connection Count 10s khi model metadata yêu cầu.
=============================================================================
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from connection_count import CONNECTION_COUNT_FEATURE, CONNECTION_WINDOW_SECONDS
from realtime_extractor import ConnectionTracker, create_streamer, extract_features
from threat_evaluator import ThreatEvaluator


CLASS_KEYS = ["BENIGN", "Brute_Force", "DoS_DDoS", "PortScan", "Web_Attack"]


def describe(values: list[float]) -> dict:
    """Return stable summary statistics for one probability vector."""
    if not values:
        return {
            "min": None,
            "mean": None,
            "median": None,
            "p95": None,
            "p99": None,
            "max": None,
        }
    array = np.asarray(values, dtype=np.float64)
    return {
        "min": float(np.min(array)),
        "mean": float(np.mean(array)),
        "median": float(np.quantile(array, 0.50)),
        "p95": float(np.quantile(array, 0.95)),
        "p99": float(np.quantile(array, 0.99)),
        "max": float(np.max(array)),
    }


def flow_matches(flow, args: argparse.Namespace) -> bool:
    """Match the CICIDS ground-truth tuple after NFStream establishes direction."""
    return (
        (args.src_ip is None or flow.src_ip == args.src_ip)
        and (args.dst_ip is None or flow.dst_ip == args.dst_ip)
        and (args.dst_port is None or int(flow.dst_port) == args.dst_port)
        and (args.protocol is None or int(flow.protocol) == args.protocol)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--models-dir", type=Path, default=PROJECT_ROOT / "models")
    parser.add_argument("--config-dir", type=Path, default=PROJECT_ROOT / "configs")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--src-ip")
    parser.add_argument("--dst-ip")
    parser.add_argument("--dst-port", type=int)
    parser.add_argument("--protocol", type=int, default=6)
    parser.add_argument("--ground-truth", default="DoS/DDoS")
    parser.add_argument("--max-target-flows", type=int)
    return parser.parse_args()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    if not args.pcap.is_file():
        raise FileNotFoundError(args.pcap)

    args.output_dir.mkdir(parents=True, exist_ok=False)
    predictions_path = args.output_dir / "predictions.csv"
    summary_path = args.output_dir / "summary.json"

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    evaluator = ThreatEvaluator(str(args.models_dir), str(args.config_dir))
    tracker = (
        ConnectionTracker(window_seconds=CONNECTION_WINDOW_SECONDS)
        if CONNECTION_COUNT_FEATURE in evaluator.feature_names
        else None
    )
    streamer = create_streamer(
        interface=str(args.pcap),
        conn_tracker=tracker,
        n_meters=1,
    )

    headers = [
        "flow_id",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "first_seen_ms",
        "last_seen_ms",
        "binary_score",
        "multi_attack_score",
        "confidence",
        "decision",
        "attack_type",
        *[f"P_{key}" for key in CLASS_KEYS],
    ]
    total_pcap_flows = 0
    target_flows = 0
    decision_counts: Counter[str] = Counter()
    predicted_type_counts: Counter[str] = Counter()
    confidences: list[float] = []
    dos_probabilities: list[float] = []
    started = time.time()

    with predictions_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()

        for flow in streamer:
            total_pcap_flows += 1
            if not flow_matches(flow, args):
                continue

            features = extract_features(flow, feature_names=evaluator.feature_names)
            result = evaluator.evaluate(features)
            probabilities = result.get("class_probabilities", {})
            confidence = float(result["confidence"])

            if result["is_attack"]:
                decision = "ATTACK"
            elif confidence > evaluator.alert_threshold:
                decision = "SUSPICIOUS"
            else:
                decision = "BENIGN"

            predicted_type = result.get("attack_type") or "BENIGN"
            target_flows += 1
            decision_counts[decision] += 1
            predicted_type_counts[predicted_type] += 1
            confidences.append(confidence)
            dos_probabilities.append(float(probabilities.get("DoS_DDoS", 0.0)))

            row = {
                "flow_id": flow.id,
                "src_ip": flow.src_ip,
                "src_port": flow.src_port,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "first_seen_ms": flow.bidirectional_first_seen_ms,
                "last_seen_ms": flow.bidirectional_last_seen_ms,
                "binary_score": result.get("binary_score", 0.0),
                "multi_attack_score": result.get("multi_score", 0.0),
                "confidence": confidence,
                "decision": decision,
                "attack_type": predicted_type,
            }
            row.update(
                {
                    f"P_{key}": probabilities.get(key, 0.0)
                    for key in CLASS_KEYS
                }
            )
            writer.writerow(row)

            if target_flows % 10_000 == 0:
                elapsed = max(time.time() - started, 0.001)
                print(
                    f"target_flows={target_flows:,} "
                    f"total_pcap_flows={total_pcap_flows:,} "
                    f"rate={target_flows / elapsed:.1f} target-flow/s",
                    flush=True,
                )
            if (
                args.max_target_flows
                and target_flows >= args.max_target_flows
            ):
                break

    elapsed = time.time() - started
    correct_type = predicted_type_counts.get(args.ground_truth, 0)
    attack_decisions = decision_counts.get("ATTACK", 0)
    summary = {
        "pcap": str(args.pcap.resolve()),
        "pcap_size_bytes": args.pcap.stat().st_size,
        "models_dir": str(args.models_dir.resolve()),
        "config_dir": str(args.config_dir.resolve()),
        "experiment_id": evaluator.experiment_id,
        "feature_count": evaluator.n_features,
        "ground_truth": args.ground_truth,
        "selector": {
            "src_ip": args.src_ip,
            "dst_ip": args.dst_ip,
            "dst_port": args.dst_port,
            "protocol": args.protocol,
        },
        "total_pcap_flows": total_pcap_flows,
        "target_flows": target_flows,
        "decision_counts": dict(decision_counts),
        "predicted_type_counts": dict(predicted_type_counts),
        "attack_decision_recall": (
            attack_decisions / target_flows if target_flows else None
        ),
        "correct_type_recall": (
            correct_type / target_flows if target_flows else None
        ),
        "confidence": describe(confidences),
        "p_dos_ddos": describe(dos_probabilities),
        "elapsed_seconds": elapsed,
        "target_flows_per_second": (
            target_flows / elapsed if elapsed > 0 else None
        ),
        "predictions_csv": str(predictions_path.resolve()),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if target_flows else 3


if __name__ == "__main__":
    raise SystemExit(main())
