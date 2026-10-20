"""Capture one real NFStream flow and run it through the deployed 21-feature models."""

import argparse
import json
import signal
import sys
from pathlib import Path

import numpy as np


def _timeout(_signum, _frame):
    raise TimeoutError("NFStream did not yield a flow before the smoke-test timeout")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--models-dir", default="/app/models")
    parser.add_argument("--config-dir", default="/app/configs")
    parser.add_argument("--src-dir", default="/app/src")
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument(
        "--expected-source-ip",
        help="ignore unrelated background flows until this source IP is observed",
    )
    args = parser.parse_args()

    sys.path.insert(0, str(Path(args.src_dir)))
    from realtime_extractor import create_streamer, extract_features
    from threat_evaluator import ThreatEvaluator

    evaluator = ThreatEvaluator(
        models_dir=args.models_dir,
        config_dir=args.config_dir,
    )
    streamer = create_streamer(interface=args.interface, n_meters=1)

    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(args.timeout_seconds)
    try:
        flow = None
        for candidate in streamer:
            if (
                args.expected_source_ip is None
                or candidate.src_ip == args.expected_source_ip
            ):
                flow = candidate
                break
    finally:
        signal.alarm(0)

    if flow is None:
        raise RuntimeError("NFStream ended before the expected live flow was observed")

    features = extract_features(flow, feature_names=evaluator.feature_names)
    result = evaluator.evaluate(features)
    probabilities = result.get("class_probabilities", {})

    payload = {
        "status": "PASS",
        "experiment_id": evaluator.experiment_id,
        "interface": args.interface,
        "flow": {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "packets": flow.bidirectional_packets,
        },
        "feature_count": int(features.shape[0]),
        "features_finite": bool(np.isfinite(features).all()),
        "feature_values": {
            name: float(value)
            for name, value in zip(evaluator.feature_names, features)
        },
        "class_count": len(probabilities),
        "class_probabilities": probabilities,
        "has_botnet_class": any("botnet" in name.lower() for name in probabilities),
        "inference": {
            "is_attack": bool(result["is_attack"]),
            "confidence": float(result["confidence"]),
            "binary_score": float(result["binary_score"]),
            "multi_score": float(result["multi_score"]),
            "attack_type": result["attack_type"],
            "inference_time_ms": float(result["inference_time_ms"]),
        },
    }
    print(json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
