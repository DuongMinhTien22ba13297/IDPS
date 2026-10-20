"""
=============================================================================
Tên file   : test_runtime_21_features.py
Mục tiêu   : Kiểm thử regression cho model production v2 21-feature hiện tại.
Input      : Artifact connection-count v2 và NFStream-like fake flow.
Output     : Kết quả unittest schema, extraction và inference.
Ngày tạo   : 2026-09-08
Ngày sửa   : 2026-09-13
Lí do sửa  : Khóa schema mặc định của extractor theo model v2 đã deploy;
             ngăn đường gọi không truyền metadata dùng nhầm vector baseline.
=============================================================================
"""

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from extract_50_features import FEATURE_NAMES as OFFLINE_FEATURE_NAMES
from extract_50_features import extract_57_features
from connection_count import CONNECTION_COUNT_FEATURE
from realtime_extractor import FEATURE_NAMES as RUNTIME_FEATURE_NAMES
from realtime_extractor import TCPWindowPlugin, extract_features
from threat_evaluator import ThreatEvaluator


EXPERIMENT_DIR = (
    PROJECT_ROOT / "experiments" / "20260913_connection_count_10s_v2"
)


class FakeFlow:
    """Small NFStream-like object; unspecified statistics default to zero."""

    def __init__(self):
        self.udps = SimpleNamespace(
            init_win_fwd=4096,
            init_win_bwd=2048,
            connection_count_10s=17.0,
        )
        self.bidirectional_duration_ms = 2000.0
        self.src2dst_packets = 4.0
        self.dst2src_packets = 6.0
        self.src2dst_bytes = 1200.0
        self.dst2src_bytes = 1800.0
        self.src2dst_max_ps = 700.0
        self.dst2src_max_ps = 900.0
        self.src2dst_stddev_ps = 12.5
        self.dst2src_stddev_ps = 20.5
        self.dst2src_mean_ps = 250.0
        self.bidirectional_mean_ps = 300.0
        self.bidirectional_stddev_ps = 55.0
        self.bidirectional_stddev_piat_ms = 1.25
        self.src2dst_min_piat_ms = 0.125
        self.src2dst_mean_ps = 350.0
        self.dst2src_max_piat_ms = 2.5
        self.dst2src_stddev_piat_ms = 0.75
        self.bidirectional_rst_packets = 2.0
        self.bidirectional_syn_packets = 3.0
        self.bidirectional_psh_packets = 4.0
        self.bidirectional_ack_packets = 8.0
        self.src2dst_psh_packets = 1.0
        self.bidirectional_bytes = self.src2dst_bytes + self.dst2src_bytes
        self.bidirectional_packets = self.src2dst_packets + self.dst2src_packets

    def __getattr__(self, _name):
        return 0.0


class RuntimeFeatureTests(unittest.TestCase):
    def test_runtime_order_matches_locked_metadata(self):
        metadata_path = EXPERIMENT_DIR / "models" / "model_metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(RUNTIME_FEATURE_NAMES, metadata["selected_features"])
        self.assertEqual(len(RUNTIME_FEATURE_NAMES), 21)

    def test_runtime_values_match_offline_extractor_formulas(self):
        flow = FakeFlow()
        offline_vector = extract_57_features(flow)
        offline_values = dict(zip(OFFLINE_FEATURE_NAMES, offline_vector))
        runtime_vector = extract_features(flow)

        self.assertEqual(runtime_vector.shape, (21,))
        for name, value in zip(RUNTIME_FEATURE_NAMES, runtime_vector):
            expected = (
                flow.udps.connection_count_10s
                if name == CONNECTION_COUNT_FEATURE
                else offline_values[name]
            )
            self.assertAlmostEqual(
                value,
                expected,
                places=10,
                msg=f"Offline/runtime mismatch for {name}",
            )

    def test_extractor_uses_requested_order_and_rejects_unknown_feature(self):
        flow = FakeFlow()
        flow.udps.connection_count_10s = 17
        names = ["ACK Flag Count", "Bwd Packets/s", "Init_Win_bytes_forward"]
        vector = extract_features(flow, feature_names=names)
        np.testing.assert_allclose(vector, [8.0, 3.0, 4096.0])

        with self.assertRaisesRegex(ValueError, "Runtime không hỗ trợ"):
            extract_features(flow, feature_names=["Unknown Feature"])

        count_vector = extract_features(flow, feature_names=[CONNECTION_COUNT_FEATURE])
        np.testing.assert_allclose(count_vector, [17.0])

    def test_tcp_window_plugin_reads_header_value(self):
        plugin = TCPWindowPlugin()
        flow = SimpleNamespace(udps=SimpleNamespace())

        forward_bytes = bytearray(40)
        forward_bytes[0] = 0x45  # IPv4, 20-byte header
        forward_bytes[34:36] = (4096).to_bytes(2, "big")
        forward_packet = SimpleNamespace(
            protocol=6,
            direction=0,
            ip_version=4,
            ip_packet=bytes(forward_bytes),
        )
        plugin.on_init(forward_packet, flow)

        backward_bytes = bytearray(40)
        backward_bytes[0] = 0x45
        backward_bytes[34:36] = (8192).to_bytes(2, "big")
        backward_packet = SimpleNamespace(
            protocol=6,
            direction=1,
            ip_version=4,
            ip_packet=bytes(backward_bytes),
        )
        plugin.on_update(backward_packet, flow)

        self.assertEqual(flow.udps.init_win_fwd, 4096)
        self.assertEqual(flow.udps.init_win_bwd, 8192)


class ThreatEvaluatorIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evaluator = ThreatEvaluator(
            models_dir=str(EXPERIMENT_DIR / "models"),
            config_dir=str(PROJECT_ROOT / "configs"),
        )

    def test_model_schema_is_locked_to_21_features(self):
        info = self.evaluator.get_model_info()
        self.assertEqual(
            info["experiment_id"], "20260913_connection_count_10s_v2"
        )
        self.assertEqual(info["feature_count"], 21)
        self.assertEqual(info["feature_names"], RUNTIME_FEATURE_NAMES)
        self.assertEqual(
            info["class_names"],
            ["BENIGN", "Brute Force", "DoS/DDoS", "PortScan", "Web Attack"],
        )
        self.assertIsNone(self.evaluator.label_encoder)

    def test_new_models_accept_a_real_final_test_row(self):
        final_test_path = EXPERIMENT_DIR / "data" / "final_test.csv"
        frame = pd.read_csv(
            final_test_path,
            usecols=RUNTIME_FEATURE_NAMES,
            nrows=1,
        )
        vector = frame[RUNTIME_FEATURE_NAMES].iloc[0].to_numpy(dtype=np.float64)
        result = self.evaluator.evaluate(vector)

        self.assertIn("is_attack", result)
        self.assertIn("class_probabilities", result)
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)
        self.assertEqual(len(result["class_probabilities"]), 5)

    def test_wrong_shape_is_rejected_without_inference(self):
        result = self.evaluator.evaluate(np.zeros(15, dtype=np.float64))
        self.assertFalse(result["is_attack"])
        self.assertEqual(result["confidence"], 0.0)

    def test_legacy_models_remain_usable_for_rollback(self):
        legacy = ThreatEvaluator(
            models_dir=str(
                PROJECT_ROOT / "backups" / "20260908_runtime_21features_v1"
            ),
            config_dir=str(PROJECT_ROOT / "configs"),
        )
        vector = extract_features(FakeFlow(), feature_names=legacy.feature_names)
        self.assertEqual(vector.shape, (15,))
        result = legacy.evaluate(vector)
        self.assertIn("is_attack", result)
        self.assertEqual(legacy.experiment_id, "legacy-artifacts")
        self.assertIsNotNone(legacy.label_encoder)


if __name__ == "__main__":
    unittest.main()
