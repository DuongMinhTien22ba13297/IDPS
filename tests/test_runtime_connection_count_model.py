"""
=============================================================================
Tên file   : test_runtime_connection_count_model.py
Mục tiêu   : Kiểm thử end-to-end schema/runtime của model Connection Count v2.
Input      : Artifact experiment v2 và một dòng final-test thực.
Output     : Kết quả unittest load model, trích xuất và inference 21 chiều.
Ngày tạo   : 2026-09-13
Ngày sửa   : 2026-09-13
Lí do sửa  : Chứng minh model tự chọn Connection Count 10s và runtime hỗ trợ.
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

from connection_count import (
    CONNECTION_COUNT_FEATURE,
    CONNECTION_KEY_COLUMNS,
    CONNECTION_WINDOW_MS,
    ConnectionWindowCounter,
)
from realtime_extractor import create_streamer, extract_features
from threat_evaluator import ThreatEvaluator


EXPERIMENT_DIR = PROJECT_ROOT / "experiments" / "20260913_connection_count_10s_v2"


class FlexibleFlow(SimpleNamespace):
    """NFStream-like fixture: statistic không khai báo có giá trị 0."""

    def __getattr__(self, _name):
        return 0.0


class RuntimeConnectionCountModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = json.loads(
            (EXPERIMENT_DIR / "models" / "model_metadata.json").read_text(
                encoding="utf-8"
            )
        )
        cls.evaluator = ThreatEvaluator(
            models_dir=str(EXPERIMENT_DIR / "models"),
            config_dir=str(PROJECT_ROOT / "configs"),
        )

    def test_model_selected_connection_count_without_forcing(self):
        self.assertIn(CONNECTION_COUNT_FEATURE, self.metadata["selected_features"])
        self.assertEqual(self.evaluator.n_features, 21)
        self.assertEqual(
            self.evaluator.feature_names,
            self.metadata["selected_features"],
        )
        contract = self.metadata["connection_count_contract"]
        self.assertEqual(contract["window_ms"], CONNECTION_WINDOW_MS)
        self.assertEqual(contract["key_columns"], list(CONNECTION_KEY_COLUMNS))
        self.assertTrue(contract["causal"])

    def test_model_accepts_real_final_test_row(self):
        names = self.evaluator.feature_names
        frame = pd.read_csv(
            EXPERIMENT_DIR / "data" / "final_test.csv",
            usecols=names,
            nrows=1,
        )
        vector = frame[names].iloc[0].to_numpy(dtype=np.float64)
        result = self.evaluator.evaluate(vector)
        self.assertEqual(vector.shape, (21,))
        self.assertIn("class_probabilities", result)
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

    def test_runtime_extracts_connection_count_in_model_order(self):
        flow = FlexibleFlow(
            udps=SimpleNamespace(init_win_fwd=8192, connection_count_10s=123),
            bidirectional_duration_ms=1000.0,
            src2dst_packets=2.0,
            dst2src_packets=1.0,
            src2dst_bytes=120.0,
            dst2src_bytes=60.0,
            src2dst_max_ps=60.0,
            dst2src_max_ps=60.0,
            src2dst_min_ps=60.0,
            dst2src_min_ps=60.0,
            src2dst_mean_ps=60.0,
            dst2src_mean_ps=60.0,
            src2dst_stddev_ps=0.0,
            dst2src_stddev_ps=0.0,
            bidirectional_mean_ps=60.0,
            bidirectional_stddev_ps=0.0,
            bidirectional_stddev_piat_ms=0.0,
            src2dst_min_piat_ms=0.0,
            src2dst_duration_ms=1000.0,
            bidirectional_rst_packets=0.0,
            bidirectional_syn_packets=2.0,
            bidirectional_psh_packets=0.0,
            bidirectional_ack_packets=1.0,
            src2dst_psh_packets=0.0,
            bidirectional_bytes=180.0,
            bidirectional_packets=3.0,
        )
        vector = extract_features(flow, feature_names=self.evaluator.feature_names)
        index = self.evaluator.feature_names.index(CONNECTION_COUNT_FEATURE)
        self.assertEqual(vector.shape, (21,))
        self.assertEqual(vector[index], 123.0)
        packets_per_second_index = self.evaluator.feature_names.index("Flow Packets/s")
        min_packet_index = self.evaluator.feature_names.index("Min Packet Length")
        self.assertEqual(vector[packets_per_second_index], 3.0)
        self.assertEqual(vector[min_packet_index], 60.0)

    def test_stateful_feature_rejects_multiple_meters(self):
        tracker = ConnectionWindowCounter()
        with self.assertRaisesRegex(ValueError, "n_meters=1"):
            create_streamer(
                interface="not-opened-because-validation-runs-first",
                conn_tracker=tracker,
                n_meters=0,
            )


if __name__ == "__main__":
    unittest.main()
