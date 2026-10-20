"""
=============================================================================
Tên file   : test_connection_count.py
Mục tiêu   : Kiểm thử công thức Connection Count dùng chung cho train/live.
Input      : Metadata flow tổng hợp và timestamp runtime.
Output     : Kết quả unittest.
Ngày tạo   : 2026-09-13
Ngày sửa   : 2026-09-13
Lí do sửa  : Khóa contract cửa sổ past-only 10 giây cho feature DoS.
=============================================================================
"""

import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from connection_count import ConnectionWindowCounter, compute_connection_counts


class ConnectionCountTests(unittest.TestCase):
    def test_batch_is_past_only_and_independent_of_csv_order(self):
        frame = pd.DataFrame(
            {
                "src_ip": ["a", "a", "a", "a", "b"],
                "dst_ip": ["v", "v", "v", "v", "v"],
                "dst_port": [80, 80, 80, 443, 80],
                "protocol": [6, 6, 6, 6, 6],
                "bidirectional_first_seen_ms": [9000, 0, 10000, 5000, 9000],
            }
        )
        actual = compute_connection_counts(frame, window_ms=10000)
        # a:v:80 at t=0 -> 1; t=9 -> 2; t=10 excludes t=0 -> 2.
        np.testing.assert_allclose(actual, [2, 1, 2, 1, 1])

    def test_runtime_counter_matches_batch_definition(self):
        counter = ConnectionWindowCounter(window_seconds=10)
        actual = [
            counter.observe("a", "v", 80, 6, timestamp)
            for timestamp in (0, 9, 10, 19)
        ]
        self.assertEqual(actual, [1, 2, 2, 2])

    def test_key_separates_destination_service_and_protocol(self):
        counter = ConnectionWindowCounter(window_seconds=10)
        self.assertEqual(counter.observe("a", "v", 80, 6, 1), 1)
        self.assertEqual(counter.observe("a", "v", 443, 6, 2), 1)
        self.assertEqual(counter.observe("a", "other", 80, 6, 3), 1)
        self.assertEqual(counter.observe("a", "v", 80, 17, 4), 1)
        self.assertEqual(counter.observe("a", "v", 80, 6, 5), 2)


if __name__ == "__main__":
    unittest.main()
