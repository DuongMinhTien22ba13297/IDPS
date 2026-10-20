import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from collect_metrics import (
    filter_events_by_run_id,
    generate_performance_table,
    measured_end_to_end_latency_ms,
)


class LatencyMetricTests(unittest.TestCase):
    def test_uses_only_confirmed_end_to_end_measurements(self):
        confirmed = {
            "run_id": "nmap_r1",
            "system_action": "AUTO_BLOCKED",
            "enforcement_applied": True,
            "end_to_end_latency_ms": 18.25,
            # This intentionally disagrees with E2E latency; it must not win.
            "response_time_ms": 2.0,
        }
        legacy = {
            "run_id": "nmap_r1",
            "system_action": "AUTO_BLOCKED",
            "response_time_ms": 999.0,
        }
        failed = {
            "run_id": "nmap_r1",
            "system_action": "AUTO_BLOCKED",
            "enforcement_applied": False,
            "end_to_end_latency_ms": 1.0,
        }

        self.assertEqual(measured_end_to_end_latency_ms(confirmed), 18.25)
        self.assertIsNone(measured_end_to_end_latency_ms(legacy))
        self.assertIsNone(measured_end_to_end_latency_ms(failed))

        report = generate_performance_table(
            [confirmed, legacy, failed],
            {"total_flows": 0, "blocked_count": 0, "suspicious_count": 0, "benign_count": 0},
        )
        self.assertIn("E2E Latency Avg | 18.2 ms", report)
        self.assertNotIn("999.0", report)

    def test_filters_events_to_an_explicit_run(self):
        events = [{"run_id": "nmap_r1"}, {"run_id": "dos_r1"}, {}]
        self.assertEqual(filter_events_by_run_id(events, "dos_r1"), [{"run_id": "dos_r1"}])
        self.assertEqual(filter_events_by_run_id(events, None), events)


if __name__ == "__main__":
    unittest.main()
