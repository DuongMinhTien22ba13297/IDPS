import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from decision_policy import apply_block
from suricata_correlator import SuricataCorrelator


class RecordingFirewall:
    def __init__(self):
        self.calls = []

    def block_ip(self, ip, reason):
        self.calls.append((ip, reason))
        return True


class RecordingIPManager:
    def __init__(self):
        self.calls = []

    def add_to_blacklist(self, ip, reason):
        self.calls.append((ip, reason))
        return True


class MonitorPolicyTests(unittest.TestCase):
    def test_monitor_only_has_no_firewall_or_blacklist_writes(self):
        firewall = RecordingFirewall()
        ip_manager = RecordingIPManager()
        applied = apply_block(
            monitor_only=True,
            firewall=firewall,
            ip_manager=ip_manager,
            src_ip="172.16.1.10",
            reason="DoS/DDoS",
        )
        self.assertFalse(applied)
        self.assertEqual(firewall.calls, [])
        self.assertEqual(ip_manager.calls, [])

    def test_enforce_mode_preserves_block_and_blacklist(self):
        firewall = RecordingFirewall()
        ip_manager = RecordingIPManager()
        timing = {}
        applied = apply_block(
            monitor_only=False,
            firewall=firewall,
            ip_manager=ip_manager,
            src_ip="172.16.1.10",
            reason="PortScan",
            timing=timing,
        )
        self.assertTrue(applied)
        self.assertEqual(firewall.calls, [("172.16.1.10", "PortScan")])
        self.assertEqual(ip_manager.calls, [("172.16.1.10", "PortScan")])
        self.assertTrue(timing["firewall_rule_inserted"])
        self.assertIsNotNone(timing["iptables_started_timestamp"])
        self.assertIsNotNone(timing["iptables_completed_timestamp"])
        self.assertGreaterEqual(timing["iptables_enforcement_latency_ms"], 0.0)
        self.assertGreaterEqual(timing["blacklist_persistence_latency_ms"], 0.0)


class FlowCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.correlator = SuricataCorrelator(alert_ttl_seconds=300)
        self.start = datetime.now(timezone.utc) - timedelta(seconds=10)
        self.end = datetime.now(timezone.utc)

    def add_alert(self, *, src_port, dst_port, timestamp=None,
                  sid=1000002, action="allowed", iface="ens33",
                  signature="IDPS SQL Injection Attempt"):
        timestamp = timestamp or (self.start + timedelta(seconds=2))
        self.correlator._add_alert({
            "timestamp": timestamp.isoformat(),
            "src_ip": "172.16.1.10",
            "src_port": src_port,
            "dest_ip": "172.16.1.2",
            "dest_port": dst_port,
            "proto": "TCP",
            "in_iface": iface,
            "alert": {
                "signature_id": sid,
                "signature": signature,
                "category": "Web Application Attack",
                "severity": 1,
                "action": action,
            },
        })

    def correlate(self, **overrides):
        arguments = {
            "src_ip": "172.16.1.10",
            "dst_port": 3001,
            "ml_attack_type": None,
            "ml_confidence": 0.01,
            "src_port": 41000,
            "protocol": 6,
            "flow_start_ms": self.start.timestamp() * 1000,
            "flow_end_ms": self.end.timestamp() * 1000,
            "related_dst_ports": {3000},
        }
        arguments.update(overrides)
        return self.correlator.correlate(**arguments)

    def test_old_alert_on_same_ip_does_not_score_a_different_flow(self):
        self.add_alert(src_port=40000, dst_port=3001)
        score, details = self.correlate()
        self.assertEqual(score, 0.0)
        self.assertEqual(details["same_flow_alerts_count"], 0)
        self.assertEqual(details["historical_alerts_count"], 1)
        self.assertFalse(details["suricata_enforcement_requested"])

    def test_bridge_duplicate_is_collapsed_and_policy_is_not_packet_drop(self):
        timestamp = self.start + timedelta(seconds=2)
        self.add_alert(src_port=41000, dst_port=3001, timestamp=timestamp, iface="ens33")
        self.add_alert(
            src_port=41000,
            dst_port=3000,
            timestamp=timestamp + timedelta(microseconds=50),
            iface="br-idps",
        )
        score, details = self.correlate()
        self.assertGreater(score, 0.0)
        self.assertEqual(details["same_flow_alerts_count"], 1)
        self.assertEqual(details["deduplicated_alerts_count"], 1)
        self.assertTrue(details["suricata_policy_match"])
        self.assertFalse(details["suricata_packet_drop"])
        self.assertTrue(details["suricata_enforcement_requested"])
        self.assertEqual(details["matched_signature_ids"], [1000002])

    def test_real_block_action_is_reported_separately(self):
        self.add_alert(
            src_port=41000,
            dst_port=3001,
            action="blocked",
            sid=2100001,
            signature="ET WEB_SERVER suspicious request",
        )
        _, details = self.correlate()
        self.assertTrue(details["suricata_packet_drop"])
        self.assertFalse(details["suricata_policy_match"])
        self.assertTrue(details["suricata_enforcement_requested"])


if __name__ == "__main__":
    unittest.main()
