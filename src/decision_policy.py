"""Side-effect boundary for enforce versus monitor-only decisions."""

from datetime import datetime, timezone
import time


def _utc_timestamp_from_ns(timestamp_ns: int) -> str:
    return datetime.fromtimestamp(
        timestamp_ns / 1_000_000_000, timezone.utc
    ).isoformat()


def apply_block(*, monitor_only: bool, firewall, ip_manager,
                src_ip: str, reason: str, timing: dict | None = None) -> bool:
    """Apply firewall/blacklist writes only in enforce mode.

    When a mutable ``timing`` mapping is supplied, it receives the precise
    wall-clock completion timestamp and monotonic duration of the firewall
    call.  The metrics are deliberately taken around ``firewall.block_ip``;
    blacklist persistence is reported separately and cannot inflate iptables
    latency.
    """
    if monitor_only:
        return False

    firewall_start_wall_ns = time.time_ns()
    firewall_start_monotonic_ns = time.perf_counter_ns()
    if timing is not None:
        timing["iptables_started_timestamp"] = _utc_timestamp_from_ns(
            firewall_start_wall_ns
        )
    blocked = firewall.block_ip(src_ip, reason=reason)
    firewall_completed_wall_ns = time.time_ns()
    firewall_completed_monotonic_ns = time.perf_counter_ns()
    if timing is not None:
        timing["iptables_completed_timestamp"] = _utc_timestamp_from_ns(
            firewall_completed_wall_ns
        )
        timing["iptables_enforcement_latency_ms"] = round(
            (firewall_completed_monotonic_ns - firewall_start_monotonic_ns)
            / 1_000_000,
            3,
        )
        timing["firewall_rule_inserted"] = bool(blocked)
        # Internal-only value consumed by the daemon to calculate end-to-end
        # latency against NFStream's epoch timestamp.
        timing["_iptables_completed_wall_ns"] = firewall_completed_wall_ns

    if blocked:
        blacklist_start_monotonic_ns = time.perf_counter_ns()
        ip_manager.add_to_blacklist(src_ip, reason=reason)
        if timing is not None:
            timing["blacklist_persistence_latency_ms"] = round(
                (time.perf_counter_ns() - blacklist_start_monotonic_ns)
                / 1_000_000,
                3,
            )
    return bool(blocked)
