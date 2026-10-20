#!/usr/bin/env python3
"""
=============================================================================
Module: suricata_correlator.py
Chức năng: Correlation Engine giữa Suricata Alerts và ML Predictions.
Input: File Suricata EVE JSON (eve.json) và thông tin ML predictions.
Output: Điểm rủi ro (risk score) và chi tiết mức độ tương quan (correlation details).
Ngày tạo: N/A
Ngày sửa: 2026-06-15
Lí do sửa: Sửa lỗi signature_id >= 1000000 nhận diện nhầm các luật Emerging Threats
           (sid >= 2000000) thành custom L7 drop rule, khiến brute force và các
           tấn công khác bị ghi đè nhãn thành Suricata_L7_DROP.
============================================================================="""

import json
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("Autodefense.SuricataCorrelator")


class SuricataAlert:
    """Đại diện cho một Suricata alert."""

    def __init__(self, alert_data: dict):
        self.timestamp = self._parse_timestamp(alert_data.get("timestamp"))
        self.flow_id = alert_data.get("flow_id")
        
        # Lấy Real IP từ X-Forwarded-For nếu có (dành cho Reverse Proxy)
        http_data = alert_data.get("http", {})
        xff = http_data.get("xff")
        if xff:
            self.src_ip = xff.split(",")[0].strip()
        else:
            self.src_ip = alert_data.get("src_ip")
            
        self.src_port = alert_data.get("src_port")
        self.dest_ip = alert_data.get("dest_ip")
        self.dest_port = alert_data.get("dest_port")
        self.protocol = alert_data.get("proto")
        self.in_iface = alert_data.get("in_iface")
        self.signature = alert_data.get("alert", {}).get("signature", "")
        self.signature_id = alert_data.get("alert", {}).get("signature_id")
        self.category = alert_data.get("alert", {}).get("category", "")
        self.severity = alert_data.get("alert", {}).get("severity", 0)
        self.action = alert_data.get("alert", {}).get("action", "")

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse timestamp từ Suricata format."""
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("+0000", "+00:00"))
        except (ValueError, AttributeError):
            return None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "in_iface": self.in_iface,
            "signature_id": self.signature_id,
            "action": self.action,
            "signature": self.signature,
            "category": self.category,
            "severity": self.severity,
        }

    def __repr__(self) -> str:
        return f"SuricataAlert({self.src_ip}:{self.src_port} → {self.dest_port}, {self.signature})"


class SuricataCorrelator:
    """
    Correlation Engine giữa Suricata và ML predictions.

    Features:
    - Real-time tail của Suricata EVE JSON log
    - In-memory cache của recent alerts (TTL: 5 phút)
    - Correlation scoring dựa trên:
      * Same IP, different attack types → HIGH RISK
      * Same IP, same attack type → CONFIRMATION
      * Multiple alerts from same IP → REPEAT OFFENDER
    """

    def __init__(self, eve_json_path: str = "/app/logs/suricata/eve.json",
                 alert_ttl_seconds: int = 300, max_alerts_per_ip: int = 50,
                 suricata_only_max_score: float = 0.30):
        self.eve_json_path = Path(eve_json_path)
        self.alert_ttl = timedelta(seconds=alert_ttl_seconds)
        self.max_alerts_per_ip = max_alerts_per_ip
        # Hard cap cho correlation_score khi ML nói Benign (suricata_only mode)
        self.suricata_only_max_score = suricata_only_max_score

        # In-memory cache: ip → deque of alerts
        self._alerts_by_ip: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_alerts_per_ip))
        self._lock = threading.Lock()

        # Signature severity mapping — dùng như hệ số nhân (multiplier) cho correlation_score.
        # Alert severity thấp (ET Info/Policy) sẽ giảm đáng kể ảnh hưởng.
        self._severity_weights = {
            1: 0.30,  # Info     — gần như vô hại (ET POLICY, ET INFO)
            2: 0.50,  # Warning  — đáng chú ý nhưng chưa chắc là tấn công
            3: 0.70,  # Notice   — khả năng cao là tấn công thật
            4: 0.85,  # Critical — tấn công nghiêm trọng đã xác nhận
        }

        # Attack type mapping từ Suricata signature → ML attack type
        self._signature_to_attack_type = {
            # SSH Brute Force
            "ssh": "Brute Force",
            "ssh-bruteforce": "Brute Force",
            "ssh-invalid": "Brute Force",

            # Port Scan
            "portscan": "PortScan",
            "scan": "PortScan",
            "recon": "PortScan",

            # DoS/DDoS
            "dos": "DoS/DDoS",
            "ddos": "DoS/DDoS",
            "flood": "DoS/DDoS",

            # Web Attacks
            "xss": "Web Attack",
            "sql": "Web Attack",
            "injection": "Web Attack",
            "web-attack": "Web Attack",
            "traversal": "Web Attack",

            # Botnet
            "bot": "Botnet",
            "c2": "Botnet",
            "malware": "Botnet",

            # Exploitation / Rare class has been removed
        }

        # Background thread để đọc alerts
        self._running = False
        self._reader_thread: Optional[threading.Thread] = None

    #  Alert Reading (Background Thread)

    def start(self):
        """Bắt đầu background thread để đọc Suricata alerts."""
        if self._running:
            logger.warning("SuricataCorrelator đã đang chạy.")
            return

        self._running = True
        self._reader_thread = threading.Thread(target=self._read_alerts_loop, daemon=True)
        self._reader_thread.start()
        logger.info(f"SuricataCorrelator đã bắt đầu đọc {self.eve_json_path}")

    def stop(self):
        """Dừng background thread."""
        self._running = False
        if self._reader_thread:
            self._reader_thread.join(timeout=5)
        logger.info("SuricataCorrelator đã dừng.")

    def _read_alerts_loop(self):
        """Background loop để đọc Suricata EVE JSON."""
        last_position = 0
        last_inode = None

        while self._running:
            try:
                if not self.eve_json_path.exists():
                    time.sleep(1)
                    continue

                # Kiểm tra log rotation dựa vào inode hoặc kích thước file
                current_inode = self.eve_json_path.stat().st_ino
                current_size = self.eve_json_path.stat().st_size

                if (last_inode is not None and current_inode != last_inode) or (current_size < last_position):
                    logger.info("Phát hiện Suricata log rotation hoặc file bị thu nhỏ, reset file pointer.")
                    last_position = 0
                last_inode = current_inode

                # Đọc file từ vị trí cuối cùng
                with open(self.eve_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_position)
                    
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            alert_data = json.loads(line)
                            if alert_data.get("event_type") == "alert":
                                self._add_alert(alert_data)
                        except json.JSONDecodeError:
                            logger.debug("Bỏ qua lỗi JSONDecodeError khi parse line từ Suricata.")
                            continue

                    last_position = f.tell()

                # Cleanup expired alerts
                self._cleanup_expired_alerts()

                time.sleep(0.5)  # Poll every 500ms

            except IOError as e:
                logger.error(f"Lỗi đọc {self.eve_json_path}: {e}")
                time.sleep(5)

    def _add_alert(self, alert_data: dict):
        """Thêm alert vào cache."""
        alert = SuricataAlert(alert_data)
        if alert.timestamp is None:
            return  # Bỏ qua nếu không parse được timestamp

        with self._lock:
            self._alerts_by_ip[alert.src_ip].append(alert)

        logger.debug(f"Đã thêm Suricata alert: {alert}")

    def _cleanup_expired_alerts(self):
        """Xóa alerts đã hết TTL."""
        now = datetime.now(timezone.utc)
        cutoff = now - self.alert_ttl

        with self._lock:
            for ip, alerts in list(self._alerts_by_ip.items()):
                # Giữ lại chỉ các alerts còn trong TTL
                while alerts and alerts[0].timestamp < cutoff:
                    alerts.popleft()

                # Xóa entry nếu không còn alerts
                if not alerts:
                    del self._alerts_by_ip[ip]

    #  Correlation Logic

    @staticmethod
    def _normalise_protocol(protocol) -> Optional[str]:
        if protocol is None:
            return None
        value = str(protocol).upper()
        return {"6": "TCP", "17": "UDP"}.get(value, value)

    @staticmethod
    def _is_policy_rule(alert: SuricataAlert) -> bool:
        """Custom IDPS alert that asks the daemon to enforce a policy block."""
        return bool(
            (alert.signature_id is not None and 1000000 <= alert.signature_id < 2000000)
            or "IDPS" in alert.signature
        )

    def _alert_matches_flow(
        self,
        alert: SuricataAlert,
        *,
        dst_port: int,
        src_port: Optional[int],
        protocol,
        flow_start_ms: Optional[float],
        flow_end_ms: Optional[float],
        related_dst_ports: set[int],
    ) -> bool:
        """Match an EVE alert to the current NFStream flow, not just its source IP."""
        allowed_ports = {int(dst_port), *related_dst_ports}
        try:
            if int(alert.dest_port) not in allowed_ports:
                return False
        except (TypeError, ValueError):
            return False

        if src_port is not None:
            try:
                if int(alert.src_port) != int(src_port):
                    return False
            except (TypeError, ValueError):
                return False

        expected_protocol = self._normalise_protocol(protocol)
        if expected_protocol and self._normalise_protocol(alert.protocol) != expected_protocol:
            return False

        if flow_start_ms is not None and flow_end_ms is not None:
            alert_ms = alert.timestamp.timestamp() * 1000.0
            # Small allowance for independent timestamping/capture paths.
            if not (float(flow_start_ms) - 2000.0 <= alert_ms <= float(flow_end_ms) + 2000.0):
                return False
        return True

    @staticmethod
    def _deduplicate_alerts(alerts: List[SuricataAlert]) -> tuple[List[SuricataAlert], int]:
        """Collapse the same signature observed on ens33 and the Docker bridge."""
        unique = {}
        for alert in alerts:
            signature_key = alert.signature_id if alert.signature_id is not None else alert.signature
            # Duplicate interface observations in this lab are sub-millisecond apart.
            time_bucket = int(alert.timestamp.timestamp() * 100)
            key = (signature_key, alert.src_ip, alert.src_port, time_bucket)
            current = unique.get(key)
            if current is None or (current.action == "allowed" and alert.action != "allowed"):
                unique[key] = alert
        return list(unique.values()), len(alerts) - len(unique)

    def correlate(self, src_ip: str, dst_port: int, ml_attack_type: str,
                  ml_confidence: float, *, src_port: Optional[int] = None,
                  protocol=None, flow_start_ms: Optional[float] = None,
                  flow_end_ms: Optional[float] = None,
                  related_dst_ports: Optional[set[int]] = None) -> Tuple[float, dict]:
        """
        Correlate ML prediction với Suricata alerts.

        Chiến lược tính điểm (đã sửa lỗi 2026-05-20):
        - Khi ML nói Benign (ml_attack_type rỗng/None): Chỉ cộng điểm nhẹ +0.10
          mỗi loại tấn công DUY NHẤT từ Suricata (suricata_only mode).
          Tổng không vượt quá self.suricata_only_max_score (mặc định 0.30).
        - Khi ML đã nói có tấn công: Dùng logic matching/different_attack_types
          để xác nhận hoặc phát hiện thêm tín hiệu nguy hiểm.
        - Điểm DROP từ Suricata custom rules chỉ tính 1 lần mỗi signature_id.
        - Sau khi tổng hợp, nhân toàn bộ correlation_score với severity_boost
          (hệ số phản ánh mức độ nghiêm trọng cao nhất trong batch alerts).

        Args:
            src_ip: Source IP từ NFStream flow
            dst_port: Destination port
            ml_attack_type: Loại tấn công từ ML prediction (None/'' nếu Benign)
            ml_confidence: Confidence score từ ML

        Returns:
            Tuple[correlation_score, correlation_details]
            - correlation_score: 0.0 - 1.0 (tăng risk score)
            - correlation_details: Dict với thông tin chi tiết
        """
        correlation_score = 0.0
        details = {
            "suricata_alerts_count": 0,
            "same_flow_alerts_count": 0,
            "historical_alerts_count": 0,
            "deduplicated_alerts_count": 0,
            "historical_attack_types": [],
            "matching_signature": False,
            "different_attack_types": False,
            "suricata_only_detection": False,
            "repeat_offender": False,
            "severity_boost": 0.0,
            "matched_signatures": [],
            "matched_signature_ids": [],
            "matched_alerts": [],
            "suricata_action_drop": False,
            "suricata_packet_drop": False,
            "suricata_policy_match": False,
            "suricata_enforcement_requested": False,
        }

        with self._lock:
            all_alerts = list(self._alerts_by_ip.get(src_ip, deque()))

            if not all_alerts:
                return 0.0, details

            related_ports = {int(port) for port in (related_dst_ports or set())}
            flow_alerts_raw = [
                alert for alert in all_alerts
                if self._alert_matches_flow(
                    alert,
                    dst_port=dst_port,
                    src_port=src_port,
                    protocol=protocol,
                    flow_start_ms=flow_start_ms,
                    flow_end_ms=flow_end_ms,
                    related_dst_ports=related_ports,
                )
            ]
            alerts, duplicate_count = self._deduplicate_alerts(flow_alerts_raw)
            historical_alerts = [alert for alert in all_alerts if alert not in flow_alerts_raw]
            details["suricata_alerts_count"] = len(alerts)
            details["same_flow_alerts_count"] = len(alerts)
            details["historical_alerts_count"] = len(historical_alerts)
            details["deduplicated_alerts_count"] = duplicate_count
            details["historical_attack_types"] = sorted({
                attack_type
                for attack_type in (
                    self._map_signature_to_attack_type(alert.signature)
                    for alert in historical_alerts
                )
                if attack_type
            })

            # History is diagnostic context only. It never adds score or overrides
            # the decision for a different flow.
            if not alerts:
                return 0.0, details

            matched_signatures = []
            # Set khử trùng lặp: mỗi loại tấn công chỉ cộng điểm 1 lần.
            seen_attack_types: set = set()
            # Set khử trùng lặp DROP: mỗi signature_id chỉ cộng điểm 1 lần.
            seen_drop_sids: set = set()

            for alert in alerts:
                # Map Suricata signature → ML attack type
                suricata_attack_type = self._map_signature_to_attack_type(alert.signature)
                if alert.signature not in matched_signatures:
                    matched_signatures.append(alert.signature)

                # Cập nhật severity_boost theo alert có severity cao nhất
                severity_weight = self._severity_weights.get(alert.severity, 0.50)
                details["severity_boost"] = max(details["severity_boost"], severity_weight)

                # --- Phân nhánh dựa trên kết quả ML ---

                if not ml_attack_type:
                    # ── Nhánh A: ML nói Benign ──────────────────────────────────
                    # Suricata alert chỉ mang tính tham khảo nhẹ (+0.10/loại).
                    # Tránh kích hoạt "different_attack_types" vì ML chưa
                    # xác nhận bất kỳ tấn công nào.
                    if suricata_attack_type and suricata_attack_type not in seen_attack_types:
                        details["suricata_only_detection"] = True
                        correlation_score += 0.10
                    if suricata_attack_type:
                        seen_attack_types.add(suricata_attack_type)

                elif suricata_attack_type == ml_attack_type:
                    # ── Nhánh B: ML và Suricata cùng loại → Xác nhận (Confirmation) ──
                    if suricata_attack_type not in seen_attack_types:
                        details["matching_signature"] = True
                        correlation_score += 0.20
                    seen_attack_types.add(suricata_attack_type)

                elif suricata_attack_type and suricata_attack_type != "Benign":
                    # ── Nhánh C: ML nói Attack-A, Suricata nói Attack-B → Rất nguy hiểm ──
                    # IP đang thực hiện đa hình thái tấn công.
                    if suricata_attack_type not in seen_attack_types:
                        details["different_attack_types"] = True
                        correlation_score += 0.30
                    seen_attack_types.add(suricata_attack_type)

                # Keep packet verdict and daemon policy enforcement distinct.
                packet_drop = alert.action in ["drop", "blocked", "reject"]
                policy_match = self._is_policy_rule(alert)
                if packet_drop:
                    details["suricata_packet_drop"] = True
                if policy_match:
                    details["suricata_policy_match"] = True
                if packet_drop or policy_match:
                    if alert.signature_id not in seen_drop_sids:
                        correlation_score += 0.50
                        seen_drop_sids.add(alert.signature_id)

            details["matched_signatures"] = matched_signatures
            details["matched_signature_ids"] = sorted({
                alert.signature_id for alert in alerts if alert.signature_id is not None
            })
            details["matched_alerts"] = [alert.to_dict() for alert in alerts]
            details["suricata_action_drop"] = details["suricata_packet_drop"]
            details["suricata_enforcement_requested"] = bool(
                details["suricata_packet_drop"] or details["suricata_policy_match"]
            )

        # Áp dụng severity_boost như hệ số nhân:
        # Alert severity thấp (ET Info/Policy → 0.30) sẽ giảm đáng kể ảnh hưởng.
        # Chỉ nhân khi severity_boost > 0 (tức là có ít nhất 1 alert).
        if details["severity_boost"] > 0:
            correlation_score *= details["severity_boost"]

        # Hard cap khi ML nói Benign: giới hạn tổng điểm tương quan
        # ở mức suricata_only_max_score (mặc định 0.30) để ET Open alerts
        # không thể tự mình đẩy final_confidence vượt ngưỡng alert.
        if not ml_attack_type:
            correlation_score = min(correlation_score, self.suricata_only_max_score)
        else:
            # Khi ML đã xác nhận tấn công, cap cao hơn (0.9) để tối đa hoá tín hiệu
            correlation_score = min(correlation_score, 0.90)

        return correlation_score, details

    def _map_signature_to_attack_type(self, signature: str) -> Optional[str]:
        """Map Suricata signature sang ML attack type."""
        if not signature:
            return None

        signature_lower = signature.lower()

        for keyword, attack_type in self._signature_to_attack_type.items():
            if keyword in signature_lower:
                return attack_type

        return None

    #  Info / Debug

    def get_recent_alerts(self, ip: str, limit: int = 10) -> List[dict]:
        """Lấy recent alerts cho một IP."""
        with self._lock:
            alerts = list(self._alerts_by_ip.get(ip, deque()))[-limit:]
            return [alert.to_dict() for alert in alerts]

    def get_all_alerts_summary(self) -> dict:
        """Lấy summary của tất cả alerts trong cache."""
        with self._lock:
            total_alerts = sum(len(alerts) for alerts in self._alerts_by_ip.values())
            unique_ips = len(self._alerts_by_ip)

            return {
                "total_alerts": total_alerts,
                "unique_ips": unique_ips,
                "top_offenders": [
                    {"ip": ip, "alert_count": len(alerts)}
                    for ip, alerts in sorted(
                        self._alerts_by_ip.items(),
                        key=lambda x: len(x[1]),
                        reverse=True
                    )[:10]
                ]
            }

    def __repr__(self) -> str:
        summary = self.get_all_alerts_summary()
        return (
            f"SuricataCorrelator(alerts={summary['total_alerts']}, "
            f"unique_ips={summary['unique_ips']})"
        )
