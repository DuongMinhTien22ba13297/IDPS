#!/usr/bin/env python3
"""
=============================================================================
Tên file   : autodefense_daemon.py
Mục tiêu   : Core Daemon xử lý sự kiện thời gian thực của hệ thống Zero-Touch IDPS.
             Thực hiện pipeline từ bắt luồng mạng đến ra quyết định chặn tấn công tự động.
Input      :
  - Traffic trực tiếp từ interface mạng (mặc định: ens33).
  - Các cấu hình từ biến môi trường (LOKI_URL, IFACE, MODELS_DIR, CONFIG_DIR).
Output     :
  - Hành động phòng vệ (iptables DROP).
  - Log sự kiện cấu trúc (JSON) gửi tới Grafana/Loki và file action_audit.log.
  - Log hoạt động hệ thống vào autodefense.log.
Quy trình  :
  1. Khởi tạo: Load mô hình ML, IPManager (Blacklist/Whitelist), và AutoFirewall.
  2. Capture: Sử dụng NFStreamer để bắt các luồng mạng (flows).
  3. Pipeline xử lý từng flow:
     - Check Blacklist: Nếu đã bị chặn thì tiếp tục chặn (re-enforce) và skip ML.
     - Check Whitelist: Nếu nằm trong danh sách trắng thì bỏ qua (skip ML).
      - ML Inference: Trích xuất đặc trưng và chạy song song XGBoost Binary & Multi-class.
     - Decision: Nếu score > threshold thì thực hiện Auto-Block và ghi log sự kiện.
Ngày tạo   : 2026-05-15
Ngày sửa   : 2026-09-13
Lí do sửa  : Tự bật Connection Count 10s và một NFStream meter khi metadata
             của model đã chọn feature hành vi nhiều-flow này.
=============================================================================
"""

import json
import time
import logging
import os
import re
import sys
import threading
from datetime import datetime, timezone

from connection_count import (
    CONNECTION_COUNT_FEATURE,
    CONNECTION_KEY_COLUMNS,
    CONNECTION_WINDOW_MS,
    CONNECTION_WINDOW_SECONDS,
)
from realtime_extractor import create_streamer, extract_features, ConnectionTracker
from threat_evaluator import ThreatEvaluator
from auto_firewall import AutoFirewall
from ip_manager import IPManager
from suricata_correlator import SuricataCorrelator
from decision_policy import apply_block
import logging_loki


def _env_flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _normalise_run_id(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())[:64]
    return value or "production"


def _parse_related_ports(value: str) -> dict[int, set[int]]:
    """Parse client:backend port pairs, for example 443:3000,3001:3000."""
    result: dict[int, set[int]] = {}
    for item in value.split(","):
        if not item.strip():
            continue
        try:
            client, backend = (int(part.strip()) for part in item.split(":", 1))
        except (TypeError, ValueError):
            raise ValueError(f"Invalid SURICATA_RELATED_PORTS item: {item!r}")
        result.setdefault(client, set()).add(backend)
    return result


def _utc_timestamp_from_ns(timestamp_ns: int) -> str:
    """Serialize an epoch timestamp in nanoseconds as an unambiguous UTC value."""
    return datetime.fromtimestamp(
        timestamp_ns / 1_000_000_000, timezone.utc
    ).isoformat()


def _flow_to_timestamp_latency_ms(flow, timestamp_ns: int) -> float | None:
    """Return elapsed wall-clock time since NFStream saw the flow's last packet.

    NFStream timestamps are epoch milliseconds, whereas ``timestamp_ns`` comes
    from the host wall clock. A negative value means the clocks cannot be
    safely compared, so the event is deliberately left unmeasured.
    """
    try:
        flow_last_seen_ms = float(getattr(flow, "bidirectional_last_seen_ms"))
    except (AttributeError, TypeError, ValueError):
        return None

    latency_ms = (timestamp_ns / 1_000_000) - flow_last_seen_ms
    if latency_ms < 0:
        logger.warning(
            "Flow %s has a future last-seen timestamp; latency omitted "
            "(flow_last_seen_ms=%s).",
            getattr(flow, "id", "unknown"),
            flow_last_seen_ms,
        )
        return None
    return round(latency_ms, 3)


MONITOR_ONLY_MODE = _env_flag("MONITOR_ONLY_MODE")
SURICATA_ONLY_MODE = _env_flag("SURICATA_ONLY_MODE")
TEST_RUN_ID = _normalise_run_id(os.getenv("TEST_RUN_ID", "production"))
CORRELATION_RELATED_PORTS = _parse_related_ports(
    os.getenv("SURICATA_RELATED_PORTS", "80:3000,443:3000,3001:3000")
)


def _load_ban_duration(config_dir: str) -> int:
    """Đọc ban_duration_seconds từ thresholds.json, mặc định 300s."""
    thresholds_path = os.path.join(config_dir, "thresholds.json")
    try:
        if os.path.exists(thresholds_path):
            with open(thresholds_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            return cfg.get("ban_duration_seconds", 300)
    except Exception as e:
        logger.error(f"Lỗi đọc ban_duration_seconds từ thresholds.json: {e}")
    return 300


def start_unblock_scheduler(ip_mgr: IPManager, firewall: AutoFirewall, ban_registry: dict, ban_lock: threading.Lock):
    """Khởi chạy background thread định kỳ unblock các IP hết hạn chặn và đồng bộ hóa cache."""
    def run_scheduler():
        logger.info("Unblock scheduler background thread started.")
        while True:
            time.sleep(5)  # Quét định kỳ mỗi 5 giây
            
            # 1. Đồng bộ hóa cache firewall từ iptables thực tế của hệ thống
            firewall._sync_from_iptables()
            
            # 2. Đồng bộ hóa registry unblock với blacklist thực tế (reload từ đĩa)
            # Hàm get_blacklist() sẽ tự động reload từ blacklist.json nếu có thay đổi bên ngoài
            current_blacklist = ip_mgr.get_blacklist()
            with ban_lock:
                for ip in list(ban_registry.keys()):
                    if ip not in current_blacklist:
                        ban_registry.pop(ip, None)
            
            # 3. Tiến hành unblock các IP hết hạn chặn (TTL expired)
            now = time.time()
            ips_to_unblock = []
            with ban_lock:
                for ip, unblock_time in list(ban_registry.items()):
                    if now >= unblock_time:
                        ips_to_unblock.append(ip)
            
            for ip in ips_to_unblock:
                try:
                    logger.info(f"Unblocking IP {ip} do hết thời gian chặn (TTL expired)...")
                    firewall.unblock_ip(ip)
                    ip_mgr.remove_from_blacklist(ip)
                    with ban_lock:
                        ban_registry.pop(ip, None)
                except Exception as e:
                    logger.error(f"Lỗi khi tự động unblock IP {ip}: {e}")

    t = threading.Thread(target=run_scheduler, daemon=True)
    t.start()

# =============================================================================
#  CẤU HÌNH LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/app/logs/autodefense.log")
    ]
)
logger = logging.getLogger("Autodefense")

# Thêm Loki Handler để đẩy log lên Grafana
try:
    loki_url = os.getenv("LOKI_URL", "http://192.168.226.151:3100/loki/api/v1/push")
    loki_handler = logging_loki.LokiHandler(
        url=loki_url,
        tags={
            "application": "idps-autodefense",
            "env": "production",
            "run_id": TEST_RUN_ID,
            "mode": "monitor_only" if MONITOR_ONLY_MODE else "enforce",
        },
        version="1",
    )
    logger.addHandler(loki_handler)
    logger.info("Đã kết nối với Loki thành công.")
except Exception as e:
    logger.error(f"Không thể kết nối với Loki: {e}")


# =============================================================================
#  XỬ LÝ TỪNG FLOW (Event-Driven Pipeline)
# =============================================================================

def process_flow(flow, ip_mgr: IPManager, evaluator: ThreatEvaluator,
                 firewall: AutoFirewall, correlator: SuricataCorrelator,
                 ban_duration_seconds: int, ban_registry: dict, ban_lock: threading.Lock):
    """
    Xử lý một flow theo pipeline:
    Blacklist → Whitelist (ML monitor) → ML Inference → Auto-Block

    Nếu SURICATA_ONLY_MODE=true:
    Chỉ dùng Suricata alerts, skip ML → dùng để so sánh A/B testing.
    """
    src_ip = flow.src_ip
    # Bỏ qua IPv6 và các IP rác (chỉ xử lý IPv4)
    if ":" in src_ip or src_ip == "0.0.0.0":
        return

    # ``perf_counter_ns`` measures durations without wall-clock adjustments.
    # ``time_ns`` is retained separately to correlate with NFStream/PCAP time.
    flow_start_monotonic_ns = time.perf_counter_ns()
    flow_start_wall_ns = time.time_ns()

    #  Bước 1: Check Blacklist (Early Drop)
    if ip_mgr.is_blacklisted(src_ip) and not MONITOR_ONLY_MODE:
        # Đảm bảo IP vẫn đang bị chặn trong iptables
        firewall.block_ip(src_ip, reason="BLACKLISTED_RECHECK")
        
        # Gia hạn thời gian unblock (slide window)
        unblock_time = time.time() + ban_duration_seconds
        with ban_lock:
            ban_registry[src_ip] = unblock_time
            
        logger.warning(
            f"BLACKLISTED IP detected: {src_ip} → re-enforce block & slide TTL | "
            f"dst_port={flow.dst_port} protocol={flow.protocol}",
            extra={"tags": {
                "src_ip": src_ip,
                "action": "BLACKLISTED_DROP",
                "dst_port": str(flow.dst_port),
            }}
        )
        return
    elif ip_mgr.is_blacklisted(src_ip):
        logger.warning(
            f"MONITOR_ONLY: {src_ip} exists in blacklist but inference continues | "
            f"dst_port={flow.dst_port}",
            extra={"tags": {
                "src_ip": src_ip, "action": "MONITOR_BLACKLIST_BYPASS",
                "dst_port": str(flow.dst_port), "run_id": TEST_RUN_ID,
            }},
        )

    #  Bước 2: Check Whitelist (Phương án A — Bypass hoàn toàn)
    if ip_mgr.is_whitelisted(src_ip) and not MONITOR_ONLY_MODE:
        logger.debug(
            f"Whitelisted IP {src_ip}: BENIGN (bypassed ML inference) | "
            f"dst_port={flow.dst_port}"
        )
        return

    #  Bước 3: Feature Extraction + ML Inference
    #  (Skip nếu SURICATA_ONLY_MODE=true)
    if SURICATA_ONLY_MODE:
        # ═══ SURICATA-ONLY MODE ═══
        # Không chạy ML, chỉ kiểm tra Suricata alerts cho IP này
        correlation_score, correlation_details = correlator.correlate(
            src_ip=src_ip,
            dst_port=flow.dst_port,
            ml_attack_type="",   # Không có ML prediction
            ml_confidence=0.0,
            src_port=getattr(flow, "src_port", None),
            protocol=getattr(flow, "protocol", None),
            flow_start_ms=getattr(flow, "bidirectional_first_seen_ms", None),
            flow_end_ms=getattr(flow, "bidirectional_last_seen_ms", None),
            related_dst_ports=CORRELATION_RELATED_PORTS.get(int(flow.dst_port), set()),
        )
        # Tạo result giả (không có ML)
        result = {
            "is_attack": correlation_details.get("suricata_enforcement_requested", False),
            "confidence": correlation_score,
            "binary_score": 0.0,
            "multi_score": 0.0,
            "attack_type": None,
            "attack_confidence": 0.0,
            "inference_time_ms": 0.0,
            "class_probabilities": {},
            "ml_confidence": 0.0,
            "ml_attack_type": None,
        }
        # Nếu Suricata có DROP action → đánh dấu là attack
        if correlation_details.get("suricata_enforcement_requested"):
            matched_sigs = correlation_details.get("matched_signatures", ["Unknown"])
            prefix = "Suricata_Packet_Drop" if correlation_details.get("suricata_packet_drop") else "Suricata_Policy_Block"
            result["attack_type"] = f"{prefix} ({matched_sigs[0]})" if matched_sigs else prefix
            result["confidence"] = max(correlation_score, 0.90)
            result["is_attack"] = True

        result["correlation_score"] = correlation_score
        result["correlation_details"] = correlation_details

        # Legacy field retained for compatibility. It is processing time before
        # the decision, not end-to-end attack-detection latency.
        response_time_ms = (
            time.perf_counter_ns() - flow_start_monotonic_ns
        ) / 1_000_000

        # Log mode indicator
        logger.info(f"SURICATA_ONLY: {src_ip} | corr={correlation_score:.3f} | "
                    f"suri_alerts={correlation_details.get('suricata_alerts_count', 0)}")
    else:
        # ═══ FULL SYSTEM MODE (ML + Suricata) ═══
        try:
            features = extract_features(flow, feature_names=evaluator.feature_names)
        except (AttributeError, TypeError, ValueError) as e:
            logger.error(f"Flow {flow.id}: không thể trích xuất features: {e}")
            return

        if features.shape != (evaluator.n_features,):
            logger.warning(
                f"Flow {flow.id}: feature shape={features.shape}, "
                f"expected=({evaluator.n_features},) — skip"
            )
            return

        if src_ip == "172.16.1.10":
            feature_str = ", ".join(
                f"{name}: {val}"
                for name, val in zip(evaluator.feature_names, features)
            )
            logger.info(f"[DEBUG 172.16.1.10] Flow {flow.id} features: {feature_str}")

        result = evaluator.evaluate(features)
        result["ml_confidence"] = result["confidence"]
        result["ml_attack_type"] = result.get("attack_type")

    #  Bước 3.5: Suricata Correlation (Layer 7)
    #  (Chỉ chạy trong Full System mode — đã chạy ở trên cho Suricata-only)
    if not SURICATA_ONLY_MODE:
        correlation_score, correlation_details = correlator.correlate(
            src_ip=src_ip,
            dst_port=flow.dst_port,
            ml_attack_type=result.get("attack_type", ""),
            ml_confidence=result["confidence"],
            src_port=getattr(flow, "src_port", None),
            protocol=getattr(flow, "protocol", None),
            flow_start_ms=getattr(flow, "bidirectional_first_seen_ms", None),
            flow_end_ms=getattr(flow, "bidirectional_last_seen_ms", None),
            related_dst_ports=CORRELATION_RELATED_PORTS.get(int(flow.dst_port), set()),
        )
        
        # Fusion: Kết hợp ML score + Suricata correlation
        final_confidence = min(result["confidence"] + correlation_score, 1.0)
        
        # Nếu Suricata có action=drop (critical L7 rule) -> Override ML
        if correlation_details.get("suricata_enforcement_requested"):
            if not result["is_attack"]:
                result["is_attack"] = True
                matched_sigs = correlation_details.get("matched_signatures", ["Unknown"])
                prefix = "Suricata_Packet_Drop" if correlation_details.get("suricata_packet_drop") else "Suricata_Policy_Block"
                result["attack_type"] = f"{prefix} ({matched_sigs[0]})" if matched_sigs else prefix
                logger.warning(f"SURICATA_OVERRIDE: {src_ip} — same-flow Suricata evidence caught an ML miss")
            final_confidence = max(final_confidence, 0.90)
            
        result["confidence"] = final_confidence
        result["correlation_score"] = correlation_score
        result["correlation_details"] = correlation_details

    decision_wall_ns = time.time_ns()
    decision_monotonic_ns = time.perf_counter_ns()
    response_time_ms = (
        decision_monotonic_ns - flow_start_monotonic_ns
    ) / 1_000_000
    timing = {
        "processing_started_timestamp": _utc_timestamp_from_ns(flow_start_wall_ns),
        "decision_timestamp": _utc_timestamp_from_ns(decision_wall_ns),
        "decision_latency_ms": _flow_to_timestamp_latency_ms(flow, decision_wall_ns),
        "pre_decision_processing_ms": round(response_time_ms, 3),
        "inference_time_ms": round(float(result.get("inference_time_ms", 0.0)), 3),
        "enforcement_requested": False,
        "enforcement_started_timestamp": None,
        "enforcement_completed_timestamp": None,
        "iptables_started_timestamp": None,
        "iptables_completed_timestamp": None,
        "iptables_enforcement_latency_ms": None,
        "blacklist_persistence_latency_ms": None,
        "mitigation_pipeline_latency_ms": None,
        "firewall_rule_inserted": False,
        "end_to_end_latency_ms": None,
        "total_pipeline_latency_ms": None,
        "enforcement_applied": False,
    }

    #  Bước 4: Autonomous Decision Engine
    if result["confidence"] > evaluator.auto_block_threshold:
        # ═══ AUTO_BLOCK ═══
        if not result["is_attack"]:
            result["is_attack"] = True
            result["attack_type"] = result.get("attack_type") or "FUSION_DETECTED"
            
        decision_action = "WOULD_BLOCK" if MONITOR_ONLY_MODE else "AUTO_BLOCKED"
        block_reason = result["attack_type"] or "ML_DETECTED"
        timing["enforcement_requested"] = not MONITOR_ONLY_MODE
        enforcement_start_wall_ns = time.time_ns()
        enforcement_start_monotonic_ns = time.perf_counter_ns()
        if not MONITOR_ONLY_MODE:
            timing["enforcement_started_timestamp"] = _utc_timestamp_from_ns(
                enforcement_start_wall_ns
            )
        blocked = apply_block(
            monitor_only=MONITOR_ONLY_MODE,
            firewall=firewall,
            ip_manager=ip_mgr,
            src_ip=src_ip,
            reason=block_reason,
            timing=timing,
        )
        enforcement_completed_wall_ns = time.time_ns()
        enforcement_completed_monotonic_ns = time.perf_counter_ns()
        if not MONITOR_ONLY_MODE:
            timing["enforcement_completed_timestamp"] = _utc_timestamp_from_ns(
                enforcement_completed_wall_ns
            )
            timing["mitigation_pipeline_latency_ms"] = round(
                (enforcement_completed_monotonic_ns - enforcement_start_monotonic_ns)
                / 1_000_000,
                3,
            )
            iptables_completed_wall_ns = timing.pop(
                "_iptables_completed_wall_ns", None
            )
            if blocked and iptables_completed_wall_ns is not None:
                timing["end_to_end_latency_ms"] = _flow_to_timestamp_latency_ms(
                    flow, iptables_completed_wall_ns
                )
            timing["total_pipeline_latency_ms"] = round(
                (enforcement_completed_monotonic_ns - flow_start_monotonic_ns)
                / 1_000_000,
                3,
            )
            timing["enforcement_applied"] = bool(blocked)
        if not MONITOR_ONLY_MODE:
            # Thêm/cập nhật thời gian unblock trong registry only when enforcing.
            unblock_time = time.time() + ban_duration_seconds
            with ban_lock:
                ban_registry[src_ip] = unblock_time
                logger.info(f"Đã lên lịch unblock cho IP {src_ip} sau {ban_duration_seconds}s (lúc {datetime.fromtimestamp(unblock_time).strftime('%H:%M:%S')})")

        _corr_score = result.get("correlation_score", 0)
        _corr_details = result.get("correlation_details", {})
        _suri_count = _corr_details.get("suricata_alerts_count", 0)
        _suri_info = f"corr={_corr_score:.3f}, suri_alerts={_suri_count}" if _suri_count > 0 else f"corr={_corr_score:.3f}"

        logger.warning(
            f"{decision_action}: {src_ip} | Type: {result['attack_type']} | "
            f"Score: {result['confidence']:.3f} (bin={result.get('binary_score',0):.3f}, "
            f"multi={result.get('multi_score',0):.3f}, {_suri_info}) | "
            f"Port: {flow.dst_port} | "
            f"Inference: {result['inference_time_ms']:.1f}ms | "
            f"Total: {response_time_ms:.0f}ms",
            extra={"tags": {
                "src_ip": src_ip,
                "action": decision_action,
                "attack_type": result["attack_type"] or "Unknown",
                "confidence": f"{result['confidence']:.3f}",
                "bin_score": f"{result.get('binary_score', 0):.3f}",
                "multi_score": f"{result.get('multi_score', 0):.3f}",
                "dst_port": str(flow.dst_port),
                "run_id": TEST_RUN_ID,
                "mode": "monitor_only" if MONITOR_ONLY_MODE else "enforce",
            }}
        )

        # Push structured event cho Grafana
        _log_event(
            src_ip=src_ip,
            dst_port=flow.dst_port,
            confidence=result["confidence"],
            attack_type=result["attack_type"],
            action=decision_action,
            response_time_ms=response_time_ms,
            result=result,
            flow=flow,
            timing=timing,
        )

    elif result["confidence"] > evaluator.alert_threshold:
        decision_action = "SUSPICIOUS"
        # Suspicious nhưng chưa đủ threshold để block
        # Hiển thị chi tiết nguồn điểm để dễ debug (ML vs Suricata correlation)
        _corr_score = result.get("correlation_score", 0)
        _corr_details = result.get("correlation_details", {})
        _suri_count = _corr_details.get("suricata_alerts_count", 0)
        _suri_info = f"corr={_corr_score:.3f}, suri_alerts={_suri_count}" if _suri_count > 0 else f"corr={_corr_score:.3f}"
        _suri_only = _corr_details.get("suricata_only_detection", False)
        if _suri_only:
            _suri_info += ", mode=suricata_only"
        logger.info(
            f"SUSPICIOUS: {src_ip} | Type: {result['attack_type']} | "
            f"Score: {result['confidence']:.3f} (bin={result.get('binary_score',0):.3f}, "
            f"multi={result.get('multi_score',0):.3f}, {_suri_info}) | Port: {flow.dst_port}",
            extra={"tags": {
                "src_ip": src_ip,
                "action": "SUSPICIOUS",
                "confidence": f"{result['confidence']:.3f}",
                "bin_score": f"{result.get('binary_score', 0):.3f}",
                "multi_score": f"{result.get('multi_score', 0):.3f}",
                "correlation_score": f"{_corr_score:.3f}",
                "suri_alerts": str(_suri_count),
                "dst_port": str(flow.dst_port),
                "run_id": TEST_RUN_ID,
                "mode": "monitor_only" if MONITOR_ONLY_MODE else "enforce",
            }}
        )
    else:
        decision_action = "BENIGN"
        # Benign
        logger.info(
            f"Flow {flow.id} from {src_ip}: BENIGN "
            f"(score={result['confidence']:.3f}, bin={result.get('binary_score',0):.3f}, multi={result.get('multi_score',0):.3f}) | Port: {flow.dst_port}",
            extra={"tags": {
                "src_ip": src_ip,
                "action": "BENIGN",
                "bin_score": f"{result.get('binary_score', 0):.3f}",
                "multi_score": f"{result.get('multi_score', 0):.3f}",
                "dst_port": str(flow.dst_port),
                "run_id": TEST_RUN_ID,
                "mode": "monitor_only" if MONITOR_ONLY_MODE else "enforce",
            }}
        )

    # Ghi log JSON xác suất (ẩn khỏi text log thường, chỉ dùng cho Grafana)
    if "class_probabilities" in result and result["class_probabilities"]:
        _log_probabilities(flow, result, decision_action, timing)


# =============================================================================
#  STRUCTURED EVENT LOG (cho Grafana / Loki)
# =============================================================================

def _log_probabilities(flow, result: dict, decision_action: str,
                       timing: dict | None = None):
    """
    Ghi log chuyên biệt chứa các xác suất từ mô hình Multi-class,
    giúp Grafana dễ dàng bóc tách JSON và tạo Panel.
    """
    event = {
        "event_type": "ml_probs",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": TEST_RUN_ID,
        "mode": "monitor_only" if MONITOR_ONLY_MODE else "enforce",
        "flow_id": getattr(flow, "id", None),
        "src_ip": flow.src_ip,
        "src_port": getattr(flow, "src_port", None),
        "dst_ip": getattr(flow, "dst_ip", None),
        "dst_port": flow.dst_port,
        "protocol": getattr(flow, "protocol", None),
        "flow_first_seen_ms": getattr(flow, "bidirectional_first_seen_ms", None),
        "flow_last_seen_ms": getattr(flow, "bidirectional_last_seen_ms", None),
        "binary_score": round(float(result.get("binary_score", 0.0)), 6),
        "multi_attack_score": round(float(result.get("multi_score", 0.0)), 6),
        "ml_confidence": round(float(result.get("ml_confidence", result.get("confidence", 0.0))), 6),
        "hybrid_confidence": round(float(result.get("confidence", 0.0)), 6),
        "ml_attack_type": result.get("ml_attack_type"),
        "hybrid_attack_type": result.get("attack_type"),
        "correlation_score": round(float(result.get("correlation_score", 0.0)), 6),
        "correlation": result.get("correlation_details", {}),
        "decision_action": decision_action,
        "enforcement_applied": decision_action == "AUTO_BLOCKED",
        "probs": result["class_probabilities"],
    }
    if timing:
        event.update(timing)
    logger.info(
        json.dumps(event, ensure_ascii=False),
        extra={"tags": {
            "application": "idps-autodefense",
            "log_type": "ml_probs",
            "src_ip": flow.src_ip,
            "dst_port": str(flow.dst_port),
            "run_id": TEST_RUN_ID,
            "mode": "monitor_only" if MONITOR_ONLY_MODE else "enforce",
        }}
    )

def _log_event(src_ip: str, dst_port: int, confidence: float,
               attack_type: str, action: str, response_time_ms: float,
               result: dict, flow, timing: dict | None = None):
    """
    Ghi structured JSON event theo format architect.md:
    {
        "timestamp": "...",
        "attacker_ip": "...",
        "target_port": 22,
        "ml_confidence_score": 0.98,
        "predicted_threat": "SSH Brute-force",
        "system_action": "AUTO_BLOCKED",
        "response_time_ms": 45
    }
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": TEST_RUN_ID,
        "mode": "monitor_only" if MONITOR_ONLY_MODE else "enforce",
        "flow_id": getattr(flow, "id", None),
        "attacker_ip": src_ip,
        "attacker_port": getattr(flow, "src_port", None),
        "target_ip": getattr(flow, "dst_ip", None),
        "target_port": dst_port,
        "protocol": getattr(flow, "protocol", None),
        "binary_score": round(float(result.get("binary_score", 0.0)), 6),
        "multi_attack_score": round(float(result.get("multi_score", 0.0)), 6),
        "raw_ml_confidence": round(float(result.get("ml_confidence", 0.0)), 6),
        "correlation_score": round(float(result.get("correlation_score", 0.0)), 6),
        "ml_confidence_score": round(confidence, 4),
        "ml_predicted_threat": result.get("ml_attack_type"),
        "predicted_threat": attack_type or "Unknown",
        "system_action": action,
        "enforcement_applied": action == "AUTO_BLOCKED",
        # Legacy: this ends before the firewall call. New reports must use
        # end_to_end_latency_ms only when it is present.
        "response_time_ms": round(response_time_ms, 1),
    }
    if timing:
        event.update(timing)

    # Ghi vào file action_audit.log (JSON-line format)
    try:
        with open("/app/logs/action_audit.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except IOError as e:
        logger.error(f"Không thể ghi action_audit.log: {e}")


# =============================================================================
#  MAIN DAEMON
# =============================================================================

def main():
    interface = os.getenv("IFACE", "ens33")
    models_dir = os.getenv("MODELS_DIR", "/app/models")
    config_dir = os.getenv("CONFIG_DIR", "/app/configs")

    logger.info(f"Interface: {interface}")
    logger.info(f"Models dir: {models_dir}")
    logger.info(f"Config dir: {config_dir}")
    logger.info(
        f"Run ID: {TEST_RUN_ID} | Mode: "
        f"{'MONITOR_ONLY' if MONITOR_ONLY_MODE else 'ENFORCE'}"
    )
    if MONITOR_ONLY_MODE and SURICATA_ONLY_MODE:
        raise ValueError("MONITOR_ONLY_MODE and SURICATA_ONLY_MODE cannot both be true")
    if MONITOR_ONLY_MODE:
        logger.warning(
            "MONITOR_ONLY_MODE=true — ML+Suricata inference remains active; "
            "firewall/blacklist writes are disabled"
        )
    if SURICATA_ONLY_MODE:
        logger.warning("⚠️  SURICATA_ONLY_MODE=true — ML inference DISABLED (chỉ Suricata alerts)")

    # ---- Khởi tạo các module ----
    logger.info("Đang khởi tạo modules...")

    # 1. IP Manager (Blacklist / Whitelist)
    ip_mgr = IPManager(config_dir=config_dir)
    logger.info(f"IPManager: {ip_mgr}")

    # 2. Threat Evaluator (ML Models)
    evaluator = ThreatEvaluator(models_dir=models_dir, config_dir=config_dir)
    logger.info(f"ThreatEvaluator: {evaluator}")
    model_info = evaluator.get_model_info()
    logger.info(f"Classes: {model_info['class_names']}")
    logger.info(
        f"Model experiment: {model_info['experiment_id']} | "
        f"Features: {model_info['feature_count']}"
    )
    logger.info(f"Auto-block threshold: {model_info['auto_block_threshold']}")

    # 3. Auto Firewall (iptables)
    firewall = AutoFirewall()
    logger.info(f"AutoFirewall: {firewall}")

    # Khởi tạo unblock registry cho TTL
    ban_duration_seconds = _load_ban_duration(config_dir)
    ban_registry = {}
    ban_lock = threading.Lock()

    if not MONITOR_ONLY_MODE:
        # Nạp các IP hiện đang bị chặn vào registry để unblock
        current_time = time.time()
        initial_blocked_ips = ip_mgr.get_blacklist()
        for ip in initial_blocked_ips:
            ban_registry[ip] = current_time + ban_duration_seconds
            logger.info(f"Nạp IP hiện có trong blacklist: {ip} → lên lịch unblock sau {ban_duration_seconds}s")

        # Monitor-only must never mutate firewall or blacklist state.
        start_unblock_scheduler(ip_mgr, firewall, ban_registry, ban_lock)

    # 4. Suricata Correlator (Layer 7 DPI)
    suricata_log_path = os.getenv("SURICATA_EVE_PATH", "/app/logs/suricata/eve.json")
    correlator = SuricataCorrelator(
        eve_json_path=suricata_log_path,
        suricata_only_max_score=evaluator.suricata_only_max_score,
    )
    correlator.start()
    logger.info(
        f"SuricataCorrelator: watching {suricata_log_path} | "
        f"suricata_only_max_score={evaluator.suricata_only_max_score}"
    )

    logger.info("Tất cả modules đã sẵn sàng!")

    # ---- Khởi tạo NFStreamer (với retry logic) ----
    logger.info(f"Khởi động NFStreamer trên interface: {interface}")
    MAX_RETRIES = 10
    INITIAL_DELAY = 5  # seconds
    streamer = None
    uses_connection_count = CONNECTION_COUNT_FEATURE in evaluator.feature_names
    if uses_connection_count:
        contract = evaluator.model_metadata.get("connection_count_contract", {})
        expected_contract = {
            "feature": CONNECTION_COUNT_FEATURE,
            "window_ms": CONNECTION_WINDOW_MS,
            "window_interval": "(t-window, t]",
            "includes_current_flow": True,
            "key_columns": list(CONNECTION_KEY_COLUMNS),
            "timestamp_column": "bidirectional_first_seen_ms",
            "causal": True,
        }
        if contract != expected_contract:
            raise ValueError(
                "Connection Count contract trong model_metadata.json không khớp runtime"
            )
    tracker = (
        ConnectionTracker(window_seconds=CONNECTION_WINDOW_SECONDS)
        if uses_connection_count
        else None
    )
    n_meters = 1 if uses_connection_count else 0
    logger.info(
        "Connection Count runtime: enabled=%s window_seconds=%.1f n_meters=%d",
        uses_connection_count,
        CONNECTION_WINDOW_SECONDS,
        n_meters,
    )

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            streamer = create_streamer(
                interface=interface,
                conn_tracker=tracker,
                n_meters=n_meters,
            )
            logger.info("NFStreamer đã sẵn sàng. Đang chờ luồng traffic...")
            break
        except (ValueError, OSError) as e:
            delay = min(INITIAL_DELAY * (2 ** (attempt - 1)), 60)
            logger.warning(
                f"NFStreamer không thể kích hoạt interface '{interface}' "
                f"(lần {attempt}/{MAX_RETRIES}): {e} — thử lại sau {delay}s"
            )
            if attempt == MAX_RETRIES:
                logger.error(
                    f"Không thể khởi tạo NFStreamer sau {MAX_RETRIES} lần thử. "
                    f"Kiểm tra: 1) Interface '{interface}' có tồn tại không (ip link show), "
                    f"2) Container có CAP_ADD: NET_RAW không, "
                    f"3) libpcap-dev đã cài đặt chưa."
                )
                raise
            time.sleep(delay)

    try:
        if MONITOR_ONLY_MODE:
            logger.info("Pipeline: Monitor-only → ML Inference → Suricata correlation → WOULD_BLOCK log")
        else:
            logger.info("Pipeline: Blacklist → Whitelist(ML) → ML Inference → Auto-Block")

        flow_count = 0
        for flow in streamer:
            flow_count += 1
            try:
                process_flow(flow, ip_mgr, evaluator, firewall, correlator, ban_duration_seconds, ban_registry, ban_lock)
            except Exception as e:
                logger.error(f"Lỗi xử lý flow {flow.id}: {e}", exc_info=True)

            # Log thống kê định kỳ (mỗi 100 flows)
            if flow_count % 100 == 0:
                logger.info(
                    f"[STATS] Processed {flow_count} flows | "
                    f"Blocked: {firewall.get_blocked_count()} IPs | "
                    f"Blacklist: {len(ip_mgr.get_blacklist())} | "
                    f"Whitelist: {len(ip_mgr.get_whitelist())}"
                )

    except KeyboardInterrupt:
        logger.info("Nhận tín hiệu dừng (Ctrl+C).")
    except Exception as e:
        logger.error(f"Lỗi nghiêm trọng trong quá trình thực thi: {e}", exc_info=True)
    finally:
        logger.info(f"Tổng số flows đã xử lý: {flow_count if 'flow_count' in dir() else 'N/A'}")
        logger.info(f"Tổng IPs bị block: {firewall.get_blocked_count()}")
        logger.info("Dừng Autodefense Daemon.")


if __name__ == "__main__":
    # Đợi một chút để Suricata khởi động (nếu cần)
    time.sleep(5)
    main()
