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
     - ML Inference: Trích xuất đặc trưng và dự đoán qua 2 tầng XGBoost (Binary & Multi-class).
     - Decision: Nếu score > threshold thì thực hiện Auto-Block và ghi log sự kiện.
=============================================================================
"""

import json
import time
import logging
import os
import sys
from datetime import datetime, timezone

from realtime_extractor import create_streamer, extract_features, ConnectionTracker
from threat_evaluator import ThreatEvaluator
from auto_firewall import AutoFirewall
from ip_manager import IPManager
import logging_loki

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
        tags={"application": "idps-autodefense", "env": "production"},
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
                 firewall: AutoFirewall):
    """
    Xử lý một flow theo pipeline:
    Blacklist → Whitelist (ML monitor) → ML Inference → Auto-Block
    """
    src_ip = flow.src_ip
    # Bỏ qua IPv6 và các IP rác (chỉ xử lý IPv4)
    if ":" in src_ip or src_ip == "0.0.0.0":
        return

    flow_start = time.time()

    # -----------------------------------------------------------------
    #  Bước 1: Check Blacklist (Early Drop)
    # -----------------------------------------------------------------
    if ip_mgr.is_blacklisted(src_ip):
        # Đảm bảo IP vẫn đang bị chặn trong iptables
        firewall.block_ip(src_ip, reason="BLACKLISTED_RECHECK")
        logger.warning(
            f"BLACKLISTED IP detected: {src_ip} → skip ML | "
            f"dst_port={flow.dst_port} protocol={flow.protocol}",
            extra={"tags": {
                "src_ip": src_ip,
                "action": "BLACKLISTED_DROP",
                "dst_port": str(flow.dst_port),
            }}
        )
        return

    # -----------------------------------------------------------------
    #  Bước 2: Check Whitelist (Phương án A — Bypass hoàn toàn)
    # -----------------------------------------------------------------
    if ip_mgr.is_whitelisted(src_ip):
        logger.debug(
            f"Whitelisted IP {src_ip}: BENIGN (bypassed ML inference) | "
            f"dst_port={flow.dst_port}"
        )
        return

    # -----------------------------------------------------------------
    #  Bước 3: Feature Extraction + ML Inference
    # -----------------------------------------------------------------
    features = extract_features(flow)
    if len(features) != 30:
        logger.warning(f"Flow {flow.id}: chỉ có {len(features)}/30 features — skip")
        return

    result = evaluator.evaluate(features)
    response_time_ms = (time.time() - flow_start) * 1000

    # -----------------------------------------------------------------
    #  Bước 4: Autonomous Decision Engine
    # -----------------------------------------------------------------
    if result["is_attack"] and result["confidence"] > evaluator.auto_block_threshold:
        # ═══ AUTO_BLOCK ═══
        blocked = firewall.block_ip(src_ip, reason=result["attack_type"] or "ML_DETECTED")

        if blocked:
            ip_mgr.add_to_blacklist(src_ip, reason=result["attack_type"] or "ML_DETECTED")

        logger.warning(
            f"AUTO_BLOCKED: {src_ip} | Type: {result['attack_type']} | "
            f"Score: {result['confidence']:.3f} (bin={result.get('binary_score',0):.3f}, multi={result.get('multi_score',0):.3f}) | "
            f"Port: {flow.dst_port} | "
            f"Inference: {result['inference_time_ms']:.1f}ms | "
            f"Total: {response_time_ms:.0f}ms",
            extra={"tags": {
                "src_ip": src_ip,
                "action": "AUTO_BLOCKED",
                "attack_type": result["attack_type"] or "Unknown",
                "confidence": f"{result['confidence']:.3f}",
                "bin_score": f"{result.get('binary_score', 0):.3f}",
                "multi_score": f"{result.get('multi_score', 0):.3f}",
                "dst_port": str(flow.dst_port),
            }}
        )

        # Push structured event cho Grafana
        _log_event(
            src_ip=src_ip,
            dst_port=flow.dst_port,
            confidence=result["confidence"],
            attack_type=result["attack_type"],
            action="AUTO_BLOCKED",
            response_time_ms=response_time_ms
        )

    elif result["confidence"] > evaluator.alert_threshold:
        # Suspicious nhưng chưa đủ threshold để block
        logger.info(
            f"SUSPICIOUS: {src_ip} | Type: {result['attack_type']} | "
            f"Score: {result['confidence']:.3f} (bin={result.get('binary_score',0):.3f}, multi={result.get('multi_score',0):.3f}) | Port: {flow.dst_port}",
            extra={"tags": {
                "src_ip": src_ip,
                "action": "SUSPICIOUS",
                "confidence": f"{result['confidence']:.3f}",
                "bin_score": f"{result.get('binary_score', 0):.3f}",
                "multi_score": f"{result.get('multi_score', 0):.3f}",
                "dst_port": str(flow.dst_port),
            }}
        )
    else:
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
            }}
        )

    # Ghi log JSON xác suất (ẩn khỏi text log thường, chỉ dùng cho Grafana)
    if "class_probabilities" in result and result["class_probabilities"]:
        _log_probabilities(src_ip, flow.dst_port, result["class_probabilities"])


# =============================================================================
#  STRUCTURED EVENT LOG (cho Grafana / Loki)
# =============================================================================

def _log_probabilities(src_ip: str, dst_port: int, probs: dict):
    """
    Ghi log chuyên biệt chứa các xác suất từ mô hình Multi-class,
    giúp Grafana dễ dàng bóc tách JSON và tạo Panel.
    """
    event = {
        "event_type": "ml_probs",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_port": dst_port,
        "probs": probs
    }
    logger.info(
        json.dumps(event, ensure_ascii=False),
        extra={"tags": {
            "application": "idps-autodefense",
            "log_type": "ml_probs",
            "src_ip": src_ip
        }}
    )

def _log_event(src_ip: str, dst_port: int, confidence: float,
               attack_type: str, action: str, response_time_ms: float):
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
        "attacker_ip": src_ip,
        "target_port": dst_port,
        "ml_confidence_score": round(confidence, 4),
        "predicted_threat": attack_type or "Unknown",
        "system_action": action,
        "response_time_ms": round(response_time_ms, 1)
    }

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
    logger.info(f"Auto-block threshold: {model_info['auto_block_threshold']}")

    # 3. Auto Firewall (iptables)
    firewall = AutoFirewall()
    logger.info(f"AutoFirewall: {firewall}")

    logger.info("Tất cả modules đã sẵn sàng!")

    # ---- Khởi tạo NFStreamer ----
    logger.info(f"Khởi động NFStreamer trên interface: {interface}")
    try:
        tracker = ConnectionTracker(window_sec=10)
        streamer = create_streamer(interface=interface, conn_tracker=tracker)
        logger.info("NFStreamer đã sẵn sàng. Đang chờ luồng traffic...")
        logger.info("Pipeline: Blacklist → Whitelist(ML) → ML Inference → Auto-Block")

        flow_count = 0
        for flow in streamer:
            flow_count += 1
            try:
                process_flow(flow, ip_mgr, evaluator, firewall)
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
