#!/usr/bin/env python3
"""
=============================================================================
Tên file   : botnet_sim.py
Mục tiêu   : Mô phỏng hành vi Botnet C&C (Command & Control) beacon pattern.
             Tạo traffic giống bot thật: periodic callback, data exfil, multi-port probing.
Input      : TARGET (IP nạn nhân), các tham số thời gian/chu kỳ.
Output     : Network traffic mô phỏng botnet → IDPS phải phát hiện.
Ngày tạo   : 2026-06-06
Ngày sửa   : —
Lí do sửa  : —
=============================================================================
"""

import socket
import time
import random
import struct
import sys
import argparse

# ── Cấu hình mặc định ──
DEFAULT_TARGET = "172.16.1.2"
BEACON_PORTS = [6667, 6668, 6669, 8443, 4444, 5555]  # IRC + common C&C ports
BEACON_CYCLES = 15          # Số lần beacon
BEACON_INTERVAL_MIN = 10    # Giây tối thiểu giữa 2 beacon
BEACON_INTERVAL_MAX = 25    # Giây tối đa (jitter)
EXFIL_CYCLES = 8            # Số lần gửi data exfiltration
EXFIL_PAYLOAD_SIZE = 4096   # Bytes mỗi lần exfil


def log(msg: str):
    """In log có timestamp."""
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def phase_beacon(target: str, cycles: int):
    """
    Phase 1: C&C Beacon — Mô phỏng bot gọi về C&C server định kỳ.
    Pattern: Kết nối TCP → gửi NICK/JOIN/PRIVMSG (giống IRC bot) → đóng.
    Đặc điểm bất thường mà ML sẽ bắt:
      - IAT (Inter-Arrival Time) có pattern periodic + jitter
      - Destination port bất thường (6667 IRC)
      - Payload nhỏ, nhiều kết nối ngắn
    """
    log(f"=== PHASE 1: C&C Beacon ({cycles} cycles) ===")

    for i in range(cycles):
        port = random.choice(BEACON_PORTS)
        bot_id = random.randint(1000, 9999)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))

            # Gửi IRC-style commands (giả lập C&C protocol)
            s.send(f"NICK bot_{bot_id}\r\n".encode())
            time.sleep(0.1)
            s.send(f"JOIN #botnet-{random.randint(1,5)}\r\n".encode())
            time.sleep(0.1)

            # Gửi "heartbeat" data (random bytes giả lập encrypted payload)
            heartbeat = struct.pack("!I", random.randint(0, 2**32 - 1))
            s.send(f"PRIVMSG #botnet :ALIVE {heartbeat.hex()}\r\n".encode())

            s.close()
            log(f"  Beacon #{i+1}/{cycles}: port={port}, bot_id={bot_id} → OK")
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            # Kết nối bị từ chối cũng tạo flow → ML vẫn thấy
            log(f"  Beacon #{i+1}/{cycles}: port={port} → {type(e).__name__} (flow vẫn tạo)")

        # Jitter: nghỉ ngẫu nhiên giữa 2 beacon (mô phỏng C&C thực tế)
        sleep_time = random.uniform(BEACON_INTERVAL_MIN, BEACON_INTERVAL_MAX)
        log(f"  Đợi {sleep_time:.1f}s (jitter)...")
        time.sleep(sleep_time)


def phase_exfiltration(target: str, cycles: int):
    """
    Phase 2: Data Exfiltration — Mô phỏng bot gửi dữ liệu đánh cắp ra ngoài.
    Pattern: Kết nối HTTPS port không chuẩn → gửi payload lớn.
    Đặc điểm bất thường:
      - Payload lớn (4KB+) gửi đi
      - Port không chuẩn (8443, 4444)
      - Forward bytes >> Backward bytes (one-way data flow)
    """
    log(f"=== PHASE 2: Data Exfiltration ({cycles} cycles) ===")

    for i in range(cycles):
        port = random.choice([8443, 4444, 9999])
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))

            # Giả lập HTTP POST với payload lớn (data exfil)
            payload = bytes(random.getrandbits(8) for _ in range(EXFIL_PAYLOAD_SIZE))
            http_req = (
                f"POST /upload HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"X-Bot-ID: {random.randint(1000,9999)}\r\n"
                f"\r\n"
            ).encode() + payload

            s.send(http_req)
            s.close()
            log(f"  Exfil #{i+1}/{cycles}: port={port}, size={len(payload)}B → OK")
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            log(f"  Exfil #{i+1}/{cycles}: port={port} → {type(e).__name__}")

        time.sleep(random.uniform(3, 8))


def phase_port_probe(target: str):
    """
    Phase 3: Internal Reconnaissance — Mô phỏng bot dò tìm dịch vụ nội bộ.
    Pattern: Connect scan nhiều port trong thời gian ngắn.
    Đặc điểm: Giống PortScan nhưng từ IP đã có C&C traffic → multi-type attack.
    """
    log("=== PHASE 3: Internal Port Probe (30 ports) ===")

    probe_ports = list(range(20, 26)) + [53, 80, 110, 143, 443, 445, 993, 995,
                                          1433, 1521, 3306, 3389, 5432, 5900,
                                          6379, 8080, 8443, 9090, 9200, 27017,
                                          6667, 6668, 4444, 5555, 8888]
    random.shuffle(probe_ports)

    for port in probe_ports[:30]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, port))
            s.close()
            log(f"  Probe port {port}: OPEN")
        except (ConnectionRefusedError, socket.timeout, OSError):
            log(f"  Probe port {port}: closed/filtered")
        time.sleep(random.uniform(0.3, 1.0))


def main():
    parser = argparse.ArgumentParser(description="Botnet C&C Simulation for IDPS Testing")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target IP (default: 172.16.1.2)")
    parser.add_argument("--beacon-cycles", type=int, default=BEACON_CYCLES, help="Number of beacon cycles")
    parser.add_argument("--exfil-cycles", type=int, default=EXFIL_CYCLES, help="Number of exfil cycles")
    parser.add_argument("--fast", action="store_true", help="Fast mode (shorter intervals)")
    args = parser.parse_args()

    # Fast mode: giảm thời gian chờ (cho test nhanh)
    if args.fast:
        global BEACON_INTERVAL_MIN, BEACON_INTERVAL_MAX
        BEACON_INTERVAL_MIN = 3
        BEACON_INTERVAL_MAX = 8

    log(f"Target: {args.target}")
    log(f"Beacon cycles: {args.beacon_cycles}, Exfil cycles: {args.exfil_cycles}")
    log(f"Mode: {'FAST' if args.fast else 'NORMAL'}")
    log("=" * 60)

    phase_beacon(args.target, args.beacon_cycles)
    phase_exfiltration(args.target, args.exfil_cycles)
    phase_port_probe(args.target)

    log("=" * 60)
    log("Botnet simulation hoàn tất.")


if __name__ == "__main__":
    main()
