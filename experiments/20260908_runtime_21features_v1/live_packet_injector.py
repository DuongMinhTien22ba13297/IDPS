"""Inject bounded synthetic TCP flows for an NFStream live-path smoke test.

The script uses only Python's standard library and sends Ethernet frames whose
destination MAC is the selected interface itself. The default source address is
from RFC 2544's benchmarking range so it cannot identify a real Internet host.
"""

import argparse
import json
import socket
import struct
import time
from pathlib import Path


def checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def mac_bytes(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def build_tcp_frame(
    source_mac: str,
    destination_mac: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    flags: int = 0x02,
) -> bytes:
    ethernet = struct.pack(
        "!6s6sH", mac_bytes(destination_mac), mac_bytes(source_mac), 0x0800
    )

    source_ip_bytes = socket.inet_aton(source_ip)
    destination_ip_bytes = socket.inet_aton(destination_ip)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        5 << 4,
        flags,
        64240,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        source_ip_bytes,
        destination_ip_bytes,
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    tcp_checksum = checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        5 << 4,
        flags,
        64240,
        tcp_checksum,
        0,
    )

    total_length = 20 + len(tcp_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        sequence & 0xFFFF,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        source_ip_bytes,
        destination_ip_bytes,
    )
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        sequence & 0xFFFF,
        0,
        64,
        socket.IPPROTO_TCP,
        ip_checksum,
        source_ip_bytes,
        destination_ip_bytes,
    )
    return ethernet + ip_header + tcp_header


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="ens33")
    parser.add_argument("--source-ip", default="198.18.0.10")
    parser.add_argument("--destination-ip", default="172.16.1.2")
    parser.add_argument("--source-mac", default="02:00:00:00:00:10")
    parser.add_argument("--destination-mac")
    parser.add_argument("--count", type=int, default=32)
    parser.add_argument("--start-port", type=int, default=20000)
    parser.add_argument("--interval-ms", type=float, default=5.0)
    parser.add_argument(
        "--close-with-rst",
        action="store_true",
        help="send a same-direction RST+ACK after every SYN so NFStream expires the flow promptly",
    )
    args = parser.parse_args()

    if not 1 <= args.count <= 256:
        raise ValueError("count must be between 1 and 256")

    destination_mac = args.destination_mac
    if destination_mac is None:
        destination_mac = Path(
            f"/sys/class/net/{args.interface}/address"
        ).read_text(encoding="ascii").strip()

    started = time.time()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as raw_socket:
        raw_socket.bind((args.interface, 0))
        for index in range(args.count):
            frame = build_tcp_frame(
                source_mac=args.source_mac,
                destination_mac=destination_mac,
                source_ip=args.source_ip,
                destination_ip=args.destination_ip,
                source_port=40000 + index,
                destination_port=args.start_port + index,
                sequence=index + 1,
            )
            raw_socket.send(frame)
            if args.close_with_rst:
                close_frame = build_tcp_frame(
                    source_mac=args.source_mac,
                    destination_mac=destination_mac,
                    source_ip=args.source_ip,
                    destination_ip=args.destination_ip,
                    source_port=40000 + index,
                    destination_port=args.start_port + index,
                    sequence=index + 2,
                    flags=0x14,
                )
                raw_socket.send(close_frame)
            time.sleep(args.interval_ms / 1000.0)

    print(
        json.dumps(
            {
                "interface": args.interface,
                "source_ip": args.source_ip,
                "destination_ip": args.destination_ip,
                "destination_mac": destination_mac,
                "flows_sent": args.count,
                "close_with_rst": args.close_with_rst,
                "destination_port_start": args.start_port,
                "elapsed_ms": round((time.time() - started) * 1000, 3),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
