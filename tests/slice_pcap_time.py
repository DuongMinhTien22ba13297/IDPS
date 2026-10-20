#!/usr/bin/env python3
"""
=============================================================================
Tên file   : slice_pcap_time.py
Mục tiêu   : Cắt một tệp PCAP cổ điển theo khoảng thời gian mà không thay đổi
             hoặc ghi đè tệp nguồn.
Input      : PCAP nguồn, PCAP đích, timestamp UTC bắt đầu/kết thúc dạng ISO-8601.
Output     : PCAP mới chỉ chứa các packet trong khoảng [start, end).
Ngày tạo   : 2026-09-13
Ngày sửa   : 2026-09-13
Lí do sửa  : Tạo tập replay DDoS CICIDS2017 có thể kiểm toán từ PCAP Friday.
=============================================================================
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def parse_utc(value: str) -> datetime:
    """Parse ISO-8601 and require an explicit timezone."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError(
            "Timestamp phải chứa timezone, ví dụ Z hoặc +00:00"
        )
    return parsed.astimezone(timezone.utc)


def slice_pcap(
    source: Path,
    destination: Path,
    start: datetime,
    end: datetime,
) -> dict:
    """Copy packet records whose timestamps fall inside [start, end)."""
    if start >= end:
        raise ValueError("Thời điểm bắt đầu phải nhỏ hơn thời điểm kết thúc")
    if destination.exists():
        raise FileExistsError(f"Tệp đích đã tồn tại, từ chối ghi đè: {destination}")

    start_epoch = start.timestamp()
    end_epoch = end.timestamp()
    total_packets = 0
    selected_packets = 0
    selected_payload_bytes = 0
    first_selected = None
    last_selected = None

    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src:
        global_header = src.read(24)
        if len(global_header) != 24:
            raise ValueError("PCAP thiếu global header 24 byte")

        magic = global_header[:4]
        if magic not in PCAP_FORMATS:
            raise ValueError(
                "Định dạng PCAP không hỗ trợ; script không xử lý PCAPNG"
            )
        endian, fraction_scale = PCAP_FORMATS[magic]
        packet_header_struct = struct.Struct(f"{endian}IIII")

        with destination.open("xb") as dst:
            dst.write(global_header)
            while True:
                packet_header = src.read(packet_header_struct.size)
                if not packet_header:
                    break
                if len(packet_header) != packet_header_struct.size:
                    raise ValueError("PCAP kết thúc giữa packet header")

                (
                    ts_sec,
                    ts_fraction,
                    captured_len,
                    _original_len,
                ) = packet_header_struct.unpack(packet_header)
                if captured_len > 16 * 1024 * 1024:
                    raise ValueError(f"captured_len bất thường: {captured_len}")

                payload = src.read(captured_len)
                if len(payload) != captured_len:
                    raise ValueError("PCAP kết thúc giữa packet payload")

                total_packets += 1
                packet_epoch = ts_sec + (ts_fraction / fraction_scale)
                if start_epoch <= packet_epoch < end_epoch:
                    dst.write(packet_header)
                    dst.write(payload)
                    selected_packets += 1
                    selected_payload_bytes += captured_len
                    first_selected = (
                        packet_epoch if first_selected is None else first_selected
                    )
                    last_selected = packet_epoch

    return {
        "source": str(source.resolve()),
        "destination": str(destination.resolve()),
        "start_utc": start.isoformat(),
        "end_utc_exclusive": end.isoformat(),
        "total_packets_scanned": total_packets,
        "selected_packets": selected_packets,
        "selected_payload_bytes": selected_payload_bytes,
        "first_selected_utc": (
            datetime.fromtimestamp(first_selected, tz=timezone.utc).isoformat()
            if first_selected is not None
            else None
        ),
        "last_selected_utc": (
            datetime.fromtimestamp(last_selected, tz=timezone.utc).isoformat()
            if last_selected is not None
            else None
        ),
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--start", required=True, type=parse_utc)
    parser.add_argument("--end", required=True, type=parse_utc)
    args = parser.parse_args()

    summary = slice_pcap(args.source, args.destination, args.start, args.end)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if summary["selected_packets"] == 0:
        raise SystemExit("Không có packet nào trong khoảng thời gian đã chọn")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
