"""
=============================================================================
Tên file   : connection_count.py
Mục tiêu   : Tính số flow bắt đầu trong cửa sổ thời gian theo cùng một định
             nghĩa cho dữ liệu huấn luyện và NFStream runtime.
Input      : Metadata flow gồm src/dst IP, dst port, protocol và first_seen.
Output     : Connection Count trong cửa sổ (t-window, t], gồm flow hiện tại.
Ngày tạo   : 2026-09-13
Ngày sửa   : 2026-09-13
Lí do sửa  : Bổ sung đặc trưng hành vi nhiều-flow để hỗ trợ nhận diện DoS.
=============================================================================
"""

from __future__ import annotations

from collections import deque

import numpy as np
import pandas as pd


CONNECTION_COUNT_FEATURE = "Connection Count 10s"
CONNECTION_WINDOW_SECONDS = 10.0
CONNECTION_WINDOW_MS = int(CONNECTION_WINDOW_SECONDS * 1000)
CONNECTION_KEY_COLUMNS = ("src_ip", "dst_ip", "dst_port", "protocol")


class ConnectionWindowCounter:
    """Đếm flow-start past-only theo nguồn và dịch vụ đích."""

    def __init__(self, window_seconds: float = CONNECTION_WINDOW_SECONDS):
        if window_seconds <= 0:
            raise ValueError("window_seconds phải lớn hơn 0")
        self.window_seconds = float(window_seconds)
        self._history: dict[tuple[str, str, int, int], deque[float]] = {}
        self._observations = 0

    def observe(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: int,
        timestamp_seconds: float,
    ) -> int:
        """Thêm flow hiện tại và trả số flow trong (t-window, t]."""
        key = (str(src_ip), str(dst_ip), int(dst_port), int(protocol))
        timestamp = float(timestamp_seconds)
        cutoff = timestamp - self.window_seconds
        timestamps = self._history.setdefault(key, deque())

        # Capture timestamps tăng dần khi dùng một NFStream meter. Từ chối
        # làm sai âm thầm nếu nguồn dữ liệu vi phạm giả định này.
        if timestamps and timestamp < timestamps[-1]:
            raise ValueError(
                f"Timestamp không tăng cho key={key}: {timestamp} < {timestamps[-1]}"
            )
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        timestamps.append(timestamp)

        self._observations += 1
        if self._observations % 1000 == 0:
            stale_keys = [
                stale_key
                for stale_key, values in self._history.items()
                if values and values[-1] <= cutoff
            ]
            for stale_key in stale_keys:
                del self._history[stale_key]
        return len(timestamps)


def compute_connection_counts(
    metadata: pd.DataFrame,
    *,
    window_ms: int = CONNECTION_WINDOW_MS,
) -> np.ndarray:
    """Tính count cho toàn bộ dataframe, trả kết quả theo đúng thứ tự dòng.

    Dữ liệu được sắp xếp ổn định theo từng connection key và first_seen trước
    khi dùng cửa sổ past-only. Vì vậy kết quả không phụ thuộc thứ tự flow được
    NFStream đóng/ghi ra CSV và không nhìn vào flow tương lai.
    """
    if window_ms <= 0:
        raise ValueError("window_ms phải lớn hơn 0")
    required = [*CONNECTION_KEY_COLUMNS, "bidirectional_first_seen_ms"]
    missing = [column for column in required if column not in metadata.columns]
    if missing:
        raise ValueError(f"Thiếu metadata để tính connection count: {missing}")

    timestamps = pd.to_numeric(
        metadata["bidirectional_first_seen_ms"], errors="coerce"
    ).to_numpy(dtype=np.float64)
    valid = np.isfinite(timestamps) & metadata[list(CONNECTION_KEY_COLUMNS)].notna().all(axis=1).to_numpy()
    result = np.full(len(metadata), np.nan, dtype=np.float32)
    if not valid.any():
        return result

    valid_positions = np.flatnonzero(valid)
    valid_keys = pd.MultiIndex.from_frame(
        metadata.loc[valid, list(CONNECTION_KEY_COLUMNS)]
    )
    key_codes, _ = pd.factorize(valid_keys, sort=False)
    valid_times = timestamps[valid].astype(np.int64, copy=False)

    # Primary key: key code; secondary: timestamp; tertiary: original row.
    order = np.lexsort((valid_positions, valid_times, key_codes))
    sorted_positions = valid_positions[order]
    sorted_times = valid_times[order]
    sorted_codes = key_codes[order]

    boundaries = np.flatnonzero(np.r_[True, sorted_codes[1:] != sorted_codes[:-1], True])
    for start, end in zip(boundaries[:-1], boundaries[1:]):
        group_times = sorted_times[start:end]
        # side="right" loại timestamp đúng bằng t-window, khớp (t-window, t].
        left = np.searchsorted(group_times, group_times - window_ms, side="right")
        counts = np.arange(1, len(group_times) + 1, dtype=np.int64) - left
        result[sorted_positions[start:end]] = counts.astype(np.float32)
    return result
