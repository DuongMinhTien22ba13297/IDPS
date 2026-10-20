"""
=============================================================================
Tên file   : realtime_extractor.py
Mục tiêu   : Trích xuất đặc trưng mạng thời gian thực từ traffic sống hoặc file PCAP.
             Chuyển đổi dữ liệu thô từ NFStream sang vector đặc trưng tương thích
             với mô hình XGBoost đã khóa trong model_metadata.json.
Input      :
  - interface : Tên card mạng để lắng nghe (mặc định: ens33).
  - flow      : Luồng mạng (flow object) được cung cấp bởi NFStreamer.
Output     :
  - np.ndarray : Vector đặc trưng theo đúng schema model_metadata.json.
Quy trình  :
  1. Cấu hình Plugins: Sử dụng TCPWindowPlugin để lấy Init_Win_bytes
     (đặc trưng nâng cao mà NFStream mặc định không có).
  2. Create Streamer: Khởi tạo bộ bắt gói tin với các tham số timeout (idle, active).
  3. Mapping: Chuyển đổi các thuộc tính của flow (số gói tin, độ dài, thời gian IAT,
     cờ TCP...) thành vector theo đúng thứ tự trong metadata của mô hình.
Ngày tạo   : 2026-05-01
Ngày sửa   : 2026-09-13
Lí do sửa  : Hỗ trợ Connection Count 10s theo cùng công thức past-only với
             tập train; yêu cầu một meter khi bật feature trạng thái này.
=============================================================================
"""
import random
import struct

import numpy as np
from nfstream import NFPlugin, NFStreamer

from connection_count import (
    CONNECTION_COUNT_FEATURE,
    CONNECTION_WINDOW_SECONDS,
    ConnectionWindowCounter,
)


# Thứ tự mặc định khớp tuyệt đối với XGBoost production v2
# (20260913_connection_count_10s_v2). Autodefense vẫn truyền schema từ
# model_metadata.json để kiểm tra tường minh và hỗ trợ rollback artifact cũ.
FEATURE_NAMES = [
    "RST Flag Count",
    "Bwd Packets/s",
    "SYN Flag Count",
    "Total Fwd Packets",
    "Bwd Packet Length Std",
    "Down/Up Ratio",
    CONNECTION_COUNT_FEATURE,
    "ACK Flag Count",
    "Fwd PSH Flags",
    "Flow Packets/s",
    "Fwd IAT Min",
    "Packet Length Mean",
    "Total Length of Fwd Packets",
    "Min Packet Length",
    "Bwd Packet Length Mean",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "PSH Flag Count",
    "Total Backward Packets",
    "Flow IAT Std",
    "Init_Win_bytes_forward",
]

ConnectionTracker = ConnectionWindowCounter


class ConnectionCountPlugin(NFPlugin):
    def on_init(self, packet, flow):
        # packet.time is in milliseconds
        current_time_sec = packet.time / 1000.0
        flow.udps.connection_count_10s = self.tracker.observe(
            flow.src_ip,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol,
            current_time_sec,
        )

# Custom plugin cho TCP Window Size (Init_Win_bytes_forward/backward).
# Công thức này giống CustomFeaturePlugin trong extract_50_features.py.
class TCPWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.init_win_fwd = 0
        flow.udps.init_win_bwd = 0
        self._update_window(packet, flow)

    def on_update(self, packet, flow):
        self._update_window(packet, flow)

    @staticmethod
    def _update_window(packet, flow):
        if packet.protocol != 6:
            return

        if packet.direction == 0 and flow.udps.init_win_fwd != 0:
            return
        if packet.direction == 1 and flow.udps.init_win_bwd != 0:
            return

        try:
            ip_packet = packet.ip_packet
            if packet.ip_version == 4:
                ip_header_len = (ip_packet[0] & 0x0F) * 4
            elif packet.ip_version == 6:
                ip_header_len = 40
            else:
                return

            if len(ip_packet) < ip_header_len + 16:
                return

            win_size = struct.unpack(
                "!H", ip_packet[ip_header_len + 14 : ip_header_len + 16]
            )[0]
            if packet.direction == 0:
                flow.udps.init_win_fwd = win_size
            else:
                flow.udps.init_win_bwd = win_size
        except (AttributeError, IndexError, TypeError, struct.error):
            # Giữ 0 nếu NFStream không cung cấp raw IP bytes cho packet này.
            return


def create_streamer(interface="ens33", conn_tracker=None, n_meters=0):
    """Tạo NFStreamer để capture live traffic. n_meters=0 tương ứng với tự động đa tiến trình tối đa CPU cores."""
    plugins = [TCPWindowPlugin()]
    if conn_tracker is not None:
        if n_meters != 1:
            raise ValueError(
                "Connection Count yêu cầu n_meters=1 để có một cửa sổ đếm duy nhất"
            )
        plugins.append(ConnectionCountPlugin(tracker=conn_tracker))

    streamer = NFStreamer(
        source=interface,
        statistical_analysis=True,  # Bật 48 statistical features
        accounting_mode=0,          # Link layer
        udps=plugins,               # Danh sách plugins
        idle_timeout=10,
        active_timeout=30,
        n_meters=n_meters,
    )
    
    # Monkey patch: Thay đổi _idx thành số ngẫu nhiên lớn
    # Điều này giúp group_id = os.getpid() + self._idx tránh trùng lặp fanout group ID trong namespace host network
    streamer._idx = random.randint(10000, 50000)
    
    return streamer


def _udps_value(flow, name: str) -> float:
    """Đọc feature plugin an toàn; trả về 0 nếu flow không có UDPS value."""
    return getattr(getattr(flow, "udps", None), name, 0.0)


def extract_feature_values(flow) -> dict[str, float]:
    """Map một NFStream flow thành dictionary dùng cùng công thức với offline extraction."""
    duration_s_safe = max(flow.bidirectional_duration_ms / 1000.0, 0.001)
    down_up_ratio = (
        flow.dst2src_packets / flow.src2dst_packets
        if flow.src2dst_packets > 0
        else 0.0
    )

    return {
        # Legacy 15-feature entries are retained for safe rollback artifacts.
        "Bwd IAT Max": flow.dst2src_max_piat_ms * 1000.0,
        "Bwd IAT Std": flow.dst2src_stddev_piat_ms * 1000.0,
        "Bwd Packet Length Mean": flow.dst2src_mean_ps,
        "Fwd Packet Length Mean": flow.src2dst_mean_ps,
        "Bwd Packets/s": flow.dst2src_packets / duration_s_safe,
        "Max Packet Length": max(flow.src2dst_max_ps, flow.dst2src_max_ps),
        "RST Flag Count": flow.bidirectional_rst_packets,
        "Bwd Packet Length Std": flow.dst2src_stddev_ps,
        "Total Fwd Packets": flow.src2dst_packets,
        "Down/Up Ratio": down_up_ratio,
        "SYN Flag Count": flow.bidirectional_syn_packets,
        "PSH Flag Count": flow.bidirectional_psh_packets,
        "Total Length of Fwd Packets": flow.src2dst_bytes,
        "ACK Flag Count": flow.bidirectional_ack_packets,
        "Flow IAT Std": flow.bidirectional_stddev_piat_ms * 1000.0,
        "Flow Bytes/s": flow.bidirectional_bytes / duration_s_safe,
        "Flow Packets/s": flow.bidirectional_packets / duration_s_safe,
        "Total Length of Bwd Packets": flow.dst2src_bytes,
        "Fwd IAT Min": flow.src2dst_min_piat_ms * 1000.0,
        "Packet Length Mean": flow.bidirectional_mean_ps,
        "Min Packet Length": min(flow.src2dst_min_ps, flow.dst2src_min_ps),
        "Fwd PSH Flags": flow.src2dst_psh_packets,
        "Total Backward Packets": flow.dst2src_packets,
        "Packet Length Std": flow.bidirectional_stddev_ps,
        "Fwd Packet Length Max": flow.src2dst_max_ps,
        "Init_Win_bytes_forward": _udps_value(flow, "init_win_fwd"),
        "Fwd Packet Length Std": flow.src2dst_stddev_ps,
        CONNECTION_COUNT_FEATURE: _udps_value(flow, "connection_count_10s"),
    }


def extract_features(flow, feature_names=None) -> np.ndarray:
    """Map NFStream flow thành vector theo thứ tự feature mà model yêu cầu.

    LƯU Ý QUAN TRỌNG:
      - Dataset NFStream lưu các IAT bằng microseconds, trong khi NFStream runtime
        trả milliseconds; các trường IAT do đó được nhân 1000.
      - Các rate dùng bidirectional duration tính bằng seconds làm mẫu số.
      - feature_names mặc định là vector 21 chiều đã khóa, nhưng có thể nhận vector
        từ ThreatEvaluator để kiểm tra/tương thích artifact một cách tường minh.
    """
    requested_names = FEATURE_NAMES if feature_names is None else list(feature_names)
    feature_values = extract_feature_values(flow)
    unsupported = [name for name in requested_names if name not in feature_values]
    if unsupported:
        raise ValueError(f"Runtime không hỗ trợ các feature: {unsupported}")

    return np.asarray(
        [feature_values[name] for name in requested_names], dtype=np.float64
    )
