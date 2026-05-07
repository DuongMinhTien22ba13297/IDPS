from nfstream import NFStreamer, NFPlugin
import numpy as np

# Custom plugin cho features NFStream không có sẵn
class TCPWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.init_win_fwd = 0
        flow.udps.init_win_bwd = 0
        flow.udps.ack_flag_count = 0
        flow.udps.is_first_packet = True

    def on_update(self, packet, flow):
        if flow.udps.is_first_packet and packet.direction == 0:
            flow.udps.init_win_fwd = packet.ip_size  # Simplified
            flow.udps.is_first_packet = False
        if packet.direction == 1 and flow.udps.init_win_bwd == 0:
            flow.udps.init_win_bwd = packet.ip_size  # Simplified
        # ACK flag counting would need raw TCP flag access


def create_streamer(interface="ens33"):
    """Tạo NFStreamer để capture live traffic."""
    return NFStreamer(
        source=interface,
        statistical_analysis=True,  # Bật 48 statistical features
        accounting_mode=0,          # Link layer
        udps=TCPWindowPlugin(),
        idle_timeout=3,
        active_timeout=5,
    )


def extract_features(flow) -> np.ndarray:
    """Map NFStream flow → 30-feature vector theo thứ tự A-Z (khớp với training CIC-IDS-2017).

    LƯU Ý QUAN TRỌNG:
      - CIC-IDS-2017 dùng MICROSECONDS (µs) cho tất cả trường thời gian.
      - NFStream trả về MILLISECONDS (ms) → cần nhân ×1000 để chuyển sang µs.
      - Flow Bytes/s và Flow Packets/s trong CIC dùng duration µs làm mẫu số.
    """
    # NFStream ms → CIC-IDS-2017 µs (×1000)
    duration_us = flow.bidirectional_duration_ms * 1000.0  # µs
    duration_us_safe = max(duration_us, 1.0)  # tránh chia cho 0

    features = np.array([
        # 0: ACK Flag Count
        getattr(flow.udps, 'ack_flag_count', 0),
        # 1: Average Packet Size
        flow.bidirectional_mean_ps,
        # 2: Avg Bwd Segment Size
        flow.dst2src_mean_ps,
        # 3: Bwd IAT Min (ms → µs)
        flow.dst2src_min_piat_ms * 1000.0,
        # 4: Bwd IAT Std (ms → µs)
        flow.dst2src_stddev_piat_ms * 1000.0,
        # 5: Bwd IAT Total (ms → µs, approx)
        flow.dst2src_max_piat_ms * flow.dst2src_packets * 1000.0,
        # 6: Bwd Packet Length Mean
        flow.dst2src_mean_ps,
        # 7: Destination Port
        flow.dst_port,
        # 8: Flow Bytes/s (bytes / duration_µs × 1e6 = bytes/s)
        flow.bidirectional_bytes / duration_us_safe * 1e6,
        # 9: Flow Duration (µs)
        duration_us,
        # 10: Flow IAT Max (ms → µs)
        flow.bidirectional_max_piat_ms * 1000.0,
        # 11: Flow IAT Std (ms → µs)
        flow.bidirectional_stddev_piat_ms * 1000.0,
        # 12: Flow Packets/s (packets / duration_µs × 1e6 = packets/s)
        flow.bidirectional_packets / duration_us_safe * 1e6,
        # 13: Fwd Header Length (approximate: total_bytes - payload_bytes)
        flow.src2dst_bytes - (flow.src2dst_mean_ps * flow.src2dst_packets),
        # 14: Fwd IAT Max (ms → µs)
        flow.src2dst_max_piat_ms * 1000.0,
        # 15: Fwd IAT Mean (ms → µs)
        flow.src2dst_mean_piat_ms * 1000.0,
        # 16: Fwd IAT Min (ms → µs)
        flow.src2dst_min_piat_ms * 1000.0,
        # 17: Fwd IAT Std (ms → µs)
        flow.src2dst_stddev_piat_ms * 1000.0,
        # 18: Fwd IAT Total (ms → µs, approx)
        flow.src2dst_max_piat_ms * flow.src2dst_packets * 1000.0,
        # 19: Fwd Packet Length Max
        flow.src2dst_max_ps,
        # 20: Fwd Packets/s (packets / duration_µs × 1e6 = packets/s)
        flow.src2dst_packets / duration_us_safe * 1e6,
        # 21: Idle Max (ms → µs)
        (flow.bidirectional_max_idle if hasattr(flow, 'bidirectional_max_idle') else 0) * 1000.0,
        # 22: Idle Mean (ms → µs)
        (flow.bidirectional_mean_idle if hasattr(flow, 'bidirectional_mean_idle') else 0) * 1000.0,
        # 23: Idle Min (ms → µs)
        (flow.bidirectional_min_idle if hasattr(flow, 'bidirectional_min_idle') else 0) * 1000.0,
        # 24: Init_Win_bytes_backward
        getattr(flow.udps, 'init_win_bwd', 0),
        # 25: Init_Win_bytes_forward
        getattr(flow.udps, 'init_win_fwd', 0),
        # 26: Packet Length Mean
        flow.bidirectional_mean_ps,
        # 27: Packet Length Std
        flow.bidirectional_stddev_ps,
        # 28: Total Length of Bwd Packets
        flow.dst2src_bytes,
        # 29: Total Length of Fwd Packets
        flow.src2dst_bytes,
    ], dtype=np.float64)

    return features


# Feature names matching training order (A-Z sorted)
FEATURE_NAMES = [
    'ACK Flag Count',
    'Average Packet Size',
    'Avg Bwd Segment Size',
    'Bwd IAT Min', 'Bwd IAT Std', 'Bwd IAT Total',
    'Bwd Packet Length Mean',
    'Destination Port',
    'Flow Bytes/s', 'Flow Duration', 'Flow IAT Max', 'Flow IAT Std',
    'Flow Packets/s',
    'Fwd Header Length',
    'Fwd IAT Max', 'Fwd IAT Mean', 'Fwd IAT Min', 'Fwd IAT Std', 'Fwd IAT Total',
    'Fwd Packet Length Max',
    'Fwd Packets/s',
    'Idle Max', 'Idle Mean', 'Idle Min',
    'Init_Win_bytes_backward', 'Init_Win_bytes_forward',
    'Packet Length Mean', 'Packet Length Std',
    'Total Length of Bwd Packets', 'Total Length of Fwd Packets',
]
