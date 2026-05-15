"""
=============================================================================
Tên file   : realtime_extractor.py
Mục tiêu   : Trích xuất đặc trưng mạng thời gian thực từ traffic sống hoặc file PCAP.
             Chuyển đổi dữ liệu thô từ NFStream sang định dạng 30 đặc trưng tương thích 
             với mô hình huấn luyện trên bộ dữ liệu CIC-IDS-2017.
Input      :
  - interface : Tên card mạng để lắng nghe (mặc định: ens33).
  - flow      : Luồng mạng (flow object) được cung cấp bởi NFStreamer.
Output     :
  - np.ndarray : Vector chứa 30 đặc trưng đã được chuẩn hóa đơn vị (ms sang µs).
Quy trình  :
  1. Cấu hình Plugins: Sử dụng TCPWindowPlugin để lấy Init_Win_bytes 
     (đặc trưng nâng cao mà NFStream mặc định không có).
  2. Create Streamer: Khởi tạo bộ bắt gói tin với các tham số timeout (idle, active).
  3. Mapping: Chuyển đổi các thuộc tính của flow (số gói tin, độ dài, thời gian IAT, 
     cờ TCP...) thành vector 30 chiều theo đúng thứ tự A-Z đã dùng khi huấn luyện.
Ngày tạo   : 2026-05-01
Ngày sửa   : 2026-05-09
Lí do sửa  : Thay thế 7 features không đóng góp (Idle Max/Mean/Min, Bwd IAT Std,
             Bwd Mean Segment Size, Fwd Mean IAT, Fwd IAT Min) bằng 7 features
             mới giúp phân biệt Web Attack, Brute Force, PortScan tốt hơn:
             SYN/FIN/RST/PSH Flag Count, Total Fwd/Bwd Packets, Fwd Packet Length Min.
             Xóa IdleStatsPlugin (không cần nữa).
=============================================================================
"""
from nfstream import NFStreamer, NFPlugin
import numpy as np
import time

class ConnectionTracker:
    def __init__(self, window_sec=10):
        self.window_sec = window_sec
        # dict: src_ip -> {dst_port: [timestamp1, timestamp2, ...]}
        self.history = {}

    def add_and_count(self, src_ip, dst_port, current_time_sec):
        if src_ip not in self.history:
            self.history[src_ip] = {}
        if dst_port not in self.history[src_ip]:
            self.history[src_ip][dst_port] = []
            
        timestamps = self.history[src_ip][dst_port]
        timestamps.append(current_time_sec)
        
        # Lọc các timestamp cũ hơn window_sec
        cutoff = current_time_sec - self.window_sec
        valid_timestamps = [ts for ts in timestamps if ts > cutoff]
        self.history[src_ip][dst_port] = valid_timestamps
        
        return len(valid_timestamps)

class ConnectionRatePlugin(NFPlugin):
    def on_init(self, packet, flow):
        # packet.time is in milliseconds
        current_time_sec = packet.time / 1000.0
        flow.udps.conn_rate = self.tracker.add_and_count(flow.src_ip, flow.dst_port, current_time_sec)

# Custom plugin cho TCP Window Size (Init_Win_bytes_forward/backward)
class TCPWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.init_win_fwd = 0
        flow.udps.init_win_bwd = 0
        flow.udps.is_first_packet = True

    def on_update(self, packet, flow):
        if flow.udps.is_first_packet and packet.direction == 0:
            flow.udps.init_win_fwd = packet.ip_size  # Simplified
            flow.udps.is_first_packet = False
        if packet.direction == 1 and flow.udps.init_win_bwd == 0:
            flow.udps.init_win_bwd = packet.ip_size  # Simplified


def create_streamer(interface="ens33", conn_tracker=None):
    """Tạo NFStreamer để capture live traffic."""
    plugins = [TCPWindowPlugin()]
    if conn_tracker is not None:
        plugins.append(ConnectionRatePlugin(tracker=conn_tracker))

    return NFStreamer(
        source=interface,
        statistical_analysis=True,  # Bật 48 statistical features
        accounting_mode=0,          # Link layer
        udps=plugins,               # Danh sách plugins
        idle_timeout=10,
        active_timeout=30,
    )


def extract_features(flow) -> np.ndarray:
    """Map NFStream flow → 30-feature vector theo thứ tự A-Z (khớp với training CIC-IDS-2017).

    LƯU Ý QUAN TRỌNG:
      - CIC-IDS-2017 dùng MICROSECONDS (µs) cho tất cả trường thời gian.
      - NFStream trả về MILLISECONDS (ms) → cần nhân ×1000 để chuyển sang µs.
      - Flow Bytes/s và Flow Packets/s trong CIC dùng duration µs làm mẫu số.

    THAY ĐỔI V2 (2026-05-09):
      - Bỏ 7 features yếu: Idle Max/Mean/Min, Bwd IAT Std, Bwd Mean Segment Size,
        Fwd Mean IAT, Fwd IAT Min.
      - Thêm 7 features mới: SYN/FIN/RST/PSH Flag Count, Total Fwd/Bwd Packets,
        Fwd Packet Length Min.
      - Mục đích: Nâng cao khả năng phát hiện Web Attack (SQL Injection, XSS)
        và phân biệt Brute Force ↔ PortScan.
    """
    # NFStream ms → CIC-IDS-2017 µs (×1000)
    duration_us = flow.bidirectional_duration_ms * 1000.0  # µs
    duration_us_safe = max(duration_us, 1.0)  # tránh chia cho 0

    features = np.array([
        # 0: ACK Flag Count (native NFStream)
        flow.bidirectional_ack_packets,
        # 1: Average Packet Size
        flow.bidirectional_mean_ps,
        # 2: Bwd IAT Min (ms → µs)
        flow.dst2src_min_piat_ms * 1000.0,
        # 3: Bwd IAT Total (ms → µs, approx)
        flow.dst2src_max_piat_ms * flow.dst2src_packets * 1000.0,
        # 4: Bwd Packet Length Max ← MỚI
        flow.dst2src_max_ps,
        # 5: Bwd Packet Length Mean
        flow.dst2src_mean_ps,
        # 6: Bwd Packet Length Min ← MỚI
        flow.dst2src_min_ps,
        # 7: Bwd Packet Length Std ← MỚI
        flow.dst2src_stddev_ps,
        # 8: Destination Port
        flow.dst_port,
        # 9: FIN Flag Count
        flow.bidirectional_fin_packets,
        # 10: Flow Bytes/s (bytes / duration_µs × 1e6 = bytes/s)
        flow.bidirectional_bytes / duration_us_safe * 1e6,
        # 11: Flow Duration (µs)
        duration_us,
        # 12: Flow IAT Max (ms → µs)
        flow.bidirectional_max_piat_ms * 1000.0,
        # 13: Flow IAT Std (ms → µs)
        flow.bidirectional_stddev_piat_ms * 1000.0,
        # 14: Flow Packets/s (packets / duration_µs × 1e6 = packets/s)
        flow.bidirectional_packets / duration_us_safe * 1e6,
        # 15: Fwd IAT Std (ms → µs)
        flow.src2dst_stddev_piat_ms * 1000.0,
        # 16: Fwd Packet Length Max
        flow.src2dst_max_ps,
        # 17: Fwd Packet Length Min
        flow.src2dst_min_ps,
        # 18: Fwd Packets/s (packets / duration_µs × 1e6 = packets/s)
        flow.src2dst_packets / duration_us_safe * 1e6,
        # 19: Init_Win_bytes_backward
        getattr(flow.udps, 'init_win_bwd', 0),
        # 20: Init_Win_bytes_forward
        getattr(flow.udps, 'init_win_fwd', 0),
        # 21: PSH Flag Count
        flow.bidirectional_psh_packets,
        # 22: Port_Conn_Rate
        getattr(flow.udps, 'conn_rate', 1.0),
        # 23: Packet Length Std
        flow.bidirectional_stddev_ps,
        # 24: RST Flag Count
        flow.bidirectional_rst_packets,
        # 25: SYN Flag Count
        flow.bidirectional_syn_packets,
        # 26: Total Backward Packets
        flow.dst2src_packets,
        # 27: Total Fwd Packets
        flow.src2dst_packets,
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
    'Bwd IAT Min', 'Bwd IAT Total',
    'Bwd Packet Length Max',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Min',
    'Bwd Packet Length Std',
    'Destination Port',
    'FIN Flag Count',
    'Flow Bytes/s', 'Flow Duration', 'Flow IAT Max', 'Flow IAT Std',
    'Flow Packets/s',
    'Fwd IAT Std',
    'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Fwd Packets/s',
    'Init_Win_bytes_backward', 'Init_Win_bytes_forward',
    'PSH Flag Count',
    'Port_Conn_Rate', 'Packet Length Std',
    'RST Flag Count',
    'SYN Flag Count',
    'Total Backward Packets', 'Total Fwd Packets',
    'Total Length of Bwd Packets', 'Total Length of Fwd Packets',
]
