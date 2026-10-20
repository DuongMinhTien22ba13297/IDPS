"""
=============================================================================
Tên file   : extract_50_features.py
Mục tiêu   : Trích xuất tập đặc trưng lớn (~57 features) của CIC-IDS-2017
             từ file PCAP thô sử dụng thư viện NFStream.
             Được thiết kế để anh sử dụng cho nghiên cứu/huấn luyện mô hình mới.
Input      : 
  - datasets/pcap/*.pcap : Các file bắt gói tin thô.
Output     :
  - datasets/nfs_csv/*_57features.csv : Các file chứa 57 đặc trưng + metadata.
=============================================================================
"""

import os
import gc
import sys
import glob
import time
import struct
import pandas as pd
import numpy as np
from nfstream import NFStreamer, NFPlugin

# Đảm bảo in ra terminal đúng định dạng UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Cấu hình đường dẫn
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_DIR = os.path.join(PROJECT_ROOT, 'datasets', 'pcap')
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'datasets', 'nfs_csv')

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ------------------------------------------------------------------
# CUSTOM NFSTREAM PLUGINS
# ------------------------------------------------------------------

class CustomFeaturePlugin(NFPlugin):
    """
    Plugin tùy chỉnh để trích xuất các đặc trưng nâng cao mà NFStream mặc định không hỗ trợ:
    1. Kích thước cửa sổ TCP ban đầu (Init_Win_bytes_forward / Init_Win_bytes_backward)
    2. Chiều dài Header (Fwd/Bwd Header Length)
    3. Số gói tin có chứa dữ liệu thực tế ở hướng đi (act_data_pkt_fwd)
    """
    def on_init(self, packet, flow):
        # Khởi tạo các giá trị cho flow
        flow.udps.init_win_fwd = 0
        flow.udps.init_win_bwd = 0
        flow.udps.fwd_header_len = 0
        flow.udps.bwd_header_len = 0
        flow.udps.act_data_pkt_fwd = 0
        
        # Cập nhật cho gói tin đầu tiên
        self.update_stats(packet, flow)

    def on_update(self, packet, flow):
        self.update_stats(packet, flow)

    def update_stats(self, packet, flow):
        # 1. Tính toán Header Length (IP Header + Transport Header)
        # ip_size chứa kích thước IP header + Transport header + Payload
        # payload_size chứa kích thước Payload thực tế
        header_len = packet.ip_size - packet.payload_size
        if packet.direction == 0:
            flow.udps.fwd_header_len += header_len
            # 2. Đếm số gói tin có chứa dữ liệu (payload_size > 0)
            if packet.payload_size > 0:
                flow.udps.act_data_pkt_fwd += 1
        else:
            flow.udps.bwd_header_len += header_len

        # 3. Trích xuất TCP Window Size từ TCP Header (nếu là giao thức TCP)
        if packet.protocol == 6:
            # Chỉ lấy giá trị của gói tin TCP đầu tiên có Window Size ở mỗi hướng
            if packet.direction == 0 and flow.udps.init_win_fwd == 0:
                self.extract_tcp_window(packet, flow, direction=0)
            elif packet.direction == 1 and flow.udps.init_win_bwd == 0:
                self.extract_tcp_window(packet, flow, direction=1)

    def extract_tcp_window(self, packet, flow, direction):
        try:
            ip_packet = packet.ip_packet
            if packet.ip_version == 4:
                ip_header_len = (ip_packet[0] & 0x0F) * 4
            elif packet.ip_version == 6:
                ip_header_len = 40
            else:
                return
            
            # TCP Window Size nằm ở byte thứ 14 và 15 của TCP Header
            if len(ip_packet) >= ip_header_len + 16:
                win_size = struct.unpack('!H', ip_packet[ip_header_len + 14 : ip_header_len + 16])[0]
                if direction == 0:
                    flow.udps.init_win_fwd = win_size
                else:
                    flow.udps.init_win_bwd = win_size
        except Exception:
            pass

# ------------------------------------------------------------------
# DANH SÁCH 57 ĐẶC TRƯNG MAPPED TỪ NFSTREAM
# ------------------------------------------------------------------

FEATURE_NAMES = [
    # Metadata identifiers
    'Destination Port',
    
    # Flow Basic metrics
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    
    # Packet Length stats (Fwd/Bwd)
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    
    # Flow rates
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packets/s',
    'Bwd Packets/s',
    
    # Flow IAT
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    
    # Fwd IAT
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    
    # Bwd IAT
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    
    # Packet Length Overall stats
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'Average Packet Size',
    
    # Segment sizes
    'Avg Fwd Segment Size',
    'Avg Bwd Segment Size',
    
    # Down/Up Ratio
    'Down/Up Ratio',
    
    # TCP Flags Counts
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'ECE Flag Count',
    'CWE Flag Count',
    'Fwd PSH Flags',
    'Bwd PSH Flags',
    'Fwd URG Flags',
    'Bwd URG Flags',
    
    # Header Lengths (Plugin)
    'Fwd Header Length',
    'Bwd Header Length',
    
    # TCP Window Size (Plugin)
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    
    # Active Data Packets (Plugin)
    'act_data_pkt_fwd'
]

def extract_57_features(flow) -> np.ndarray:
    duration_us = flow.bidirectional_duration_ms * 1000.0  # µs
    duration_us_safe = max(duration_us, 1.0)
    duration_s_safe = max(flow.bidirectional_duration_ms / 1000.0, 0.001)
    
    # Biến tính toán thêm
    min_pkt_len = min(flow.src2dst_min_ps, flow.dst2src_min_ps)
    max_pkt_len = max(flow.src2dst_max_ps, flow.dst2src_max_ps)
    pkt_len_var = flow.bidirectional_stddev_ps ** 2
    avg_pkt_size = flow.bidirectional_bytes / flow.bidirectional_packets if flow.bidirectional_packets > 0 else 0.0
    down_up_ratio = flow.dst2src_packets / flow.src2dst_packets if flow.src2dst_packets > 0 else 0.0
    
    features = np.array([
        # 1. Destination Port
        flow.dst_port,
        
        # 2. Flow Duration (µs)
        duration_us,
        # 3. Total Fwd Packets
        flow.src2dst_packets,
        # 4. Total Backward Packets
        flow.dst2src_packets,
        # 5. Total Length of Fwd Packets
        flow.src2dst_bytes,
        # 6. Total Length of Bwd Packets
        flow.dst2src_bytes,
        
        # 7-10. Fwd Packet Length stats
        flow.src2dst_max_ps,
        flow.src2dst_min_ps,
        flow.src2dst_mean_ps,
        flow.src2dst_stddev_ps,
        
        # 11-14. Bwd Packet Length stats
        flow.dst2src_max_ps,
        flow.dst2src_min_ps,
        flow.dst2src_mean_ps,
        flow.dst2src_stddev_ps,
        
        # 15. Flow Bytes/s
        flow.bidirectional_bytes / duration_s_safe,
        # 16. Flow Packets/s
        flow.bidirectional_packets / duration_s_safe,
        # 17. Fwd Packets/s
        flow.src2dst_packets / duration_s_safe,
        # 18. Bwd Packets/s
        flow.dst2src_packets / duration_s_safe,
        
        # 19-22. Flow IAT (ms -> µs)
        flow.bidirectional_mean_piat_ms * 1000.0,
        flow.bidirectional_stddev_piat_ms * 1000.0,
        flow.bidirectional_max_piat_ms * 1000.0,
        flow.bidirectional_min_piat_ms * 1000.0,
        
        # 23-27. Fwd IAT (ms -> µs)
        flow.src2dst_duration_ms * 1000.0,
        flow.src2dst_mean_piat_ms * 1000.0,
        flow.src2dst_stddev_piat_ms * 1000.0,
        flow.src2dst_max_piat_ms * 1000.0,
        flow.src2dst_min_piat_ms * 1000.0,
        
        # 28-32. Bwd IAT (ms -> µs)
        flow.dst2src_duration_ms * 1000.0,
        flow.dst2src_mean_piat_ms * 1000.0,
        flow.dst2src_stddev_piat_ms * 1000.0,
        flow.dst2src_max_piat_ms * 1000.0,
        flow.dst2src_min_piat_ms * 1000.0,
        
        # 33-38. Packet Length Overall stats
        min_pkt_len,
        max_pkt_len,
        flow.bidirectional_mean_ps,
        flow.bidirectional_stddev_ps,
        pkt_len_var,
        avg_pkt_size,
        
        # 39. Avg Fwd Segment Size
        flow.src2dst_mean_ps,
        # 40. Avg Bwd Segment Size
        flow.dst2src_mean_ps,
        
        # 41. Down/Up Ratio
        down_up_ratio,
        
        # 42-49. TCP Flags Counts (Bidi)
        flow.bidirectional_fin_packets,
        flow.bidirectional_syn_packets,
        flow.bidirectional_rst_packets,
        flow.bidirectional_psh_packets,
        flow.bidirectional_ack_packets,
        flow.bidirectional_urg_packets,
        flow.bidirectional_ece_packets,
        flow.bidirectional_cwr_packets,  # Map to CWE Flag Count
        
        # 50-53. Directional TCP Flags
        flow.src2dst_psh_packets,         # Fwd PSH Flags
        flow.dst2src_psh_packets,         # Bwd PSH Flags
        flow.src2dst_urg_packets,         # Fwd URG Flags
        flow.dst2src_urg_packets,         # Bwd URG Flags
        
        # 54-55. Header Length (Plugin)
        getattr(flow.udps, 'fwd_header_len', 0),
        getattr(flow.udps, 'bwd_header_len', 0),
        
        # 56-57. TCP Window Size (Plugin)
        getattr(flow.udps, 'init_win_fwd', 0),
        getattr(flow.udps, 'init_win_bwd', 0),
        
        # 58. Active data packets forward (Plugin)
        getattr(flow.udps, 'act_data_pkt_fwd', 0)
    ], dtype=np.float64)
    
    return features

# Các cột metadata dùng để gán nhãn
METADATA_COLS = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms'
]

ALL_COLS = METADATA_COLS + FEATURE_NAMES

def process_pcap(pcap_file: str, output_csv: str):
    print(f"\n[{time.strftime('%H:%M:%S')}] Đang xử lý file: {os.path.basename(pcap_file)}")
    
    # Khởi tạo NFStreamer với plugin CustomFeaturePlugin
    streamer = NFStreamer(
        source=pcap_file,
        statistical_analysis=True,
        accounting_mode=0,
        udps=[CustomFeaturePlugin()],
        idle_timeout=10,
        active_timeout=30,
    )
    
    chunk_size = 100000
    rows = []
    total_flows = 0
    
    for flow in streamer:
        # Lấy metadata
        metadata = [
            flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol,
            flow.bidirectional_first_seen_ms, flow.bidirectional_last_seen_ms
        ]
        
        # Trích xuất 57 đặc trưng
        features_array = extract_57_features(flow).tolist()
        
        rows.append(metadata + features_array)
        total_flows += 1
        
        if len(rows) >= chunk_size:
            df = pd.DataFrame(rows, columns=ALL_COLS)
            mode = 'a' if os.path.exists(output_csv) else 'w'
            header = not os.path.exists(output_csv)
            df.to_csv(output_csv, mode=mode, header=header, index=False)
            
            print(f"  → Đã ghi {total_flows:,} flows...")
            rows = []
            del df
            gc.collect()
            
    if len(rows) > 0:
        df = pd.DataFrame(rows, columns=ALL_COLS)
        mode = 'a' if os.path.exists(output_csv) else 'w'
        header = not os.path.exists(output_csv)
        df.to_csv(output_csv, mode=mode, header=header, index=False)
        del df
        gc.collect()

    print(f"[{time.strftime('%H:%M:%S')}] Hoàn tất file {os.path.basename(pcap_file)}! Tổng cộng: {total_flows:,} flows.")

def main():
    print("=" * 70)
    print(" BẮT ĐẦU TRÍCH XUẤT 57 ĐẶC TRƯNG CIC-IDS-2017 BẰNG NFSTREAM ")
    print("=" * 70)
    
    pcap_files = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
    if not pcap_files:
        print(f"[-] Không tìm thấy file PCAP nào trong {PCAP_DIR}")
        return
        
    for pcap_file in pcap_files:
        base_name = os.path.basename(pcap_file).split('.')[0]
        output_csv = os.path.join(OUTPUT_DIR, f"{base_name}_57features.csv")
        
        if os.path.exists(output_csv):
            print(f"[!] File {output_csv} đã tồn tại, tiến hành xóa và ghi đè...")
            os.remove(output_csv)
            
        process_pcap(pcap_file, output_csv)
        
    print("\n" + "=" * 70)
    print(" HOÀN TẤT! Dữ liệu được lưu tại: datasets/nfs_csv/")
    print("=" * 70)

if __name__ == "__main__":
    main()
