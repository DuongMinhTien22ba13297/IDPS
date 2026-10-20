"""
=============================================================================
Tên file   : label_flows_50.py
Mục tiêu   : Gán nhãn tấn công cho tập dữ liệu 58 đặc trưng (57 features + Metadata)
             đã được trích xuất từ PCAP bằng nfstream.
Input      :
  - datasets/nfs_csv/*_57features.csv : Các file đặc trưng 58 chiều chưa gán nhãn.
Output     :
  - datasets/cic2017_nfs_labeled_57features.csv : File tổng hợp đã được gán nhãn đầy đủ.
=============================================================================
"""

import os
import sys
import glob
import time
import datetime
import pandas as pd

# Đảm bảo in ra terminal đúng định dạng UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Cấu hình thư mục
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_DIR = os.path.join(PROJECT_ROOT, 'datasets', 'nfs_csv')
OUTPUT_FILE = os.path.join(PROJECT_ROOT, 'datasets', 'cic2017_nfs_labeled_57features.csv')

# Múi giờ lệch (Timezone Offset). CIC-IDS-2017 capture ở ADT (UTC-3).
TIMEZONE_OFFSET_HOURS = -3

# Hàm hỗ trợ kiểm tra thời gian
def is_in_time(t: datetime.time, start: tuple, end: tuple):
    start_t = datetime.time(*start)
    end_t = datetime.time(*end)
    return start_t <= t <= end_t

# Luật gán nhãn chi tiết cho từng ngày (Theo lịch trình chuẩn CIC-IDS-2017)
def label_tuesday(row, t):
    src, dst = row['src_ip'], row['dst_ip']
    if src == '172.16.0.1' and dst == '192.168.10.50':
        if is_in_time(t, (9, 20), (10, 20)): return 'FTP-Patator'
        if is_in_time(t, (14, 0), (15, 0)): return 'SSH-Patator'
    return 'BENIGN'

def label_wednesday(row, t):
    src, dst = row['src_ip'], row['dst_ip']
    if src == '172.16.0.1' and dst == '192.168.10.50':
        if is_in_time(t, (9, 47), (10, 10)): return 'DoS slowloris'
        if is_in_time(t, (10, 14), (10, 35)): return 'DoS Slowhttptest'
        if is_in_time(t, (10, 43), (11, 0)): return 'DoS Hulk'
        if is_in_time(t, (11, 10), (11, 23)): return 'DoS GoldenEye'
    
    # Heartbleed
    if (src == '172.16.0.11' or src == '172.16.0.1') and dst == '192.168.10.51':
        if is_in_time(t, (15, 12), (15, 32)): return 'Heartbleed'
    return 'BENIGN'

def label_thursday(row, t):
    src, dst = row['src_ip'], row['dst_ip']
    if src == '172.16.0.1' and dst == '192.168.10.50':
        if is_in_time(t, (9, 20), (10, 0)): return 'Web Attack – Brute Force'
        if is_in_time(t, (10, 15), (10, 35)): return 'Web Attack – XSS'
        if is_in_time(t, (10, 40), (10, 42)): return 'Web Attack – Sql Injection'
    
    kali_ips = ['205.174.165.73', '172.16.0.1']
    # Infiltration Win Vista
    if (src in kali_ips and dst == '192.168.10.8') or (dst in kali_ips and src == '192.168.10.8'):
        if is_in_time(t, (14, 19), (14, 21)) or is_in_time(t, (14, 33), (14, 35)): return 'Infiltration'
        if is_in_time(t, (15, 4), (15, 45)): return 'Infiltration'
    
    # Infiltration MAC
    if (src in kali_ips and dst == '192.168.10.25') or (dst in kali_ips and src == '192.168.10.25'):
        if is_in_time(t, (14, 53), (15, 0)): return 'Infiltration'
        
    return 'BENIGN'

def label_friday(row, t):
    src, dst = row['src_ip'], row['dst_ip']
    # Botnet ARES
    botnet_victims = ['192.168.10.15', '192.168.10.9', '192.168.10.14', '192.168.10.5', '192.168.10.8']
    kali_ips = ['205.174.165.73', '172.16.0.1']
    if (src in kali_ips and dst in botnet_victims) or (dst in kali_ips and src in botnet_victims):
        if is_in_time(t, (10, 2), (11, 2)): return 'Botnet'
        
    # PortScan
    if src == '172.16.0.1' and dst == '192.168.10.50':
        if is_in_time(t, (13, 55), (14, 35)) or is_in_time(t, (14, 51), (15, 29)): return 'PortScan'
        
    # DDoS LOIT
    if src == '172.16.0.1' and dst == '192.168.10.50':
        if is_in_time(t, (15, 56), (16, 16)): return 'DDoS'
        
    return 'BENIGN'

def get_label(row, day_name):
    # Lấy trường thời gian đầu của flow
    ms = row['bidirectional_first_seen_ms']
    dt_utc = datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc)
    dt_local = dt_utc + datetime.timedelta(hours=TIMEZONE_OFFSET_HOURS)
    t = dt_local.time()
    
    # Kiểm tra khớp ngày
    if 'Monday' in day_name:
        return 'BENIGN'
    elif 'Tuesday' in day_name:
        return label_tuesday(row, t)
    elif 'Wednesday' in day_name:
        return label_wednesday(row, t)
    elif 'Thursday' in day_name:
        return label_thursday(row, t)
    elif 'Friday' in day_name:
        return label_friday(row, t)
    return 'BENIGN'

def main():
    print("=" * 70)
    print(f" GÁN NHÃN CHO TẬP DỮ LIỆU 58 FEATURES (Offset: {TIMEZONE_OFFSET_HOURS}h) ")
    print("=" * 70)
    
    # Tìm kiếm các file 57features.csv
    csv_files = sorted(glob.glob(os.path.join(INPUT_DIR, "*_57features.csv")))
    if not csv_files:
        print(f"[-] Không tìm thấy file CSV chứa 57features nào trong {INPUT_DIR}!")
        return
        
    if os.path.exists(OUTPUT_FILE):
        print(f"[!] File output {OUTPUT_FILE} đã tồn tại, tiến hành xóa để ghi mới...")
        os.remove(OUTPUT_FILE)
        
    chunk_size = 200000
    first_write = True
    
    for csv_file in csv_files:
        file_name = os.path.basename(csv_file)
        print(f"\n[{time.strftime('%H:%M:%S')}] Đang gán nhãn cho file: {file_name}...")
        
        # Đọc theo từng chunk để tối ưu RAM
        chunk_iter = pd.read_csv(csv_file, chunksize=chunk_size)
        for chunk in chunk_iter:
            # Gán nhãn cho từng dòng
            chunk['Label'] = chunk.apply(lambda row: get_label(row, file_name), axis=1)
            
            # Ghi nối vào file kết quả chung
            mode = 'w' if first_write else 'a'
            chunk.to_csv(OUTPUT_FILE, mode=mode, header=first_write, index=False)
            first_write = False
            
            # Thống kê nhãn trong chunk vừa xử lý
            label_counts = chunk['Label'].value_counts()
            attack_counts = label_counts[label_counts.index != 'BENIGN'].sum()
            if attack_counts > 0:
                print(f"  → Phát hiện {attack_counts:,} cuộc tấn công trong chunk này. Chi tiết: {dict(label_counts[label_counts.index != 'BENIGN'])}")
                
    print("\n" + "=" * 70)
    print(f" HOÀN TẤT GÁN NHÃN! File đích: {OUTPUT_FILE}")
    print("=" * 70)

if __name__ == "__main__":
    main()
