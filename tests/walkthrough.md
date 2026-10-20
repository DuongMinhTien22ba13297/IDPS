# Walkthrough: IDPS Robust Test Suite

## Tổng Quan

Đã tạo bộ test suite hoàn chỉnh trong thư mục `tests/` với **15 files**, cho phép test hệ thống IDPS như một dự án thực tế.

## Cấu Trúc Thư Mục

```
c:\IDPS\tests\
├── idps_test_suite.sh              ← Master script (chạy trên Kali)
├── scenarios/
│   ├── 01_portscan.sh              ← 7 lệnh nmap, 3 phases
│   ├── 02_bruteforce.sh            ← hydra/medusa/ncrack, 3 phases
│   ├── 03_dos.sh                   ← SYN/UDP/Slowloris/HTTP flood, 4 phases
│   ├── 04_web_attack.sh            ← 60+ payloads (SQLi/XSS/Traversal), 5 phases
│   ├── 05_botnet.sh                ← C&C beacon + exfil + probe
│   └── 06_evasion.sh               ← Fragment/Decoy/Slow/Random, 4 techniques
├── tools/
│   ├── botnet_sim.py               ← Python C&C simulator
│   ├── slowloris_fallback.py       ← Fallback khi không có slowhttptest
│   └── syn_flood_fallback.py       ← Fallback khi không có hping3
├── wordlists/
│   └── simple_passwords.txt        ← 20 passwords
├── collect_metrics.py              ← Parser log → 4 bảng Markdown cho báo cáo
├── reset_environment.sh            ← Flush iptables + clear blacklist
└── inject_benign.sh                ← 125 flows bình thường cho FPR test
```

## Thay Đổi Source Code

### [autodefense_daemon.py](file:///c:/IDPS/src/autodefense_daemon.py)
- Thêm biến `SURICATA_ONLY_MODE` (env var)
- Khi `true`: Skip ML inference, chỉ dùng Suricata alerts
- Mục đích: So sánh A/B (Suricata-only ~50% DR vs Full System ~100% DR)

## Cách Sử Dụng

### Cấu hình IP Mạng:
* **Mạng nội bộ để test tấn công:** `172.16.1.x` (Kali Linux: `172.16.1.10`, IDPS Server: `172.16.1.2`)
* **Mạng giao tiếp với máy thật (để chuyển file / SSH):** `192.168.226.x` (Kali Linux: `192.168.226.136`, IDPS Server: `192.168.226.151`)

### Bước 1: Copy test suite lên máy Kali và Server
Chạy các lệnh sau trên máy thật (Windows) để chuyển dữ liệu sang Kali:
```bash
# Khởi tạo thư mục đích trên Kali
ssh kali@192.168.226.136 "mkdir -p /home/kali/idps_tests"

# Sao chép toàn bộ test suite từ máy Windows lên Kali
scp -r C:\IDPS\tests\* kali@192.168.226.136:/home/kali/idps_tests/
```

Đồng thời sao chép các file quản trị cần thiết sang IDPS Server:
```bash
scp C:\IDPS\tests\collect_metrics.py C:\IDPS\tests\reset_environment.sh dmtien@192.168.226.151:/home/dmtien/
```

### Bước 2: Chạy test suite trên máy Kali
Truy cập vào máy Kali Linux để chạy bộ test:
```bash
# SSH vào máy Kali
ssh kali@192.168.226.136

# Di chuyển vào thư mục và cấp quyền thực thi cho các scripts
cd /home/kali/idps_tests
chmod +x idps_test_suite.sh scenarios/*.sh

# Chạy bộ test suite điều phối (tấn công sẽ nhắm trực tiếp vào victim IP 172.16.1.2)
sudo ./idps_test_suite.sh
```

### Bước 3: Thu thập số liệu trên IDPS Server
Sau khi quá trình test kết thúc, truy cập vào IDPS Server để phân tích log và trích xuất bảng số liệu:
```bash
# SSH vào IDPS Server
ssh dmtien@192.168.226.151

# Chạy script parser để xuất kết quả báo cáo
python3 /home/dmtien/collect_metrics.py \
    --audit /app/logs/action_audit.log \
    --log /app/logs/autodefense.log \
    --output /home/dmtien/test_report.md
```

### Bước 4 (Tùy chọn): Test Suricata-Only Mode (A/B Testing)
Để đo đạc hiệu quả của cơ chế kết hợp ML so với chỉ dùng Suricata thuần túy:
```bash
# SSH vào IDPS Server và dừng container chứa daemon autodefense
ssh dmtien@192.168.226.151
docker stop autodefense

# Khởi chạy lại container với tham số môi trường SURICATA_ONLY_MODE=true
docker run -d --name autodefense -e SURICATA_ONLY_MODE=true ... autodefense

# SSH vào Kali và chạy lại bộ test
ssh kali@192.168.226.136
cd /home/kali/idps_tests
sudo ./idps_test_suite.sh

# Chạy lại collect_metrics.py trên IDPS Server để so sánh kết quả
```

## Đặc Điểm Thiết Kế

1. **Fallback tự động**: Mỗi scenario kiểm tra tool trước khi chạy, fallback sang Python nếu thiếu
2. **Multi-tool per scenario**: Không chỉ 1 command/loại tấn công — mỗi scenario dùng 3-8 lệnh khác nhau
3. **Reset tự động**: SSH vào server reset iptables + blacklist giữa mỗi scenario
4. **Marker timestamps**: Ghi thời điểm bắt đầu/kết thúc mỗi scenario → `collect_metrics.py` parse chính xác
5. **Benign injection**: Tạo 125 flows bình thường xen kẽ attacks → đo False Positive Rate
6. **4 bảng số liệu**: Markdown format, copy-paste trực tiếp vào báo cáo đồ án
