# Kế Hoạch Test Hệ Thống IDPS — Automation Script Suite

## Bối Cảnh

| Thông tin | Giá trị |
|---|---|
| IP Attacker (Kali) | `172.16.1.10` |
| IP Server (Victim) | `172.16.1.2` |
| Interface capture | `ens33` |
| Juice Shop | ✅ Port 3001 (qua Nginx 80/443) |
| Network | `172.16.1.0/24` (cùng subnet) |
| Tools có sẵn | `nmap`, `hydra`, `curl`, `python3` |
| Tools có thể thiếu | `hping3`, `nikto`, `sqlmap`, `slowhttptest`, `gobuster`, `medusa` |

**Mục tiêu**: Tạo bộ automation script chạy trên Kali, thu thập số liệu realtime cho báo cáo đồ án. Script phải **linh hoạt** — kiểm tra tool trước khi dùng, skip nếu thiếu, ưu tiên tool có sẵn.

---

## Proposed Changes

### Component 1: Test Scripts (chạy trên Kali 172.16.1.10)

#### [NEW] `tests/idps_test_suite.sh`
Master script điều phối toàn bộ test flow:
1. **Pre-flight check**: Kiểm tra từng tool có sẵn không
2. **Cài đặt thiếu**: Tự động cài các tool thiếu bằng `apt install` (hỏi user trước)
3. **6 kịch bản tuần tự**: Mỗi kịch bản gọi sub-script riêng
4. **Reset giữa kịch bản**: SSH vào server chạy reset
5. **Ghi marker timestamp** vào log để `collect_metrics.py` parse

#### [NEW] `tests/scenarios/01_portscan.sh`
PortScan multi-phase (5 lệnh nmap, 3 phase):
- Stealth (T1, NULL scan) → Aggressive (T4, full port) → Service Enum (NSE scripts)
- Chỉ dùng `nmap` (đã có sẵn)

#### [NEW] `tests/scenarios/02_bruteforce.sh`
SSH Brute Force multi-tool (hydra + ncrack/medusa nếu có):
- Password Spray → Dictionary → Parallel Attack
- Fallback: nếu chỉ có hydra, chạy 3 lần hydra với config khác nhau
- Kèm wordlist nhỏ (`tests/wordlists/simple_passwords.txt`)

#### [NEW] `tests/scenarios/03_dos.sh`
DoS Multi-Vector:
- Tool chính: `hping3` (nếu có), fallback: `python3 + scapy` cho SYN flood
- `slowhttptest` (nếu có), fallback: `python3` script slowloris tự viết
- `curl` batch (HTTP flood đơn giản, luôn hoạt động)

#### [NEW] `tests/scenarios/04_web_attack.sh`
Web Attack nhắm vào Juice Shop (https://172.16.1.2):
- SQLi: `sqlmap` nếu có, fallback: 10+ curl payloads thủ công
- XSS: curl payloads
- Path traversal: curl payloads
- Dir fuzzing: `gobuster` nếu có, fallback: curl + wordlist
- **Luôn hoạt động** vì curl có sẵn

#### [NEW] `tests/scenarios/05_botnet.sh`
Wrapper chạy Python script `botnet_sim.py`:
- C&C beacon (20 cycles, 15-30s interval)
- Data exfiltration simulation
- **Chỉ cần python3** (có sẵn trên Kali)

#### [NEW] `tests/scenarios/06_evasion.sh`
Evasion techniques (chỉ cần `nmap`):
- Fragment scan, Decoy scan, Ultra-slow scan, Timing randomization

#### [NEW] `tests/botnet_sim.py`
Python script mô phỏng Botnet C&C beacon pattern.

#### [NEW] `tests/wordlists/simple_passwords.txt`
20 passwords phổ biến cho brute force test.

#### [NEW] `tests/slowloris_fallback.py`
Fallback Slowloris script (nếu không có `slowhttptest`). Dùng Python thuần.

---

### Component 2: Metric Collection (chạy trên Server 172.16.1.2)

#### [NEW] `tests/collect_metrics.py`
Script Python parse log và xuất bảng số liệu:
- Input: `action_audit.log`, `autodefense.log`
- Output: JSON + bảng Markdown (copy-paste vào báo cáo)
- Tính: Detection Rate, Response Time (min/avg/max/p95), FP Rate, Correlation Impact

#### [NEW] `tests/reset_environment.sh`
Script reset nhanh giữa các kịch bản:
```bash
iptables -F INPUT && iptables -A INPUT -j ACCEPT
echo '{"description":"IP Blacklist","ips":[]}' > /app/configs/blacklist.json
```

#### [NEW] `tests/inject_benign.sh`
Tạo traffic benign (curl/wget trang web bình thường) để đo FP rate.

---

### Component 3: Toggle Suricata-Only Mode

#### [MODIFY] [autodefense_daemon.py](file:///c:/IDPS/src/autodefense_daemon.py)
Thêm biến môi trường `SURICATA_ONLY_MODE`:
- `true`: Skip ML inference, chỉ log Suricata alerts → dùng để so sánh
- `false` (default): Pipeline đầy đủ

---

## Verification Plan

### Automated Tests
```bash
# Trên Kali (172.16.1.10):
cd tests && chmod +x idps_test_suite.sh
./idps_test_suite.sh

# Trên Server (172.16.1.2):
python3 tests/collect_metrics.py --log /app/logs/action_audit.log
```

### Manual Verification
- Kiểm tra `action_audit.log` có ghi đúng events
- Kiểm tra Grafana dashboard hiển thị đúng
- Kiểm tra `iptables -L INPUT -n` có rules DROP cho 172.16.1.10
