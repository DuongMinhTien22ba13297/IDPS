# Kế Hoạch Demo Hệ Thống IDPS Trước Hội Đồng

## Bối Cảnh & Mục Tiêu

Hệ thống cần được trình bày **như một sản phẩm nghiên cứu thực chiến**, không phải demo đồ chơi. Hội đồng đánh giá theo tiêu chuẩn của một IDPS thực tế — tức là hệ thống phải chứng minh được 3 điều:
1. **Phát hiện đúng** các tấn công thực tế, đa dạng, đa bước.
2. **Phản ứng tự động** (Zero-touch) đo được bằng số liệu ms.
3. **Chịu được evasion** — kẻ tấn công cố tình né tránh nhưng hệ thống vẫn bắt được.

---

> [!IMPORTANT]
> **Điểm Yếu Chết Người Nếu Chỉ Dùng 1 Lệnh/Loại Tấn Công:**
> Hội đồng sẽ hỏi ngay: *"Tấn công này Suricata/Snort cũng bắt được, ML của bạn thêm gì?"*
> Phải demo được các tình huống mà **Suricata một mình sẽ bỏ sót**, nhưng ML+Suricata phối hợp mới bắt được.

---

## Các Yếu Tố Cần Thảo Luận Thêm

> [!WARNING]
> **5 câu hỏi quan trọng cần anh trả lời trước khi tôi hoàn thiện plan:**

1. **Máy tấn công (Attacker)**: Anh dùng máy thật thứ 2, hay máy ảo Kali Linux trên cùng hypervisor? Hay replay PCAP từ dataset CIC-IDS-2017 gốc? → Ảnh hưởng đến thiết kế kịch bản.
2. **Mạng lab**: Máy IDPS (Ubuntu 192.168.226.151) được giám sát interface nào? Máy tấn công kết nối qua switch thật hay NAT VMware? → Ảnh hưởng đến `ens33` capture.
3. **Thời lượng demo**: Bao nhiêu phút? Hội đồng có cho phép anh reset blacklist giữa chừng không?
4. **Có màn hình Grafana chiếu song song không?** → Đây là điểm mạnh nhất của hệ thống, cần được khai thác triệt để.
5. **Evasion demo**: Anh có muốn demo cả kịch bản kẻ tấn công cố né tránh (slow scan, fragmented, low-rate) không? → Rất ấn tượng nhưng cần chuẩn bị thêm.

---

## Kiến Trúc Demo Được Đề Xuất

```
[Kali Linux / Attacker VM]
        |
        | (Mạng LAN ảo)
        |
[Ubuntu Server 192.168.226.151]  ← IDPS đang chạy
   ├── Suricata (L7 signature)
   ├── NFStream (flow extractor)
   ├── XGBoost (ML decision)
   ├── AutoFirewall (iptables)
   └── Grafana:3000  ← Chiếu lên màn hình hội đồng
```

---

## Kịch Bản Demo Thực Chiến (Attack Scenarios)

### Kịch Bản 1: PortScan Multi-Stage (Trinh Sát → Khai Thác)
**Mục đích**: Demo ML phát hiện pattern thống kê, không chỉ signature.

**Phase 1 — Slow Stealth Scan** (Suricata có thể bỏ qua):
```bash
# Kẻ tấn công dùng timing chậm để né IDS rule
nmap -sS -T1 --scan-delay 500ms -p 1-1000 192.168.226.151
```
*Quan sát*: Suricata alert count thấp hoặc 0. ML vẫn nhận ra pattern IAT bất thường.

**Phase 2 — Aggressive Scan** (Tăng tốc để demo tốc độ phản ứng):
```bash
nmap -sS -sV -O -A -T4 -p- 192.168.226.151
```
*Quan sát*: ML score tăng vọt → `AUTO_BLOCKED` xuất hiện trên Grafana trong < 100ms.

**Phase 3 — Service Fingerprinting**:
```bash
nmap -sV --version-intensity 9 -p 22,80,443,8080 192.168.226.151
nmap --script=banner 192.168.226.151
```

**Kết quả kỳ vọng**: Grafana hiển thị IP kẻ tấn công trong Blacklist, iptables DROP rule được tạo.

---

### Kịch Bản 2: SSH Brute Force (Credentialed + Uncredentialed)
**Mục đích**: Demo Brute Force detection + Suricata correlation boost.

**Phase 1 — Password Spray** (nhiều user, ít password):
```bash
hydra -L /usr/share/wordlists/metasploit/unix_users.txt \
      -p "password123" \
      ssh://192.168.226.151 \
      -t 4 -s 22 -V
```

**Phase 2 — Dictionary Attack** (1 user, nhiều password):
```bash
hydra -l root \
      -P /usr/share/wordlists/rockyou.txt \
      ssh://192.168.226.151 \
      -t 8 -s 22 -V -I
```

**Phase 3 — Medusa Parallel** (multi-threaded để tăng tốc):
```bash
medusa -h 192.168.226.151 -u admin -P /usr/share/wordlists/rockyou.txt \
       -M ssh -t 10 -n 22
```

**Narrative cho hội đồng**: 
- Suricata alert `ET SCAN SSH BruteForce` → correlation_boost += 0.15
- ML binary score > 0.85 → AUTO_BLOCK
- Grafana hiển thị `SUSPICIOUS → AUTO_BLOCKED` transition live

---

### Kịch Bản 3: DoS/DDoS Multi-Vector
**Mục đích**: Demo response time < 100ms và high-volume detection.

**Phase 1 — SYN Flood** (Layer 4):
```bash
# Cần hping3 hoặc scapy
hping3 -S --flood -V -p 80 192.168.226.151
# Hoặc với scapy:
python3 -c "
from scapy.all import *
send(IP(dst='192.168.226.151')/TCP(dport=80, flags='S'), count=10000, inter=0)
"
```

**Phase 2 — UDP Flood**:
```bash
hping3 --udp -p 53 --flood 192.168.226.151
```

**Phase 3 — HTTP Flood** (Application layer - Low-and-Slow):
```bash
# Slowloris - giữ kết nối lâu để exhaust server
slowhttptest -c 500 -H -g -o slowloris_test \
             -i 10 -r 200 -t GET \
             -u http://192.168.226.151 -x 24 -p 3
```

**Narrative**: Đây là lúc demo **sức mạnh của NFStream vs Suricata**:
- Suricata bắt được SYN flood (signature) nhưng không có flow statistics
- NFStream trích xuất: `Flow Packets/s`, `Flow Bytes/s`, `IAT Std` → XGBoost classify DoS/DDoS

---

### Kịch Bản 4: Web Attack (OWASP Top 10)
**Mục đích**: Demo multi-class classification chính xác đúng loại tấn công.

**Phase 1 — SQL Injection**:
```bash
# SQLMap automated
sqlmap -u "http://192.168.226.151/login.php?id=1" \
       --level=3 --risk=2 --batch \
       --technique=BEUSTQ \
       --dbms=mysql -v 3

# Manual payload để hội đồng thấy rõ
curl "http://192.168.226.151/?id=1' OR '1'='1' --"
curl "http://192.168.226.151/?id=1; DROP TABLE users; --"
```

**Phase 2 — XSS Attack**:
```bash
# Automated
nikto -h http://192.168.226.151 -Tuning x

# Manual XSS payloads
curl "http://192.168.226.151/search?q=<script>alert('XSS')</script>"
curl "http://192.168.226.151/search?q=<img src=x onerror=alert(1)>"
```

**Phase 3 — Directory Traversal + Fuzzing**:
```bash
gobuster dir -u http://192.168.226.151 \
             -w /usr/share/wordlists/dirb/common.txt \
             -t 50 -x php,html,txt

# Path traversal
curl "http://192.168.226.151/../../../../etc/passwd"
wfuzz -c -w /usr/share/wordlists/wfuzz/general/common.txt \
      http://192.168.226.151/FUZZ
```

**Narrative**: ML multi-class output trên Grafana hiển thị `Web Attack (confidence: 0.97)` — không chỉ là "attack" chung chung.

---

### Kịch Bản 5: Botnet C&C Simulation
**Mục đích**: Demo detection của traffic pattern bất thường, không có signature cụ thể.

```bash
# Simulate C&C beacon (periodic callback mỗi 30s)
python3 -c "
import socket, time, random
while True:
    try:
        s = socket.socket()
        s.connect(('192.168.226.151', 6667))  # IRC port
        s.send(b'NICK bot_' + str(random.randint(1000,9999)).encode())
        s.close()
    except: pass
    time.sleep(30 + random.randint(-5, 5))
"

# Ncrack để simulate brute force từ botnet
ncrack -U users.txt -P pass.txt 192.168.226.151:22,80,21
```

---

### Kịch Bản 6: Evasion Attempt (Kịch Bản Nâng Cao - Rất Ấn Tượng)
**Mục đích**: Chứng minh hệ thống vượt trội so với pure signature IDS.

**Evasion 1 — IP Spoofing + Fragmentation**:
```bash
# Fragment packets để né Suricata signature matching
nmap -f --mtu 8 -sS 192.168.226.151
nmap -f -f -sS 192.168.226.151  # 16-byte fragments
```
*Narrative*: Suricata bỏ sót do packet quá nhỏ, nhưng ML nhận ra flow statistics bất thường (IAT pattern của scan).

**Evasion 2 — Decoy Scan** (nguồn IP giả):
```bash
nmap -D RND:10 192.168.226.151  # 10 decoy IPs
nmap -D 10.0.0.1,10.0.0.2,10.0.0.3 192.168.226.151
```
*Narrative*: IP thật vẫn phải gửi SYN → ML bắt được src_ip thật.

**Evasion 3 — Low-and-Slow PortScan**:
```bash
nmap -sS -T0 -p 1-100 192.168.226.151  # T0 = Paranoid, 5 phút/port
```
*Narrative*: Suricata không alert, nhưng khi NFStream hoàn tất flow (sau timeout), ML vẫn classify là PortScan nhờ `Idle Max`, `IAT Std`.

---

## Tiêu Chí Thành Công Đo Được (KPIs)

| Chỉ Số | Mục Tiêu | Cách Đo |
|---|---|---|
| Detection Rate | ≥ 99% tấn công bị phát hiện | Đếm số kịch bản bị block |
| Response Time | < 100ms từ flow → iptables DROP | Log `Total: XXms` trong autodefense.log |
| False Positive Rate | = 0 trong demo (whitelist đúng) | Truy cập web bình thường vẫn OK |
| Multi-class Accuracy | Đúng loại tấn công ≥ 5/6 kịch bản | Grafana ML Probabilities panel |
| Suricata Correlation | Hiển thị được boost score khi L7 detect | Log `corr=0.15, suri_alerts=X` |

---

## Kịch Bản "Chứng Minh Giá Trị Của ML" (Quan Trọng Nhất)

> [!IMPORTANT]
> **Đây là phần hội đồng sẽ hỏi nhiều nhất**: "Tại sao cần ML? Suricata không đủ sao?"

**Bước 1**: Tạm thời disable ML (chỉ dùng Suricata threshold = alert only), chạy Kịch Bản 1 Phase 1 (Slow Scan T1).
→ *Suricata: 0 alerts. Hệ thống im lặng.*

**Bước 2**: Enable ML lại, chạy cùng kịch bản.
→ *ML: SUSPICIOUS → AUTO_BLOCKED dù không có Suricata alert.*

**Kết luận trực quan**: ML phát hiện được zero-day-like behavior mà signature-based bỏ sót.

---

## Chuẩn Bị Kỹ Thuật Trước Demo

### Checklist Môi Trường
- [ ] Docker compose đang chạy đủ 4 containers: `suricata`, `autodefense`, `loki`, `grafana`
- [ ] Kiểm tra `docker logs autodefense -f` để xác nhận NFStream đang capture
- [ ] Grafana dashboard mở sẵn, auto-refresh 5s, khung hình full-screen
- [ ] **Xóa blacklist** và flush iptables trước mỗi kịch bản mới
- [ ] IP máy attacker **KHÔNG** nằm trong whitelist.json
- [ ] IP máy bản thân (máy demo, admin) đã được thêm vào whitelist.json

### Checklist Công Cụ Trên Máy Attacker (Kali Linux)
- [ ] `nmap`, `hping3`, `hydra`, `medusa`, `sqlmap`, `nikto`, `gobuster`, `wfuzz`
- [ ] `slowhttptest` hoặc `slowloris.py`
- [ ] `scapy` (Python) cho custom packet crafting
- [ ] Wordlists: `rockyou.txt`, `common.txt`, `unix_users.txt`
- [ ] Script Python custom cho Botnet simulation

### Checklist Log & Monitoring
- [ ] Terminal 1: `docker logs autodefense -f` (live log stream)
- [ ] Terminal 2: `watch -n 1 "iptables -L INPUT -n --line-numbers | head -20"` (live firewall rules)
- [ ] Terminal 3: `sudo iptables -L INPUT -n -v` (packet counts)
- [ ] Browser: Grafana dashboard `http://192.168.226.151:3000`

---

## Kịch Bản Trả Lời Câu Hỏi Hội Đồng

| Câu Hỏi Dự Kiến | Câu Trả Lời + Bằng Chứng |
|---|---|
| "Tại sao dùng XGBoost mà không phải Deep Learning?" | Latency 0.73µs vs CNN/LSTM cần > 1ms; tabular data XGBoost vượt trội; model chỉ 2.12 MB |
| "Dataset CIC-IDS-2017 có phải dữ liệu thực tế không?" | Là chuẩn quốc tế, được dùng trong 500+ bài báo peer-reviewed; giới hạn đã trình bày rõ ở mục 1.3 |
| "SMOTE có tạo ra overfitting không?" | Test set hoàn toàn tách biệt khỏi SMOTE; FPR 0.106% trên tập test không có SMOTE |
| "Ngưỡng 0.85 lấy từ đâu?" | ROC curve analysis; trade-off giữa DR và FPR; đã thử 0.5, 0.7, 0.85, 0.95 |
| "Hệ thống có bị bypass không?" | Demo Kịch Bản 6; giải thích lớp Suricata là safety net khi ML không chắc |
| "Performance trên production thế nào?" | Single-node test; đã nêu limitation ở scope; hướng phát triển là distributed |

---

## Thứ Tự Demo Tối Ưu (Gợi Ý 20 Phút)

| Thời Gian | Hoạt Động |
|---|---|
| 0:00 - 2:00 | Giới thiệu kiến trúc tổng thể, mở Grafana dashboard |
| 2:00 - 4:00 | **Baseline**: Ping bình thường, truy cập web bình thường → BENIGN trên Grafana |
| 4:00 - 7:00 | **Kịch Bản 2**: SSH Brute Force → AUTO_BLOCKED, đo response time |
| 7:00 - 10:00 | **Kịch Bản 3**: DoS Flood → Grafana Alert + iptables DROP live |
| 10:00 - 13:00 | **Kịch Bản 1 Phase 1**: Slow Scan (không có Suricata alert) → ML vẫn bắt |
| 13:00 - 15:00 | **Kịch Bản 4**: Web Attack → Multi-class: "Web Attack 0.97" trên Grafana |
| 15:00 - 17:00 | **"Chứng Minh Giá Trị ML"**: Disable ML → miss; Enable ML → catch |
| 17:00 - 20:00 | Q&A + Hiển thị action_audit.log, thống kê tổng kết |

---

## Các Yếu Tố Nâng Cao Điểm Ấn Tượng

1. **Live Response Time Counter**: Trong demo, sau khi chạy tấn công, chiếu log line `Total: 47ms` lên màn hình và nói *"Hệ thống phản ứng trong 47ms, nhanh hơn cả TCP handshake timeout của mã độc"*.

2. **Grafana Full-Screen Mode**: Panel `Threat Logs (Non-Benign)` và `Top Source IPs` phải được highlight khi bị tấn công — đây là visual impact mạnh nhất.

3. **Reset Script**: Chuẩn bị sẵn script reset môi trường nhanh giữa các kịch bản:
```bash
# reset_demo.sh
sudo iptables -F INPUT
sudo iptables -A INPUT -j ACCEPT
echo "[]" > /path/to/configs/blacklist.json
docker restart autodefense
```

4. **Slide "Before vs After"**: Slide so sánh Suricata-only vs hệ thống của bạn trên cùng traffic trace — không có gì thuyết phục hơn con số.

5. **action_audit.log Export**: Sau demo, mở file `action_audit.log` (JSON structured), đọc được event đầy đủ: `attacker_ip`, `predicted_threat`, `response_time_ms` — chứng minh hệ thống có audit trail.
