# BÁO CÁO CHẤT LƯỢNG CODE — HỆ THỐNG ZERO-TOUCH IDPS

**Ngày:** 2026-06-11  
**Phạm vi:** Toàn bộ dự án `C:\IDPS`  
**Ngôn ngữ:** Python 3.10+ | Tổng dòng code Python: ~1,800

---

## TÓM TẮT

| Hạng mục | Số lượng | Mức nghiêm trọng |
|:---|:---|:---|
| Lỗi logic | 11 | 4 Critical, 4 Medium, 3 Low |
| Code thừa / chết | 4 | 2 Medium, 2 Low |
| Lỗ hổng bảo mật | 8 | 3 Critical, 3 Medium, 2 Low |

---

## PHẦN 1: LỖI LOGIC

### 🔴 Critical

#### L1. `ConnectionRatePlugin` sẽ crash runtime — `self.tracker` không được khởi tạo

**File:** `src/realtime_extractor.py:53-57`

```python
class ConnectionRatePlugin(NFPlugin):
    def on_init(self, packet, flow):
        current_time_sec = packet.time / 1000.0
        flow.udps.conn_rate = self.tracker.add_and_count(...)  # ← AttributeError!
```

Lớp `ConnectionRatePlugin` không định nghĩa `__init__`, không có dòng `self.tracker = tracker` nào. Khi `on_init` được gọi, `self.tracker` sẽ gây `AttributeError`. Plugin này được sử dụng trong cả `create_streamer()` (real-time) và `extract_pcap_features.py` (offline).

→ **Hậu quả:** Toàn bộ pipeline real-time sẽ crash khi có flow đầu tiên đi qua plugin này.

---

#### L2. `TCPWindowPlugin` trích xuất sai giá trị TCP Window Size

**File:** `src/realtime_extractor.py:67-71`

```python
def on_update(self, packet, flow):
    if flow.udps.is_first_packet and packet.direction == 0:
        flow.udps.init_win_fwd = packet.ip_size  # ← ĐÂY LÀ IP SIZE, KHÔNG PHẢI TCP WINDOW!
```

Giá trị `packet.ip_size` là kích thước gói tin ở tầng IP, **không phải** kích thước TCP Window. TCP Window nằm trong TCP header và cần được parse riêng. Kết quả là 2 trong 30 features (`Init_Win_bytes_forward`, `Init_Win_bytes_backward` — index 19, 20) luôn chứa giá trị sai, làm giảm độ chính xác của toàn bộ mô hình ML.

→ **Hậu quả:** Mô hình ML hoạt động với dữ liệu nhiễu ở 2/30 features (~7% features bị sai), dẫn đến tỉ lệ False Negative/False Positive tăng.

---

#### L3. `Bwd IAT Total` tính xấp xỉ thô, khác biệt nghiêm trọng với tập huấn luyện

**File:** `src/realtime_extractor.py:127`

```python
flow.dst2src_max_piat_ms * flow.dst2src_packets * 1000.0,
```

Công thức `max_piat × số_gói_tin` là upper bound cực kỳ thô. Trong tập CIC-IDS-2017, "Bwd IAT Total" là **tổng thực tế** của tất cả khoảng thời gian giữa các gói tin chiều ngược. Sai số có thể lên đến hàng trăm lần đối với các flow có IAT biến thiên lớn.

→ **Hậu quả:** Feature mismatch giữa training và inference, giảm độ chính xác ML.

---

#### L4. `SURICATA_ONLY_MODE` khiến `final_confidence` bị tính 2 lần Suricata

**File:** `src/autodefense_daemon.py:127-197`

Trong chế độ `SURICATA_ONLY_MODE=true`:
1. Dòng 130-135: `correlator.correlate()` được gọi → trả về `correlation_score`
2. Dòng 154: Gán `result["correlation_score"] = correlation_score`
3. Dòng 184: `final_confidence = min(result["confidence"] + correlation_score, 1.0)`

Nhưng `result["confidence"]` đã được gán bằng `correlation_score` ở dòng 139 (khi không có DROP action) hoặc `max(correlation_score, 0.90)` ở dòng 151 (khi có DROP). Như vậy **Suricata score bị cộng 2 lần** vào final_confidence.

→ **Hậu quả:** Trong SURICATA_ONLY_MODE, confidence bị đội lên cao giả tạo, gây False Positive.

---

### 🟡 Medium

#### L5. `whitelist_alert_threshold` được load nhưng không bao giờ sử dụng

**File:** `src/threat_evaluator.py:69`

```python
self.whitelist_alert_threshold = cfg.get("whitelist_alert_threshold", 0.85)
```

Biến này có mặt trong `thresholds.json`, được load cẩn thận với `try/except` và giá trị mặc định, nhưng **không hề được tham chiếu** ở bất kỳ đâu trong toàn bộ codebase. Tương tự, `configs/thresholds.json` cũng chứa field này.

→ **Hậu quả:** Code thừa + gây hiểu nhầm rằng whitelist có cơ chế alert riêng.

---

#### L6. `is_attack` bị kiểm tra kép (double-check) không cần thiết

**File:** `src/autodefense_daemon.py:204`

```python
if result["is_attack"] and result["confidence"] > evaluator.auto_block_threshold:
```

Trong `threat_evaluator.py:202`:
```python
is_attack = confidence > self.auto_block_threshold
```

`is_attack` đã được định nghĩa là `confidence > auto_block_threshold`, nên điều kiện thứ 2 là dư thừa. Nếu `auto_block_threshold` bị thay đổi runtime (vd reload config), 2 giá trị này có thể lệch nhau.

---

#### L7. `datetime.now()` vs `datetime.now(timezone.utc)` không nhất quán

**File:** `src/suricata_correlator_remote.py:216` vs `src/suricata_correlator.py:232`

```python
# suricata_correlator_remote.py:216
now = datetime.now()  # ← timezone-naive

# suricata_correlator.py:232
now = datetime.now(timezone.utc)  # ← timezone-aware
```

Phiên bản chính (`suricata_correlator.py`) đã sửa thành timezone-aware, nhưng nếu `suricata_correlator_remote.py` còn được dùng ở đâu đó, việc so sánh timezone-naive với timezone-aware timestamp từ Suricata có thể gây ra hành vi không xác định.

---

### 🟢 Low

#### L8. IPv6 trong whitelist.json vô tác dụng

**File:** `configs/whitelist.json`, `src/autodefense_daemon.py:91`

Whitelist chứa `fe80::20c:29ff:fecc:4bbb` và `fe80::20c:29ff:fee3:d92`. Nhưng `process_flow()` dòng 91 filter IPv6 (`":" in src_ip`) **trước** khi kiểm tra whitelist:

```python
if ":" in src_ip or src_ip == "0.0.0.0":
    return  # ← Thoát trước khi check whitelist!
```

→ 2 entry IPv6 trong whitelist không bao giờ được sử dụng.

---

#### L9. `PROTECTED_IPS` trong `auto_firewall.py` khác biệt với `whitelist.json`

| IP | `PROTECTED_IPS` | `whitelist.json` |
|:---|:---|:---|
| `192.168.226.1` | ✓ | ✓ |
| `192.168.226.151` | ✓ | ❌ (`192.168.225.151` — khác 1 số!) |
| `192.168.226.15` | ❌ | ✓ |
| `172.16.1.1` | ❌ | ✓ |
| `172.16.1.2` | ❌ | ✓ |

`192.168.225.151` trong whitelist.json có khả năng cao là **lỗi đánh máy** (nên là `192.168.226.151`).

---

## PHẦN 2: CODE THỪA / CHẾT

### 🟡 Medium

#### D1. `suricata_correlator_remote.py` — phiên bản cũ, logic đã lỗi thời

**File:** `src/suricata_correlator_remote.py` (350 dòng)

Đây là bản sao gần như y hệt `suricata_correlator.py` nhưng **thiếu toàn bộ các bản sửa lỗi quan trọng ngày 2026-05-20**:
- Không có dedup theo signature_id
- Không áp dụng severity_boost làm hệ số nhân
- Không có nhánh `suricata_only` riêng
- Repeat offender áp dụng kể cả khi ML nói Benign
- Hard cap 0.5 thay vì 0.90 / `suricata_only_max_score`
- Không hỗ trợ X-Forwarded-For

**Không được import ở bất kỳ đâu.** Gây nguy hiểm nếu ai đó vô tình import nhầm file này.

→ **Khuyến nghị:** Xóa file này ngay lập tức.

---

### 🟢 Low

#### D2. `test.py` — file hỏng ở thư mục gốc

**File:** `C:\IDPS\test.py`

File chứa nội dung mã hóa/garbled (có vẻ là UTF-16 được đọc sai). Không có giá trị sử dụng.

---

#### D3. Import `random` chỉ để dùng 1 lần cho monkey-patch

**File:** `src/realtime_extractor.py:74,94`

```python
import random  # ← Import ở giữa file, không theo chuẩn
...
streamer._idx = random.randint(10000, 50000)  # ← Dùng đúng 1 lần
```

Import nên được đưa lên đầu file. Logic monkey-patch `streamer._idx` truy cập vào private attribute của thư viện ngoài — dễ vỡ khi NFStream update.

---

## PHẦN 3: BẢO MẬT

### 🔴 Critical

#### S1. TOCTOU Race Condition giữa blacklist check và firewall block

**File:** `src/autodefense_daemon.py:99-101,204-209`

```python
# Bước 1: Check blacklist (dòng 99)
if ip_mgr.is_blacklisted(src_ip):
    firewall.block_ip(...)
    return

# ... 100 dòng code sau ...

# Bước 2: Quyết định block IP mới (dòng 204-209)
if result["is_attack"] and result["confidence"] > evaluator.auto_block_threshold:
    firewall.block_ip(src_ip, ...)
    ip_mgr.add_to_blacklist(src_ip, ...)
```

Khoảng thời gian giữa `is_blacklisted()` (dòng 99) và `block_ip()` (dòng 206), một attacker có thể gửi **nhiều flow đồng thời** từ cùng IP. Flow thứ 2 sẽ vượt qua blacklist check (vì IP chưa kịp bị thêm vào blacklist bởi flow 1), dẫn đến phải chạy ML inference không cần thiết và có khả năng tạo ra các rule iptables trùng lặp.

Mặc dù `auto_firewall.block_ip()` có duplicate check, nhưng vẫn lãng phí CPU cho ML inference.

---

#### S2. `GF_SECURITY_ADMIN_PASSWORD` mặc định là `admin`

**File:** `docker/docker-compose.yml:87`

```yaml
GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
```

Nếu triển khai mà không set biến môi trường, Grafana sẽ có mật khẩu `admin/admin` — một trong những cặp credentials bị tấn công nhiều nhất.

---

#### S3. Log gửi qua HTTP không mã hóa

**File:** `src/autodefense_daemon.py:56`

```python
loki_url = os.getenv("LOKI_URL", "http://192.168.226.151:3100/loki/api/v1/push")
```

Tất cả log (bao gồm IP attacker, loại tấn công, cấu trúc mạng nội bộ) được gửi qua HTTP không mã hóa. Không có TLS, không có authentication. Bất kỳ ai trong mạng nội bộ đều có thể sniff hoặc inject log giả.

---

### 🟡 Medium

#### S4. Container chạy trong `network_mode: host`

**File:** `docker/docker-compose.yml:18,27`

```yaml
suricata:
    network_mode: 'host'
autodefense:
    network_mode: 'host'
```

2 container dùng host network, tức là chúng chia sẻ toàn bộ network namespace với máy chủ. Nếu 1 container bị compromise, attacker có toàn quyền truy cập network của host.

---

#### S5. Image Docker dùng tag `:latest` — không kiểm soát được phiên bản

```yaml
image: grafana/loki:latest
image: grafana/grafana:latest
image: bkimminich/juice-shop:latest
```

Tag `latest` khiến việc tái tạo môi trường (reproducible builds) là không thể, và có thể vô tình nhận bản update chứa CVE mới.

---

#### S6. Không có cơ chế rate-limiting cho việc block IP

**File:** `src/autodefense_daemon.py:204-209`

Không có giới hạn số lượng IP bị block trong 1 khoảng thời gian. Một attacker có thể giả mạo nhiều IP (spoofing) để làm đầy bộ nhớ blacklist và/hoặc iptables chain, dẫn đến từ chối dịch vụ (DoS chính hệ thống phòng thủ).

---

### 🟢 Low

#### S7. Không validate IP từ flow trước khi dùng

**File:** `src/autodefense_daemon.py:89`

```python
src_ip = flow.src_ip
if ":" in src_ip or src_ip == "0.0.0.0":
    return
```

Chỉ kiểm tra IPv6 và `0.0.0.0`. Không kiểm tra các địa chỉ đặc biệt khác như:
- `255.255.255.255` (broadcast)
- `127.0.0.0/8` (ngoài `127.0.0.1`)
- Địa chỉ multicast (`224.0.0.0/4`)
- Private IP của chính hệ thống

Tuy `AutoFirewall._is_valid_ip()` có validate, nhưng các địa chỉ trên vẫn hợp lệ về mặt format.

---

#### S8. Không có cơ chế tự động unblock IP sau 1 khoảng thời gian

**File:** `src/auto_firewall.py`

IP bị block là **vĩnh viễn** — không có TTL, không có cơ chế tự động unblock. Nếu False Positive chặn nhầm IP quan trọng, hệ thống không có cách tự phục hồi.

---

## PHỤ LỤC: BẢNG TỔNG HỢP THEO FILE

| File | Lỗi logic | Code thừa | Bảo mật |
|:---|:---|:---|:---|
| `src/realtime_extractor.py` | L1 (Critical), L2 (Critical), L3 (Critical) | D3 (Low) | — |
| `src/autodefense_daemon.py` | L4 (Critical), L6 (Medium), L8 (Low) | — | S1 (Critical), S6 (Medium), S7 (Low), S8 (Low) |
| `src/suricata_correlator.py` | — | — | — |
| `src/suricata_correlator_remote.py` | L7 (Medium) | D1 (Medium) | — |
| `src/threat_evaluator.py` | L5 (Medium) | — | — |
| `src/auto_firewall.py` | L9 (Low) | — | — |
| `configs/whitelist.json` | L8 (Low) | — | — |
| `docker/docker-compose.yml` | — | — | S2 (Critical), S3 (Critical), S4 (Medium), S5 (Medium) |
| `test.py` | — | D2 (Low) | — |

---

## KHUYẾN NGHỊ ƯU TIÊN

1. **Sửa ngay `TCPWindowPlugin`** — trích xuất đúng TCP Window size từ TCP header thay vì `packet.ip_size`
2. **Sửa `ConnectionRatePlugin`** — thêm `__init__` để lưu `self.tracker`
3. **Sửa `Bwd IAT Total`** — tính tổng thực tế hoặc dùng feature tương đương từ NFStream
4. **Xóa `suricata_correlator_remote.py`** — tránh nhầm lẫn với bản chính
5. **Sửa double-count trong SURICATA_ONLY_MODE** — không cộng correlation_score 2 lần
6. **Bật TLS cho Loki** — dùng HTTPS và thêm authentication
7. **Thêm rate-limiting** cho việc block IP để chống DoS ngược
8. **Đồng bộ `PROTECTED_IPS` với `whitelist.json`** — sửa `192.168.225.151` → `192.168.226.151`
9. **Pin version Docker images** — thay `:latest` bằng tag cụ thể
10. **Thêm cơ chế TTL cho IP bị block** — tự động unblock sau N phút