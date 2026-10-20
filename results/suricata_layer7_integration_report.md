# Báo Cáo Tích Hợp Suricata Layer 7 — Hybrid Detection System

**Thời gian:** 16/05/2026  
**Người thực hiện:** Antigravity (AI Coding Agent)  
**Trạng thái:** Hoàn thành triển khai cơ sở hạ tầng

---

## 1. Bối cảnh & Vấn đề

### 1.1 Giới hạn của ML Model hiện tại

Mô hình XGBoost 2 tầng (Binary + Multiclass) của hệ thống IDPS hoạt động trên **30 features thống kê** được trích xuất từ NFStream ở tầng mạng Layer 3-4 (Transport/Network). Đây là thiết kế phù hợp cho:

| Loại tấn công | ML phát hiện? | Lý do |
|:---|:---:|:---|
| DoS/DDoS volumetric | ✅ 99.95% DR | Features: packet rate, byte rate, flow duration |
| Brute Force SSH/FTP | ✅ 100.00% DR | Features: connection frequency, port patterns |
| Port Scan | ✅ 99.99% DR | Features: unique dst port count, SYN flag ratio |
| Botnet C2 Beacon | ✅ 96.15% DR | Features: periodic timing, packet size variance |
| Web Attack (flow) | ⚠️ 98.83% DR | Chỉ thấy hành vi flow, KHÔNG thấy payload |

**Điểm mù tuyệt đối của ML (Layer 7 — Application Layer):**

| Loại tấn công L7 | ML phát hiện? | Lý do ML bị mù |
|:---|:---:|:---|
| SQL Injection payload | ❌ | 1 HTTP GET/POST bình thường — không có pattern thống kê |
| XSS (`<script>...`) | ❌ | Payload size giống request bình thường |
| Command Injection | ❌ | 1 request = 1 flow, không có hành vi dị thường |
| Path Traversal (`../../`) | ❌ | URI length không khác biệt đáng kể |
| Malware download (PE header) | ❌ | ML không inspect nội dung file |
| DNS Tunneling (encoded) | ❌ | ML thấy DNS flow bình thường |

### 1.2 Phát hiện trong Codebase

Khi phân tích source code, phát hiện ra **`src/suricata_correlator.py`** (350 dòng) đã được viết đầy đủ nhưng **KHÔNG BAO GIỜ được import hay gọi** trong `autodefense_daemon.py`. Module correlation hoàn toàn "chết" trong production.

---

## 2. Giải pháp: Hybrid Detection Architecture

### 2.1 Chiến lược Fusion

```
Traffic (HTTPS) → Nginx (TLS Termination) → Plaintext HTTP
                                                    │
                          ┌─────────────────────────┤
                          │                         │
                          ▼                         ▼
              ┌─────────────────────┐   ┌─────────────────────┐
              │  Suricata DPI       │   │  NFStream Extractor  │
              │  (Layer 7 inspect)  │   │  (Layer 3-4 stats)  │
              │                     │   │                      │
              │  Custom Rules:      │   │  30 Features →       │
              │  SQLi, XSS, CMDi,  │   │  XGBoost Binary +    │
              │  PathTraversal...   │   │  XGBoost Multiclass  │
              └─────────┬───────────┘   └──────────┬───────────┘
                        │ eve.json (tail)           │ result dict
                        ▼                           ▼
              ┌─────────────────────────────────────────────┐
              │           CORRELATION ENGINE                 │
              │   SuricataCorrelator.correlate()            │
              │                                              │
              │   final_score = ML_score + corr_score       │
              │   IF suricata_action == "drop" → Override   │
              └────────────────────┬─────────────────────────┘
                                   │ final_confidence
                                   ▼
              ┌─────────────────────────────────────────────┐
              │           DECISION ENGINE                    │
              │   if final_confidence > 0.85 → AUTO_BLOCK   │
              │   if suricata_action_drop → AUTO_BLOCK       │
              └────────────────────┬─────────────────────────┘
                                   │
                                   ▼ iptables DROP + Blacklist
```

### 2.2 Fusion Score Formula

```
final_confidence = min(ML_score + correlation_score, 1.0)

Trong đó:
  correlation_score = 0.0  (mặc định, không có Suricata alert)
                   + 0.05  (≥ 2 alerts từ cùng IP)
                   + 0.15  (≥ 3 alerts — repeat offender)
                   + 0.20  (matching attack type — confirmation)
                   + 0.30  (different attack types — HIGH RISK)
                   + 0.50  (action=drop từ custom L7 rules)

  Max cap: 0.9 (không bao giờ saturate về 1.0 từ Suricata đơn độc)
```

**Suricata Override Mode**: Nếu Suricata bắn rule có `action=drop`, `blocked`, hoặc `reject` → `final_confidence` bị ép về ≥ 0.90 và `is_attack = True`, bất kể ML cho kết quả gì.

---

## 3. Chi tiết các thay đổi

### 3.1 File MỚI được tạo

#### `docker/suricata/custom-rules/local.rules`

Custom ruleset 12 rules, tất cả dùng action `drop` (block ngay lập tức), phủ các vector tấn công L7 chính:

| SID | Mô tả | Pattern |
|:---|:---|:---|
| 1000001 | SQL Injection — UNION SELECT | `content:"UNION"; content:"SELECT"; within:20` |
| 1000002 | SQL Injection — OR 1=1 | `content:"OR"; content:"1=1"; within:10` |
| 1000003 | SQL Injection — Comment | `content:"--"; content:"'"` |
| 1000010 | XSS — Script Tag | `content:"<script"; nocase` |
| 1000011 | XSS — Event Handler | `pcre:"/on(load\|error\|click\|mouseover)\s*=/i"` |
| 1000012 | XSS — javascript URI | `content:"javascript:"; nocase` |
| 1000020 | Command Injection — Semicolon | `content:";"; content:"/bin/"; within:20` |
| 1000021 | Command Injection — Pipe | `content:"\|"; content:"/etc/passwd"; within:30` |
| 1000030 | Path Traversal | `content:"../"; content:"../"; within:10` |
| 1000040 | Malware PE Download | `content:"MZ"; offset:0; depth:2` |
| 1000050 | DNS Tunneling — Long Query | `dsize:>100` (DNS query dài bất thường) |

**Thiết kế rules:**
- Chỉ match trên `http` protocol, `flow:established,to_server` — tránh false positive
- `classtype:web-application-attack` để Suricata phân loại đúng severity
- PCRE được dùng tiết kiệm (chỉ cho XSS event handler) vì overhead cao

#### `docker/suricata/patch_config.sh`

Script chạy trong Docker build-time để patch file `/etc/suricata/suricata.yaml` mặc định:

1. Cập nhật `HOME_NET` bao gồm các dải mạng RFC1918
2. Enable XFF (X-Forwarded-For) parser: `mode: overwrite` — ghi đè `src_ip` trong EVE JSON bằng IP thật của client (thay vì IP của Nginx proxy)
3. Inject đường dẫn custom rules vào `rule-files` section

#### `docker/nginx/nginx.conf`

Reverse proxy với 2 server block:
- **Port 80**: Redirect 301 sang HTTPS
- **Port 443 SSL**: TLS termination, `proxy_pass` sang `juice-shop:3000`

Headers được chèn:
```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

XFF header này là **cầu nối quan trọng** giữa Nginx và Suricata: Suricata đọc header này từ HTTP payload plaintext trên `br-idps`, dùng IP thật của attacker thay vì IP `172.x.x.x` của Nginx.

#### `docker/nginx/entrypoint.sh`

Script tự sinh **self-signed certificate** khi container khởi động lần đầu:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/key.pem \
    -out /etc/nginx/certs/cert.pem \
    -subj "/C=VN/ST=HCM/L=HCM/O=IDPS/OU=Dev/CN=localhost"
```

Trong production thực tế, thay thế bằng Let's Encrypt (Certbot) hoặc enterprise certificate.

#### `docker/nginx/Dockerfile`

Image `nginx:alpine` + `openssl` để sinh cert. Lightweight (~25MB).

---

### 3.2 File được CHỈNH SỬA

#### `docker/suricata/Dockerfile`

**Thêm 4 dòng** vào sau `RUN suricata-update`:

```dockerfile
COPY custom-rules/ /etc/suricata/rules/custom/
COPY patch_config.sh /patch_config.sh
RUN chmod +x /patch_config.sh && /patch_config.sh
```

Kết quả: Container Suricata build-time đã có sẵn custom rules và XFF config.

#### `docker/docker-compose.yml`

**5 thay đổi chính:**

1. **Suricata**: Thêm `depends_on: nginx` và lắng nghe thêm interface `br-idps` (để inspect plaintext HTTP sau Nginx)
2. **Autodefense**: Thêm volume mount `../logs/suricata:/app/logs/suricata:ro` — chia sẻ log giữa Suricata (write) và Autodefense (read-only)
3. **Thêm service `juice-shop`**: Web app mẫu có lỗ hổng bảo mật, dùng để test L7 attacks
4. **Thêm service `nginx`**: Reverse proxy với SSL termination
5. **Thêm network `idps_net`**: Docker bridge network tên `br-idps` — Nginx và Juice-shop giao tiếp qua đây, Suricata sniff trên bridge này

**Chi tiết network flow:**
```
[Attacker] --HTTPS--> [Host:443] --DNAT--> [Nginx:443]
                                                │
                              [br-idps network] │ plaintext HTTP
                                                ▼
                                         [Juice-shop:3000]

[Suricata] sniffs ---> br-idps (plaintext) + ens33 (encrypted)
```

#### `src/suricata_correlator.py`

**Thay đổi 1 — XFF-aware IP extraction** (dòng 30-41):

```python
# Lấy Real IP từ X-Forwarded-For nếu có (dành cho Reverse Proxy)
http_data = alert_data.get("http", {})
xff = http_data.get("xff")
if xff:
    self.src_ip = xff.split(",")[0].strip()  # Lấy IP đầu tiên trong chuỗi XFF
else:
    self.src_ip = alert_data.get("src_ip")   # Fallback: IP trực tiếp
```

**Lý do**: Khi Nginx terminate TLS, `src_ip` trong EVE JSON sẽ là IP của Nginx (`172.18.0.x`), không phải IP attacker thật. Nhờ XFF override trong Suricata + logic này, ta lấy được IP attacker thật.

**Thay đổi 2 — Suricata Drop Action boost** (dòng 292-304):

```python
# Check 5: Action Drop (Critical L7 Custom Rules)
if alert.action in ["drop", "blocked", "reject"]:
    details["suricata_action_drop"] = True
    correlation_score += 0.50

# Cap nâng từ 0.5 → 0.9 (cho phép drop action đẩy score cao)
correlation_score = min(correlation_score, 0.9)
```

#### `src/autodefense_daemon.py`

**4 thay đổi cốt lõi:**

**Thay đổi 1** — Import SuricataCorrelator:
```python
from suricata_correlator import SuricataCorrelator
```

**Thay đổi 2** — Thêm `correlator` parameter vào `process_flow()`:
```python
def process_flow(flow, ip_mgr, evaluator, firewall, correlator: SuricataCorrelator):
```

**Thay đổi 3** — Bước 3.5 mới trong pipeline xử lý flow:
```python
# Bước 3.5: Suricata Correlation (Layer 7)
correlation_score, correlation_details = correlator.correlate(
    src_ip=src_ip,
    dst_port=flow.dst_port,
    ml_attack_type=result.get("attack_type", ""),
    ml_confidence=result["confidence"]
)

# Fusion Score
final_confidence = min(result["confidence"] + correlation_score, 1.0)

# Override: Nếu Suricata drop L7 rule → bắt buộc block dù ML miss
if correlation_details.get("suricata_action_drop"):
    if not result["is_attack"]:
        result["is_attack"] = True
        result["attack_type"] = f"Suricata_L7_DROP ({matched_sig})"
        logger.warning(f"SURICATA_OVERRIDE: {src_ip} — ML missed but Suricata L7 caught")
    final_confidence = max(final_confidence, 0.90)

result["confidence"] = final_confidence
```

**Thay đổi 4** — Khởi tạo SuricataCorrelator trong `main()`:
```python
# 4. Suricata Correlator (Layer 7 DPI)
suricata_log_path = os.getenv("SURICATA_EVE_PATH", "/app/logs/suricata/eve.json")
correlator = SuricataCorrelator(eve_json_path=suricata_log_path)
correlator.start()  # Bắt đầu background thread đọc eve.json
logger.info(f"SuricataCorrelator: watching {suricata_log_path}")
```

#### `configs/thresholds.json`

**Thêm 3 tham số mới:**

```json
{
    "description": "Confidence thresholds for autonomous decision engine. suricata_only_max_score: hard cap correlation score khi ML=Benign",
    "auto_block_threshold": 0.85,
    "alert_threshold": 0.60,
    "whitelist_alert_threshold": 0.85,
    "suricata_only_max_score": 0.30
}
```

| Tham số | Giá trị | Ý nghĩa |
|:---|:---:|:---|
| `auto_block_threshold` | 0.85 | Tăng từ 0.80 — cần confidence cao hơn do Fusion có thể inflate score |
| `alert_threshold` | 0.60 | Tăng từ 0.35 — tránh quá nhiều SUSPICIOUS logs |
| `suricata_only_max_score` | 0.30 | Hard cap correlation score khi ML=Benign — tránh ET Open alerts tự kích hoạt block |

---

## 4. Decision Engine — Các Scenario mới

| Scenario | ML Score | Suricata | Fusion Action | Log Label |
|:---|:---:|:---:|:---:|:---:|
| **ML-only detect** | > 0.85 | Không có alert | `AUTO_BLOCK` | `ML_DETECTED` |
| **Suricata Drop L7** | Bất kỳ | `action=drop` | `AUTO_BLOCK` (override) | `Suricata_L7_DROP` |
| **Cross-validation** | > 0.60 | Has matching alert | `AUTO_BLOCK` (boosted) | `ML_DETECTED + correlation` |
| **Suricata low severity** | < 0.60 | `severity=1` (info) | `SUSPICIOUS` (alert only) | `SUSPICIOUS` |
| **ML SUSPICIOUS only** | 0.60–0.85 | Không có alert | `SUSPICIOUS` | `SUSPICIOUS` |
| **Benign** | < 0.60 | Không có alert | `BENIGN` (pass) | `BENIGN` |

---

## 5. Tóm tắt files thay đổi

| File | Hành động | Mô tả |
|:---|:---:|:---|
| `docker/suricata/custom-rules/local.rules` | **TẠO MỚI** | 11 custom rules, action `drop`, cho SQLi/XSS/CMDi/PathTraversal |
| `docker/suricata/patch_config.sh` | **TẠO MỚI** | Patch suricata.yaml: HOME_NET, XFF override, custom rule path |
| `docker/nginx/nginx.conf` | **TẠO MỚI** | HTTPS reverse proxy, TLS termination, XFF headers |
| `docker/nginx/entrypoint.sh` | **TẠO MỚI** | Auto-generate self-signed cert on first start |
| `docker/nginx/Dockerfile` | **TẠO MỚI** | nginx:alpine + openssl |
| `docker/suricata/Dockerfile` | **SỬA ĐỔI** | Thêm COPY custom rules + RUN patch_config.sh |
| `docker/docker-compose.yml` | **SỬA ĐỔI** | Thêm nginx, juice-shop, idps_net; sửa Suricata/Autodefense volumes |
| `src/suricata_correlator.py` | **SỬA ĐỔI** | XFF IP extraction + Drop action boost (+0.50) + cap nâng 0.9 |
| `src/autodefense_daemon.py` | **SỬA ĐỔI** | Import + khởi tạo Correlator, thêm Bước 3.5 Fusion vào pipeline |
| `configs/thresholds.json` | **SỬA ĐỔI** | Thêm 3 tham số Suricata, điều chỉnh thresholds |

**Không thay đổi:** `src/threat_evaluator.py`, `src/realtime_extractor.py`, `src/auto_firewall.py`, `src/ip_manager.py`, `models/*.pkl`

---

## 6. Hướng dẫn Triển khai (Deploy lên Ubuntu VM)

```bash
# 1. Sync files mới từ Windows sang Ubuntu
scp -r c:\IDPS\docker\nginx dmtien@192.168.226.151:/home/dmtien/IDPS/docker/
scp c:\IDPS\docker\suricata\Dockerfile dmtien@192.168.226.151:/home/dmtien/IDPS/docker/suricata/
scp c:\IDPS\docker\suricata\patch_config.sh dmtien@192.168.226.151:/home/dmtien/IDPS/docker/suricata/
scp -r c:\IDPS\docker\suricata\custom-rules dmtien@192.168.226.151:/home/dmtien/IDPS/docker/suricata/
scp c:\IDPS\docker\docker-compose.yml dmtien@192.168.226.151:/home/dmtien/IDPS/docker/
scp c:\IDPS\src\autodefense_daemon.py dmtien@192.168.226.151:/home/dmtien/IDPS/src/
scp c:\IDPS\src\suricata_correlator.py dmtien@192.168.226.151:/home/dmtien/IDPS/src/
scp c:\IDPS\configs\thresholds.json dmtien@192.168.226.151:/home/dmtien/IDPS/configs/

# 2. SSH vào server và rebuild
ssh dmtien@192.168.226.151
cd /home/dmtien/IDPS/docker
docker-compose down
docker-compose up -d --build

# 3. Kiểm tra tất cả containers up
docker-compose ps

# 4. Xác nhận Suricata đang watch br-idps
docker logs suricata 2>&1 | grep "br-idps\|ens33"

# 5. Xác nhận SuricataCorrelator đang chạy trong Autodefense
docker logs autodefense 2>&1 | grep "SuricataCorrelator"
```

---

## 7. Kiểm thử Validation

```bash
# Test 1: SQL Injection → phải bị BLOCK
curl -k "https://localhost/rest/products/search?q=1' UNION SELECT * FROM Users --"

# Test 2: XSS → phải bị BLOCK
curl -k "https://localhost/search?q=<script>alert(1)</script>"

# Test 3: Path Traversal → phải bị BLOCK
curl -k "https://localhost/ftp/../../../etc/passwd"

# Test 4: Request hợp lệ → phải PASS
curl -k "https://localhost/rest/products/search?q=apple"

# Xem log blocks trong Grafana: http://192.168.226.151:3000
# Lọc theo: {application="idps-autodefense"} |= "SURICATA_OVERRIDE"
```

---

## 8. Giới hạn & Hướng cải thiện tương lai

| Giới hạn | Mô tả | Giải pháp đề xuất |
|:---|:---|:---|
| **HTTPS mã hóa end-to-end** | Suricata chỉ inspect được traffic sau TLS termination (trên br-idps) | Triển khai mTLS inspection proxy |
| **Self-signed cert** | Browser báo "Not secure" | Dùng Let's Encrypt / Certbot |
| **False Positive risk** | Rules SQLi/XSS có thể match query parameter hợp lệ | Fine-tune rules theo traffic thực tế, dùng `threshold` directive |
| **Suricata rule latency** | Drop action trong Suricata không block ngay ở kernel như iptables | Kết hợp với NFQ (NFQueue) để Suricata drop packet trực tiếp |
| **Chưa có Grafana panels mới** | Chưa thêm panel "Suricata L7 Alerts" vào Grafana dashboard | Thêm panel JSON với LogQL: `{application="idps-autodefense"} |= "SURICATA"` |
