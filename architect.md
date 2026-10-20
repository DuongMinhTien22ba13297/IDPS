topic: Machine Learning-Based Intrusion Detection and Prevention System

Đối với một hệ thống IDPS hiện đại, tính hoàn toàn tự động (Fully Automated / Zero-touch) chính là "trái tim" của dự án, giúp hệ thống phản ứng với các cuộc tấn công trong tính bằng mili-giây mà không cần bất kỳ sự phê duyệt hay can thiệp thủ công nào từ quản trị viên.

File: `architect\_add\_docker.md`

> \*\*Lưu ý Quan trọng về Môi trường Triển khai (Deployment Environment Note):\*\*
> Hệ thống này \*\*hoàn toàn không\*\* được triển khai hay lưu trữ trong thư mục `IDPS` trên máy vật lý (Host OS). Toàn bộ dự án và các tiến trình tự động hóa được host trên \*\*Máy ảo (Virtual Machine) Ubuntu Server 24.04 LTS (Noble Numbat)\*\* và \*\*được container hóa hoàn toàn bằng Docker + Docker Compose\*\*.
>
> \* \*\*Giao thức kết nối:\*\* Yêu cầu sử dụng SSH để truy cập vào môi trường thực thi.
> \* \*\*Địa chỉ máy chủ (Victim/Phòng thủ):\*\* `192.168.226.151`
> \* \*\*Lệnh truy cập:\*\* `ssh dmtien@192.168.226.151`
> \* \*\*Quản lý Docker:\*\* `docker compose up -d --build`, `docker compose logs -f`, `docker compose down`

\---

### 0\. Docker Container Architecture (Multi-Container Zero-Touch)

**Số lượng container: 6 services** trong `docker-compose.yml` (5 container đang chạy, 1 container nginx đã Exited)

> **Trạng thái thực tế (2026-06-01):** Container `reverse-proxy` (nginx) đã Exited — hệ thống hiện hoạt động với 5 container active: suricata, autodefense, loki, grafana, juice-shop.

> \*\*Lưu ý về Feature Extraction:\*\*
> Suricata chỉ cung cấp signature-based alerts (EVE JSON) — \*\*không dùng để trích xuất 15 features ML\*\*.
> \*\*NFStream\*\* được tích hợp trực tiếp vào container `autodefense` để trích xuất 15 đặc trưng tối ưu (IAT, Packet Length, Flag Count, TCP Window...) từ live traffic.
>
> \*\*Lưu ý về Suricata Correlation:\*\*
> Suricata EVE JSON alerts được \*\*tương quan (correlate)\*\* với kết quả ML inference qua module `suricata\_correlator.py` — kết hợp Layer 3-4 (ML/NFStream) với Layer 7 (Suricata DPI) để tăng độ chính xác phát hiện.

|STT|Container Name|Image Type|Network Mode|Privileges / Cap|Volume Mounts chính|Mục đích chính|
|-|-|-|-|-|-|-|
|1|**suricata**|Custom (`docker-suricata`, built from Ubuntu 22.04)|`host`|NET\_ADMIN, NET\_RAW, NET\_BIND\_SERVICE|`../logs/suricata:/var/log/suricata`|Packet capture & sinh EVE JSON alerts; signature-based detection; custom Layer 7 rules|
|2|**autodefense**|Custom (`docker-autodefense`, built from Python 3.10-slim)|`host`|NET\_ADMIN|`../src:/app/src:ro`<br>`../models:/app/models:ro`<br>`../logs:/app/logs`<br>`../configs:/app/configs`<br>`../logs/suricata:/app/logs/suricata:ro`<br>`/etc/localtime:/etc/localtime:ro`|NFStream live sniff + 15-feature extraction; ML inference (2-layer XGBoost); Suricata correlation; iptables auto-block; Push logs → Loki|
|3|**nginx** (reverse-proxy)|Custom (`docker-nginx`, built from nginx:alpine)|bridge (`idps\_net`)|—|—|Reverse proxy (HTTP→HTTPS redirect); SSL termination; Proxy `X-Forwarded-For` header cho Suricata real IP parsing. **⚠️ Hiện đang Exited**|
|4|**juice-shop**|bkimminich/juice-shop:latest|bridge (`idps\_net`)|—|—|Vulnerable Web Application (OWASP Juice Shop) — mục tiêu tấn công Layer 7 để test detection|
|5|**loki**|grafana/loki:latest|default (port mapping)|—|`./loki/data:/loki`|Lưu trữ log + event từ autodefense|
|6|**grafana**|grafana/grafana:latest|default (port mapping)|—|`./grafana/data:/var/lib/grafana`<br>`./grafana/provisioning:/etc/grafana/provisioning`|Dashboard realtime (auto-refresh); hiển thị attack events, ML probabilities|

**docker-compose.yml** nằm tại `docker/docker-compose.yml`.

**Network Architecture:**

```
┌─────────────────────────────────────────────────────┐
│  Docker Host (Ubuntu 24.04 LTS - 192.168.226.151)   │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐                 │
│  │  suricata     │  │  autodefense │   host network  │
│  │  (host net)   │  │  (host net)  │                 │
│  └──────┬───────┘  └──────┬───────┘                 │
│         │ ens33 + br-idps │ ens33                   │
│         │                 │                          │
│  ┌──────┴────────────────┴──────┐                   │
│  │        br-idps (bridge)       │                   │
│  │  ┌─────────┐  ┌────────────┐ │                   │
│  │  │  nginx   │  │ juice-shop │ │  idps\_net         │
│  │  │ :80/:443 │  │   :3001    │ │                   │
│  │  └─────────┘  └────────────┘ │                   │
│  └──────────────────────────────┘                   │
│                                                     │
│  ┌──────────┐  ┌──────────┐                         │
│  │   loki   │  │  grafana  │   port mapping          │
│  │  :3100   │  │  :3000    │   → 192.168.226.151     │
│  └──────────┘  └──────────┘                         │
└─────────────────────────────────────────────────────┘
```

\---

### 1\. Tech Stack (Zero-Touch Architecture)

**Containerization \& Orchestration:**

* Docker 29.1.3
* Docker Compose v2.40.3
* Custom Dockerfiles cho suricata, autodefense, nginx

**Hệ điều hành / Môi trường:**

* Host: Ubuntu Server 24.04.4 LTS Noble Numbat (kernel 6.8.0-111-generic, chạy Docker)
* Container suricata: Ubuntu 22.04 + Suricata (PPA oisf/suricata-stable)
* Container autodefense: Python 3.10-slim + NFStream, scikit-learn, XGBoost, Pandas, NumPy, joblib, watchdog, python-logging-loki
* Container nginx: nginx:alpine + openssl (self-signed certs)
* Container juice-shop: bkimminich/juice-shop:latest (OWASP Juice Shop)

**Cảm biến Mạng:**

* **Suricata** (container `suricata`) — Signature-based IDS + custom Layer 7 rules, sinh EVE JSON alerts, X-Forwarded-For parsing
* **NFStream** (trong container `autodefense`) — Live flow meter, trích xuất 15 statistical features

**Automation Engine / Machine Learning:**

* Python service trong container `autodefense`
* 2-layer XGBoost: Binary classifier (`active\_model.pkl`) + Multi-class classifier (`classification\_model.pkl`)
* LabelEncoder (`label\_encoder.pkl`) để decode class names
* Suricata Correlator (`suricata\_correlator.py`) — Layer 7 DPI correlation

**Tự động hóa Ngăn chặn:**

* `iptables` (thực thi từ bên trong container `autodefense` với CAP NET\_ADMIN)
* IP Manager (`ip\_manager.py`) — Blacklist/Whitelist management với JSON persistence

**Giám sát / Cảnh báo:** Loki + Grafana (official Docker images) + `python-logging-loki`

\---

### 2\. Project Structure (Thực tế trên VM: `/home/dmtien/IDPS/`)

> **Lưu ý:** Cấu trúc dưới đây phản ánh chính xác trạng thái triển khai trên máy ảo Ubuntu.
> Các thư mục `Guide_line/`, `results/`, `datasets/` chỉ tồn tại trên workspace phát triển (máy thật), **KHÔNG** có trên VM.
> Thư mục `datasets/` trên VM tồn tại nhưng **rỗng** (dữ liệu training chỉ dùng offline trên máy thật).

```text
/home/dmtien/IDPS/
│
├── docker/                              # ← THƯ MỤC DOCKER (docker-compose root)
│   ├── docker-compose.yml               # Orchestrate 6 services
│   ├── suricata/
│   │   ├── Dockerfile                   # Ubuntu 22.04 + Suricata PPA
│   │   ├── patch\_config.sh              # Patch suricata.yaml (HOME\_NET, XFF, custom rules)
│   │   └── custom-rules/
│   │       └── local.rules              # Custom Layer 7 detection rules (SQL Injection, XSS, ...)
│   ├── autodefense/
│   │   ├── Dockerfile                   # Python 3.10-slim + libpcap-dev + iptables
│   │   ├── requirements.txt             # nfstream, xgboost, scikit-learn, pandas, numpy, ...
│   │   └── entrypoint.sh               # Entrypoint: check mount → chạy autodefense\_daemon.py
│   ├── nginx/
│   │   ├── Dockerfile                   # nginx:alpine + openssl
│   │   ├── nginx.conf                   # Reverse proxy config (HTTP→HTTPS, X-Forwarded-For)
│   │   └── entrypoint.sh               # Generate self-signed certs + start nginx
│   ├── loki/
│   │   └── data/                        # Loki persistent data (WAL, TSDB index, chunks)
│   ├── grafana/
│   │   ├── data/                        # Grafana persistent data
│   │   └── provisioning/
│   │       ├── dashboards/
│   │       │   ├── provider.yml          # Dashboard provider config
│   │       │   └── json/
│   │       │       └── idps\_dashboard.json  # Auto-provisioned IDPS dashboard
│   │       └── datasources/
│   │           └── loki.yml             # Loki datasource (http://loki:3100)
│   └── logs/                            # Docker-local logs (loki-data)
│
├── src/                                 # Source code (mounted read-only vào autodefense)
│   ├── autodefense\_daemon.py            # CORE daemon — pipeline xử lý flow (15.5 KB)
│   ├── realtime\_extractor.py            # NFStream → 15-feature vector (8.3 KB)
│   ├── threat\_evaluator.py              # ML inference: binary + multiclass XGBoost (11.9 KB)
│   ├── auto\_firewall.py                 # iptables auto-block (8 KB)
│   ├── ip\_manager.py                    # Blacklist/Whitelist management (7.1 KB)
│   └── suricata\_correlator.py           # Suricata EVE JSON correlation engine (18 KB)
│
├── models/                              # ML models (mounted read-only vào autodefense)
│   ├── active\_model.pkl                 # XGBoost binary classifier — Attack/Benign (612 KB)
│   ├── classification\_model.pkl         # XGBoost multiclass classifier — 6 classes (2.6 MB)
│   └── label\_encoder.pkl                # LabelEncoder cho multiclass (562 B)
│
├── configs/                             # Cấu hình (mounted read-write vào autodefense)
│   ├── thresholds.json                  # Confidence thresholds (auto\_block, alert, correlation)
│   ├── whitelist.json                   # Trusted IPs (admin, gateway, internal services)
│   └── blacklist.json                   # Auto-blocked IPs (ML detection + manual)
│
├── logs/                                # Logs runtime
│   ├── action\_audit.log                 # JSON-line log các sự kiện AUTO\_BLOCKED (~36 KB)
│   ├── autodefense.log                  # System log của daemon (~13 MB, growing)
│   ├── suricata/                        # Shared volume với container suricata
│   │   ├── eve.json                     # EVE JSON alerts (~225 MB, primary log)
│   │   ├── fast.log                     # Fast alert log (~320 KB)
│   │   ├── stats.log                    # Performance stats (~121 MB)
│   │   └── suricata.log                 # Suricata engine log (~510 KB)
│   └── loki-data/                       # Loki local cache
│
├── datasets/                            # (RỖNG trên VM — training data chỉ trên máy thật)
│
├── .gitignore                           # Ignore: logs/, datasets/, docker data, __pycache__
├── .gitattributes
├── LICENSE
├── README.md
└── system\_update.sh                     # Script cập nhật hệ thống
```

\---

### 3\. Dockerfiles — Chi tiết từng Container

#### 3.1. Dockerfile — Container `suricata`

```dockerfile
# NOTE: Suricata container dùng Ubuntu 22.04 base image (không phải 24.04 host OS)
FROM ubuntu:22.04

ENV DEBIAN\_FRONTEND=noninteractive

# Cài Suricata từ PPA chính thức
RUN apt-get update \&\& \\
    apt-get install -y software-properties-common wget curl jq \&\& \\
    add-apt-repository ppa:oisf/suricata-stable -y \&\& \\
    apt-get update \&\& \\
    apt-get install -y suricata \&\& \\
    apt-get clean \&\& \\
    rm -rf /var/lib/apt/lists/\*

# Cập nhật ET Open ruleset
RUN suricata-update

# Thêm custom rules cho Web Attack (Layer 7)
COPY custom-rules/ /etc/suricata/rules/custom/
COPY patch\_config.sh /patch\_config.sh
RUN chmod +x /patch\_config.sh \&\& /patch\_config.sh

ENV IFACE=ens33

CMD \["sh", "-c", "suricata -c /etc/suricata/suricata.yaml -i $IFACE"]
```

**patch\_config.sh** thực hiện:

* Cập nhật HOME\_NET: `\[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]`
* Enable X-Forwarded-For parsing (mode: overwrite) — quan trọng cho Reverse Proxy
* Thêm custom rules path: `/etc/suricata/rules/custom/local.rules`
* Enable drop alerts

#### 3.2. Dockerfile — Container `autodefense`

```dockerfile
FROM python:3.10-slim

# libpcap-dev là dependency bắt buộc của NFStream; iptables để auto-block
RUN apt-get update \&\& \\
    apt-get install -y iptables iproute2 libpcap-dev gcc \&\& \\
    apt-get clean \&\& \\
    rm -rf /var/lib/apt/lists/\*

WORKDIR /app

# Copy requirements và cài đặt
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Script khởi chạy
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT \["/app/entrypoint.sh"]
```

**requirements.txt:**

```
nfstream
scikit-learn>=1.2.0
xgboost>=1.7.0
pandas>=1.5.0
numpy>=1.23.0
joblib>=1.2.0
watchdog>=3.0.0
python-logging-loki
```

**entrypoint.sh:**

```bash
#!/bin/bash
if \[ ! -f "/app/src/autodefense\_daemon.py" ]; then
  echo "ERROR: /app/src/autodefense\_daemon.py not found!"
  echo "Vui lòng mount volume đúng cách: ./src:/app/src"
  tail -f /dev/null
fi
echo "Starting Autodefense Daemon..."
exec python3 /app/src/autodefense\_daemon.py
```

> \*\*Lưu ý:\*\* Source code KHÔNG được COPY vào image. Thay vào đó, được mount qua Docker volumes (`../src:/app/src:ro`) để dễ dàng cập nhật code mà không cần rebuild image.

#### 3.3. Dockerfile — Container `nginx` (Reverse Proxy)

```dockerfile
FROM nginx:alpine

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT \["/entrypoint.sh"]
```

**nginx.conf** cấu hình:

* HTTP (port 80) → redirect HTTPS (port 443)
* SSL termination với self-signed certificates
* Reverse proxy đến `juice-shop` (port 3001 trên host)
* **Quan trọng:** Truyền `X-Forwarded-For`, `X-Real-IP` header cho Suricata parsing real client IP

\---

### 4\. Data Model \& Automated Core Logic

#### Vai trò của từng thành phần

|Thành phần|Vai trò|Ghi chú|
|-|-|-|
|**Suricata**|Signature-based detection + EVE JSON alerts + Custom Layer 7 rules|KHÔNG dùng để trích xuất 15 features ML|
|**NFStream**|Live flow meter — trích xuất 15 statistical features|Chạy trong container `autodefense`, sniff cùng interface (host network)|
|**realtime\_extractor.py**|Map NFStream output → 15-feature NumPy array (A-Z sorted, µs units)|V2: thêm SYN/FIN/RST/PSH flags, Port\_Conn\_Rate|
|**threat\_evaluator.py**|ML inference: binary (Attack?) + multiclass (loại tấn công?)|2-layer XGBoost + LabelEncoder|
|**suricata\_correlator.py**|Correlation Engine: kết hợp Suricata alerts + ML predictions|Background thread tail EVE JSON, tính risk score|
|**ip\_manager.py**|Quản lý Blacklist/Whitelist IP (in-memory + JSON persistence)|O(1) lookup mỗi flow, thread-safe|
|**auto\_firewall.py**|`iptables -I INPUT -s {IP} -j DROP`|Trigger khi confidence > auto\_block\_threshold|
|**autodefense\_daemon.py**|Core daemon — orchestrate toàn bộ pipeline|Entry point chính của container autodefense|

#### 4.1. Vector Đặc trưng — 15 Features (NFStream V3, A-Z Sorted)

NFStream sniff live interface → tính 15 statistical features per flow → NumPy array 1D đẩy thẳng vào ML model.

> **QUAN TRỌNG:** CIC-IDS-2017 dùng MICROSECONDS (µs), NFStream trả về MILLISECONDS (ms) → cần nhân ×1000 để chuyển đổi.

|#|Feature|NFStream Field / Tính toán|Đơn vị|
|-|-|-|-|
|0|ACK Flag Count|`bidirectional\_ack\_packets`|count|
|1|Bwd IAT Max|`dst2src\_max\_piat\_ms × 1000`|µs|
|2|Bwd IAT Std|`dst2src\_stddev\_piat\_ms × 1000`|µs|
|3|Bwd Packet Length Mean|`dst2src\_mean\_ps`|bytes|
|4|Bwd Packet Length Std|`dst2src\_stddev\_ps`|bytes|
|5|Bwd Packets/s|`dst2src\_packets / duration\_s\_safe`|pkts/s|
|6|Flow Bytes/s|`bidirectional\_bytes / duration\_s\_safe`|bytes/s|
|7|Fwd IAT Min|`src2dst\_min\_piat\_ms × 1000`|µs|
|8|Fwd Packet Length Max|`src2dst\_max\_ps`|bytes|
|9|Fwd Packet Length Mean|`src2dst\_mean\_ps`|bytes|
|10|Fwd Packet Length Std|`src2dst\_stddev\_ps`|bytes|
|11|PSH Flag Count|`bidirectional\_psh\_packets`|count|
|12|Packet Length Mean|`bidirectional\_mean\_ps`|bytes|
|13|Total Fwd Packets|`src2dst\_packets`|count|
|14|Total Length of Fwd Packets|`src2dst\_bytes`|bytes|

> **Thay đổi V3 (2026-06-22):** Chốt bộ 15 đặc trưng tối ưu thông qua Bayesian Optimization và Cross-Validation, loại bỏ các đặc trưng thừa để giảm chiều từ 30 → 15 nhằm tăng tốc độ phản hồi và độ chính xác.

#### 4.2. Thông tin để Block IP/Session

Tất cả thông tin cần thiết cho `iptables` đều có sẵn từ NFStream flow object:

|Thông tin|NFStream Field|Dùng để|
|-|-|-|
|Source IP|`flow.src\_ip`|`iptables -I INPUT -s {src\_ip} -j DROP`|
|Destination IP|`flow.dst\_ip`|Xác định target|
|Source Port|`flow.src\_port`|Block cụ thể session|
|Destination Port|`flow.dst\_port`|Block theo service|
|Protocol|`flow.protocol`|TCP/UDP/ICMP|
|Flow ID|`flow.id`|Session tracking|
|Timestamp|`flow.bidirectional\_first\_seen\_ms`|Logging|

#### 4.3. Confidence Thresholds (configs/thresholds.json)

```json
{
    "description": "Confidence thresholds for autonomous decision engine",
    "auto\_block\_threshold": 0.85,
    "alert\_threshold": 0.60,
    "whitelist\_alert\_threshold": 0.85,
    "suricata\_override\_severity": 3,
    "suricata\_correlation\_boost": 0.15,
    "suricata\_auto\_block\_on\_critical": true,
    "suricata\_only\_max\_score": 0.30
}
```

|Threshold|Giá trị|Mô tả|
|-|-|-|
|`auto\_block\_threshold`|0.85|Score > 0.85 → AUTO\_BLOCK (iptables DROP)|
|`alert\_threshold`|0.60|Score > 0.60 → SUSPICIOUS (log warning, không block)|
|`suricata\_only\_max\_score`|0.30|Hard cap cho correlation khi ML nói Benign|
|`suricata\_auto\_block\_on\_critical`|true|Suricata DROP action → override ML decision|

#### 4.4. Automated Action Log (Đẩy lên Loki)

```json
{
  "timestamp": "2026-05-28T15:00:00+00:00",
  "attacker\_ip": "192.168.226.55",
  "target\_port": 22,
  "ml\_confidence\_score": 0.98,
  "predicted\_threat": "Brute Force",
  "system\_action": "AUTO\_BLOCKED",
  "response\_time\_ms": 45.2
}
```

Log được ghi đồng thời vào:

1. **action\_audit.log** — JSON-line format (file cục bộ)
2. **Loki** — qua `python-logging-loki` handler (remote)
3. **autodefense.log** — structured text log (file cục bộ)

\---

### 5\. Event-Driven Flow (Automated Core Logic)

Hệ thống hoạt động theo luồng Event-Driven hoàn toàn tự động:

```
Network traffic vào host (ens33)
     │
     ├──→ Suricata container (--network host, lắng nghe ens33 + br-idps):
     │       Signature-based detection (ET Open + Custom Layer 7 rules)
     │       → EVE JSON alerts → shared volume ../logs/suricata/eve.json
     │       → X-Forwarded-For parsing (real client IP from nginx reverse proxy)
     │
     ├──→ nginx container (bridge: idps\_net, port 80/443):
     │       HTTP → HTTPS redirect
     │       SSL termination + Reverse proxy → juice-shop (:3001)
     │       → Inject X-Forwarded-For, X-Real-IP headers
     │
     ├──→ juice-shop container (bridge: idps\_net, port 3001):
     │       OWASP Juice Shop (vulnerable web app for L7 attack testing)
     │
     └──→ autodefense container (--network host):
           │
           ├── NFStream sniff cùng interface (ens33)
           │       → statistical\_analysis=True
           │       → TCPWindowPlugin + ConnectionRatePlugin (custom NFPlugins)
           │       → Extract 15 features per flow (A-Z sorted, µs units)
           │
           ├── autodefense\_daemon.py — Core Pipeline per flow:
           │   │
           │   ├── Bước 1: Check Blacklist (IPManager)
           │   │       → Nếu đã bị block → re-enforce iptables DROP, skip ML
           │   │
           │   ├── Bước 2: Check Whitelist (IPManager)
           │   │       → Nếu trusted IP → bypass ML inference hoàn toàn
           │   │
           │   ├── Bước 3: Feature Extraction + ML Inference
           │   │       → realtime\_extractor.extract\_features(flow) → \[15 features]
           │   │       → threat\_evaluator.evaluate(features):
           │   │           ├── active\_model.pkl → Binary: Attack? (confidence score)
           │   │           └── classification\_model.pkl → Attack type (6 classes)
           │   │
           │   ├── Bước 3.5: Suricata Correlation (Layer 7 DPI)
           │   │       → suricata\_correlator.correlate(src\_ip, dst\_port, ml\_type, ml\_score)
           │   │       → Fusion: final\_confidence = ML score + correlation\_score
           │   │       → Suricata DROP override nếu custom rule critical
           │   │
           │   ├── Bước 4: Autonomous Decision Engine
           │   │       score > 0.85 → AUTO\_BLOCK
           │   │       score > 0.60 → SUSPICIOUS (log only)
           │   │       score ≤ 0.60 → BENIGN
           │   │
           │   ├── auto\_firewall.py:
           │   │       iptables -I INPUT -s {src\_ip} -j DROP
           │   │       + Thêm IP vào blacklist.json (persistent)
           │   │
           │   └── Push structured event → Loki (python-logging-loki)
           │           + Ghi action\_audit.log (JSON-line format)
           │
           └── Loki + Grafana:
                   Loki (:3100) ← nhận log từ autodefense
                   Grafana (:3000) ← Dashboard, LogQL queries
```

\---

### 6\. `realtime\_extractor.py` — Implementation Reference (V2)

```python
from nfstream import NFStreamer, NFPlugin
import numpy as np

class ConnectionTracker:
    """Sliding window tracker để đếm connection rate per IP/port."""
    def \_\_init\_\_(self, window\_sec=10):
        self.window\_sec = window\_sec
        self.history = {}  # src\_ip → {dst\_port: \[timestamps]}

    def add\_and\_count(self, src\_ip, dst\_port, current\_time\_sec):
        if src\_ip not in self.history:
            self.history\[src\_ip] = {}
        if dst\_port not in self.history\[src\_ip]:
            self.history\[src\_ip]\[dst\_port] = \[]
        timestamps = self.history\[src\_ip]\[dst\_port]
        timestamps.append(current\_time\_sec)
        cutoff = current\_time\_sec - self.window\_sec
        valid\_timestamps = \[ts for ts in timestamps if ts > cutoff]
        self.history\[src\_ip]\[dst\_port] = valid\_timestamps
        return len(valid\_timestamps)

class ConnectionRatePlugin(NFPlugin):
    def on\_init(self, packet, flow):
        current\_time\_sec = packet.time / 1000.0
        flow.udps.conn\_rate = self.tracker.add\_and\_count(
            flow.src\_ip, flow.dst\_port, current\_time\_sec
        )

class TCPWindowPlugin(NFPlugin):
    """Custom plugin để lấy TCP window size."""
    def on\_init(self, packet, flow):
        flow.udps.init\_win\_fwd = 0
        flow.udps.init\_win\_bwd = 0
        flow.udps.is\_first\_packet = True

    def on\_update(self, packet, flow):
        if flow.udps.is\_first\_packet and packet.direction == 0:
            flow.udps.init\_win\_fwd = packet.ip\_size
            flow.udps.is\_first\_packet = False
        if packet.direction == 1 and flow.udps.init\_win\_bwd == 0:
            flow.udps.init\_win\_bwd = packet.ip\_size


def create\_streamer(interface="ens33", conn\_tracker=None):
    plugins = \[TCPWindowPlugin()]
    if conn\_tracker is not None:
        plugins.append(ConnectionRatePlugin(tracker=conn\_tracker))

    return NFStreamer(
        source=interface,
        statistical\_analysis=True,   # Bật 48 statistical features
        accounting\_mode=0,           # Link layer
        udps=plugins,
        idle\_timeout=10,
        active\_timeout=30,
    )


def extract\_features(flow) -> np.ndarray:
    """Map NFStream flow → 15-feature vector theo thứ tự A-Z (khớp với training).

    LƯU Ý: CIC-IDS-2017 dùng µs, NFStream trả ms → nhân ×1000.
    """
    duration_s_safe = max(flow.bidirectional_duration_ms / 1000.0, 0.001)

    return np.array([
        flow.bidirectional\_ack\_packets,                              # 0:  ACK Flag Count
        flow.dst2src\_max\_piat\_ms * 1000.0,                          # 1:  Bwd IAT Max (µs)
        flow.dst2src\_stddev\_piat\_ms * 1000.0,                       # 2:  Bwd IAT Std (µs)
        flow.dst2src\_mean\_ps,                                        # 3:  Bwd Packet Length Mean
        flow.dst2src\_stddev\_ps,                                      # 4:  Bwd Packet Length Std
        flow.dst2src\_packets / duration_s_safe,                       # 5:  Bwd Packets/s
        flow.bidirectional\_bytes / duration_s_safe,                   # 6:  Flow Bytes/s
        flow.src2dst\_min\_piat\_ms * 1000.0,                          # 7:  Fwd IAT Min (µs)
        flow.src2dst\_max\_ps,                                         # 8:  Fwd Packet Length Max
        flow.src2dst\_mean\_ps,                                        # 9:  Fwd Packet Length Mean
        flow.src2dst\_stddev\_ps,                                      # 10: Fwd Packet Length Std
        flow.bidirectional\_psh\_packets,                              # 11: PSH Flag Count
        flow.bidirectional\_mean\_ps,                                  # 12: Packet Length Mean
        flow.src2dst\_packets,                                        # 13: Total Fwd Packets
        flow.src2dst\_bytes,                                          # 14: Total Length of Fwd Packets
    ], dtype=np.float64)
```

\---

### 7\. Phased Implementation (Lộ trình Dockerized)

**Phase 0: Docker Infrastructure Setup** ✅ Done

* Cài Docker + Docker Compose trên Ubuntu Server VM
* Tạo thư mục `docker/` và các Dockerfile
* Viết `docker-compose.yml` với 6 services (suricata, autodefense, nginx, juice-shop, loki, grafana)
* Thiết lập Docker network `idps\_net` (bridge) với custom bridge name `br-idps`
* Build \& test: `docker compose up -d`

**Phase 1: Tiền xử lý dữ liệu** ✅ Done

Tiền xử lý dataset CIC-IDS2017:

* Gộp nhãn tương đồng:

  * PortScan → PortScan
  * DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS → DoS/DDoS
  * Web Attack - Brute Force, Web Attack - XSS, Web Attack - Sql Injection → Web Attack
  * FTP-Patator, SSH-Patator → Brute Force
  * Bot → Botnet
  * Infiltration, Heartbleed → Loại bỏ khỏi dataset (map sang Unknown)
* Xử lý class imbalance (imblearn):

  * Không undersample trong Preprocessing để tránh Data Leakage
  * Áp dụng SMOTE x10 động trong từng Train Fold của Cross-Validation
* 15 features A-Z sorted, chia train/test 80/20

Chạy training: `docker compose run --rm autodefense python src/train_production_models.py`

**Phase 1.5: Xây dựng Bộ não ML (Offline)** ✅ Done

* Huấn luyện 3 algorithms (XGBoost, LightGBM, RandomForest) cho cả Binary và Multiclass
* Đánh giá: Precision, Recall, F1-Score, Confusion Matrix
* Chọn best model → lưu `active\_model.pkl` (Binary XGBoost) và `classification\_model.pkl` (Multiclass XGBoost) + `label\_encoder.pkl`

**Phase 2: Triển khai Cảm biến và Xử lý Luồng (Real-time Detection)** ✅ Done

* Build \& chạy `suricata` container (host network) — signature alerts + custom L7 rules
* Build \& chạy `autodefense` container — **NFStream live sniff** trích xuất 15 features V3
* Build \& chạy `nginx` container — reverse proxy cho juice-shop + X-Forwarded-For
* Build \& chạy `juice-shop` container — vulnerable web app target
* Tích hợp `suricata\_correlator.py` — background thread tail EVE JSON, correlation scoring
* Verify: `docker compose logs -f autodefense`

**Phase 3: Tự động hóa Ngăn chặn (Zero-touch Prevention)** ✅ Done

* Kích hoạt `auto\_firewall.py` + `ip\_manager.py` (Blacklist/Whitelist)
* Pipeline: Blacklist → Whitelist → ML + Suricata Correlation → Auto-Block
* Test: Kali bắn Nmap/Hydra/Web Attacks → autodefense tự động `iptables DROP`

**Phase 4: Tự động hóa Giám sát (Automated Observability)** ✅ Done

* `loki` + `grafana` chạy trong Docker Compose
* `autodefense` push event qua `python-logging-loki`
* Grafana provisioning (auto-datasource + dashboards)
* Dashboard hiển thị: attack events, ML probabilities, blocked IPs

\---

### 8\. docker-compose.yml (Thực tế)

```yaml
services:
  suricata:
    build:
      context: ./suricata
    container\_name: suricata
    network\_mode: 'host'
    cap\_add:
      - NET\_ADMIN
      - NET\_RAW
      - NET\_BIND\_SERVICE
    restart: always
    read\_only: true
    tmpfs:
      - /tmp:size=10M,mode=1777
    environment:
      - IFACE=ens33 -i br-idps
    volumes:
      - ../logs/suricata:/var/log/suricata
    depends\_on:
      - nginx

  autodefense:
    build:
      context: ./autodefense
    container\_name: autodefense
    network\_mode: 'host'
    cap\_add:
      - NET\_ADMIN
    restart: always
    tmpfs:
      - /tmp:size=10M,mode=1777
    volumes:
      - ../src:/app/src:ro
      - ../models:/app/models:ro
      - ../logs:/app/logs
      - ../configs:/app/configs
      - ../logs/suricata:/app/logs/suricata:ro
      - /etc/localtime:/etc/localtime:ro
    depends\_on:
      - loki
      - suricata

  nginx:
    build:
      context: ./nginx
    container\_name: reverse-proxy
    ports:
      - "80:80"
      - "443:443"
    networks:
      - idps\_net

  juice-shop:
    image: bkimminich/juice-shop:latest
    container\_name: juice-shop
    restart: always
    ports:
      - "3001:3000"
    networks:
      - idps\_net

  loki:
    image: grafana/loki:latest
    container\_name: loki
    ports:
      - "192.168.226.151:3100:3100"
    user: "0:0"
    command: -config.file=/etc/loki/local-config.yaml
    restart: always
    volumes:
      - ./loki/data:/loki

  grafana:
    image: grafana/grafana:latest
    container\_name: grafana
    ports:
      - "192.168.226.151:3000:3000"
    restart: always
    environment:
      - GF\_SECURITY\_ADMIN\_PASSWORD=${GRAFANA\_PASSWORD:-admin}
    depends\_on:
      - loki
    volumes:
      - ./grafana/data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning

networks:
  idps\_net:
    driver: bridge
    driver\_opts:
      com.docker.network.bridge.name: br-idps
```

\---

**Cách chạy toàn bộ hệ thống (Zero-Touch):**

```bash
cd IDPS/docker/
docker compose up -d --build
docker compose logs -f autodefense   # theo dõi core daemon + NFStream output
```

**1 lệnh** `docker compose up -d` là toàn bộ hệ thống (Suricata + NFStream + ML + Firewall + Nginx + Juice Shop + Loki + Grafana) tự động khởi động và chạy Zero-Touch.

