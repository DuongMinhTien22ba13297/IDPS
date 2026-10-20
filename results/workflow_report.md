# IDPS Workflow Report

## Tổng quan

Hệ thống **Intrusion Detection and Prevention System (IDPS)** là một giải pháp bảo mật mạng hiện đại với khả năng **Fully Automated / Zero-touch** - tự động phát hiện và ngăn chặn các cuộc tấn công trong thời gian thực mà không cần sự can thiệp của con người.

---

## 1. Kiến trúc Hệ thống

### 1.1. Môi trường Triển khai

| Thành phần | Chi tiết |
|-----------|----------|
| **Host OS** | Ubuntu Server 22.04 LTS (Virtual Machine) |
| **Địa chỉ IP** | 192.168.1.151 |
| **Truy cập** | `ssh dmtien@192.168.1.151` |
| **Containerization** | Docker + Docker Compose v2.x |
| **Network Mode** | `--network host` cho Suricata và AutoDefense |

### 1.2. Multi-Container Architecture

Hệ thống bao gồm **4 container chính** chạy song song:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker Compose Orchestration                  │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   Suricata    │   │ AutoDefense   │   │   Loki        │
│   Container   │   │   Container   │   │   Container   │
│  (--net host) │   │ (--net host)  │   │   (bridge)    │
└───────────────┘   └───────────────┘   └───────────────┘
        │                     │                     │
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                              ▼
                     ┌───────────────┐
                     │   Grafana     │
                     │   Container   │
                     │   (bridge)    │
                     └───────────────┘
```

| STT | Container | Image | Network | Privileges | Mục đích |
|-----|-----------|-------|---------|------------|---------|
| 1 | **suricata** | Custom Ubuntu + Suricata | host | --privileged | Packet capture, signature-based detection |
| 2 | **autodefense** | Python 3.10 + NFStream | host | NET_ADMIN, SYS_ADMIN, privileged | ML inference, auto-block, 30-feature extraction |
| 3 | **loki** | Grafana Loki | bridge | - | Log aggregation |
| 4 | **grafana** | Grafana | bridge | - | Real-time dashboard |

---

## 2. Workflow Chi tiết

### 2.1. Luồng Dữ liệu Tổng quan

```
Network Traffic (ens33)
         │
         ├───► Suricata Container
         │        │
         │        ├──► Signature-based Detection
         │        │    (Emerging Threats rules)
         │        │
         │        └──► EVE JSON Alerts
         │             └──► ./logs/suricata/eve.json
         │
         └───► AutoDefense Container
                  │
                  ├──► NFStream Live Sniff
                  │    │
                  │    ├──► statistical_analysis=True
                  │    ├──► TCPWindowPlugin
                  │    └──► Extract 30 features/flow
                  │
                  ├──► realtime_extractor.py
                  │    │
                  │    └──► NFStream flow → NumPy array [30]
                  │
                  ├──► threat_evaluator.py
                  │    │
                  │    ├──► active_model.pkl → Binary (Attack?)
                  │    └──► classification_model.pkl → Attack Type
                  │
                  ├──► Autonomous Decision Engine
                  │    │
                  │    └──► confidence > 0.85 → AUTO_BLOCK
                  │
                  ├──► auto_firewall.py
                  │    │
                  │    └──► iptables -I INPUT -s {IP} -j DROP
                  │
                  └──► Logging → Loki → Grafana
```

### 2.2. Phase 1: Data Preprocessing & Training

#### 2.2.1. Dataset Processing

**Input:** CIC-IDS2017 dataset

**Processing Steps:**

1. **Label Consolidation** - Gộp các nhãn tương đồng:
   - `PortScan` → `PortScan`
   - `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest`, `DDoS` → `DoS/DDoS`
   - `Web Attack - Brute Force`, `Web Attack - XSS`, `Web Attack - Sql Injection` → `Web Attack`
   - `FTP-Patator`, `SSH-Patator` → `Brute Force`
   - `Bot` → `Botnet`
   - `Infiltration`, `Heartbleed` → `Exploitation/Rare`

2. **Custom Resampling** - Xử lý imbalance:
   - **Undersampling Benign:** Giảm xuống bằng lớp tấn công lớn nhất
   - **Keep Medium:** Giữ nguyên DoS, DDoS
   - **Oversampling Rare:** SMOTE cho Web Attack, Infiltration

3. **Feature Selection:** Chỉ giữ 30 features quan trọng nhất

4. **Train/Test Split:** Tỉ lệ 80/20

#### 2.2.2. Model Training

```bash
docker compose run --rm autodefense python src/offline_training.py
```

**Output Models:**
- `models/active_model.pkl` - XGBoost Binary Classifier (Attack vs Benign)
- `models/classification_model.pkl` - XGBoost Multiclass Classifier (Attack Type)
- `models/label_encoder.pkl` - Label mapping

### 2.3. Phase 2: Real-time Detection

#### 2.3.1. NFStream Feature Extraction

NFStream hoạt động như một **live flow meter** trên network interface:

```python
NFStreamer(
    source="ens33",
    statistical_analysis=True,   # 48 statistical features
    accounting_mode=0,           # Link layer
    udps=TCPWindowPlugin(),      # Custom plugin
    idle_timeout=120,
    active_timeout=1800,
)
```

#### 2.3.2. 30 Statistical Features Mapping

| # | Feature | NFStream Field | Type |
|---|---------|----------------|------|
| 1 | Idle Max | `bidirectional_max_idle` | Native |
| 2 | Idle Mean | `bidirectional_mean_idle` | Native |
| 3 | Flow Duration | `bidirectional_duration_ms / 1000` | Calculated |
| 4 | Idle Min | `bidirectional_min_idle` | Native |
| 5 | Fwd IAT Min | `src2dst_min_piat_ms` | Native |
| 6 | Fwd IAT Total | `src2dst_max_piat_ms * src2dst_packets` | Calculated |
| 7 | Fwd IAT Std | `src2dst_stddev_piat_ms` | Native |
| 8 | Fwd IAT Max | `src2dst_max_piat_ms` | Native |
| 9 | Destination Port | `dst_port` | Native |
| 10 | Flow IAT Max | `bidirectional_max_piat_ms` | Native |
| 11 | Bwd IAT Total | `dst2src_max_piat_ms * dst2src_packets` | Calculated |
| 12 | Bwd IAT Min | `dst2src_min_piat_ms` | Native |
| 13 | Flow IAT Std | `bidirectional_stddev_piat_ms` | Native |
| 14 | Fwd Header Length | `src2dst_bytes - (src2dst_mean_ps * src2dst_packets)` | Calculated |
| 15 | Flow Bytes/s | `bidirectional_bytes / duration_s` | Calculated |
| 16 | Packet Length Std | `bidirectional_stddev_ps` | Native |
| 17 | Mean Payload Size | `bidirectional_mean_ps` | Native |
| 18 | Bwd IAT Std | `dst2src_stddev_piat_ms` | Native |
| 19 | Bwd Mean Segment Size | `dst2src_mean_ps` | Native |
| 20 | Fwd Mean IAT | `src2dst_mean_piat_ms` | Native |
| 21 | Init_Win_bytes_forward | `udps.init_win_fwd` | NFPlugin |
| 22 | Init_Win_bytes_backward | `udps.init_win_bwd` | NFPlugin |
| 23 | ACK Flag Count | `bidirectional_ack_packets` | Native |
| 24 | Flow Packets/s | `bidirectional_packets / duration_s` | Calculated |
| 25 | Fwd Packet Length Max | `src2dst_max_ps` | Native |
| 26 | Total Length of Fwd Packets | `src2dst_bytes` | Native |
| 27 | Total Length of Bwd Packets | `dst2src_bytes` | Native |
| 28 | Fwd Packets/s | `src2dst_packets / duration_s` | Calculated |
| 29 | Packet Length Mean | `bidirectional_mean_ps` | Native |
| 30 | Bwd Packet Length Mean | `dst2src_mean_ps` | Native |

### 2.4. Phase 3: ML Inference & Decision Making

#### 2.4.1. Binary Classification (Attack Detection)

```
Input: NumPy array [30 features]
         │
         ▼
    active_model.pkl (XGBoost)
         │
         ▼
    Output: [probability_attack, probability_benign]
         │
         ▼
    Decision: confidence_score = max(probability_attack)
```

#### 2.4.2. Multiclass Classification (Attack Type)

```
Input: NumPy array [30 features]
         │
         ▼
    classification_model.pkl (XGBoost)
         │
         ▼
    Output: [prob_portscan, prob_dos, prob_web_attack, ...]
         │
         ▼
    Decision: predicted_class = argmax(probabilities)
```

#### 2.4.3. Autonomous Decision Engine

```python
if confidence_score > 0.85:
    action = "AUTO_BLOCK"
    execute_firewall_block(src_ip, dst_port)
elif confidence_score > 0.70:
    action = "ALERT_ONLY"
    log_threat_event()
else:
    action = "IGNORE"
```

### 2.5. Phase 4: Automated Prevention

#### 2.5.1. Auto Firewall Block

```python
# auto_firewall.py
def block_ip(src_ip, dst_port=None):
    cmd = f"iptables -I INPUT -s {src_ip} -j DROP"
    if dst_port:
        cmd = f"iptables -I INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP"
    execute_with_privileges(cmd)
```

**Response Time:** < 100ms từ khi phát hiện đến khi block

#### 2.5.2. Action Log Format

```json
{
  "timestamp": "2026-04-27T15:00:00Z",
  "attacker_ip": "192.168.1.55",
  "target_port": 22,
  "ml_confidence_score": 0.98,
  "predicted_threat": "SSH Brute-force",
  "system_action": "AUTO_BLOCKED",
  "response_time_ms": 45
}
```

### 2.6. Phase 5: Observability & Monitoring

#### 2.6.1. Log Aggregation (Loki)

```
AutoDefense Container
         │
         ▼
    python-logging-loki
         │
         ▼
    Loki Container (./loki/data)
         │
         ▼
    LogQL Queries
```

#### 2.6.2. Grafana Dashboard

- **Auto-refresh:** 5 seconds
- **Panels:**
  - Live Attack Map
  - Attack Type Distribution
  - Top Attacker IPs
  - Blocked Sessions Timeline
  - ML Confidence Score Distribution

---

## 3. Component Interactions

### 3.1. Suricata ↔ AutoDefense Correlation

```
Suricata EVE JSON                    NFStream Flow
┌─────────────────┐                ┌─────────────────┐
│ src_ip: 1.2.3.4 │                │ src_ip: 1.2.3.4 │
│ dst_port: 22    │                │ dst_port: 22    │
│ alert: SSH      │                │ duration: 5s    │
│                 │                │ packets: 150    │
└─────────────────┘                └─────────────────┘
         │                                  │
         └──────────┬───────────────────────┘
                    ▼
            Correlation Engine
                    │
                    ▼
        Enhanced Detection Context
```

### 3.2. Container Communication

```
┌─────────────────────────────────────────────────────────────┐
│                    Host Network (192.168.1.151)             │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Suricata   │  │ AutoDefense  │  │   Docker     │      │
│  │   (host)     │  │   (host)     │  │   Network    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │             │
│         └──────────────────┼──────────────────┘             │
│                            │                                │
│                    ┌───────▼───────┐                        │
│                    │ Shared Volume │                        │
│                    │ ./logs/       │                        │
│                    └───────────────┘                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ Docker Network  │
                    │   (bridge)      │
                    │                 │
                    │  ┌───────────┐  │
                    │  │   Loki    │  │
                    │  └───────────┘  │
                    │  ┌───────────┐  │
                    │  │  Grafana  │  │
                    │  └───────────┘  │
                    └─────────────────┘
```

---

## 4. Deployment Workflow

### 4.1. Initial Setup

```bash
# 1. Clone repository
git clone <repo-url>
cd IDPS

# 2. Build and start all containers
cd docker/
docker compose up -d --build

# 3. Verify containers running
docker compose ps

# 4. View logs
docker compose logs -f autodefense
```

### 4.2. Training Workflow

```bash
# Run training inside autodefense container
docker compose run --rm autodefense python src/offline_training.py

# Verify models created
ls -lh ../models/
```

### 4.3. Production Workflow

```bash
# Start all services
docker compose up -d

# Monitor in real-time
docker compose logs -f autodefense

# Check firewall rules
docker compose exec autodefense iptables -L -n

# View Grafana
# Open browser: http://192.168.1.151:3000
```

### 4.4. Maintenance Workflow

```bash
# Stop all services
docker compose down

# Update models
docker compose run --rm autodefense python src/offline_training.py

# Restart with new models
docker compose up -d

# View specific container logs
docker compose logs -f suricata
docker compose logs -f loki
```

---

## 5. Performance Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| Detection Latency | < 50ms | From packet capture to ML inference |
| Block Response Time | < 100ms | From detection to iptables DROP |
| Feature Extraction | < 10ms/flow | NFStream statistical analysis |
| False Positive Rate | < 1% | XGBoost with tuned threshold |
| Dashboard Refresh | 5s | Grafana auto-refresh |
| Log Retention | 7 days | Loki default |

---

## 6. Security Considerations

### 6.1. Container Privileges

| Container | Required Privileges | Reason |
|-----------|---------------------|--------|
| suricata | `--privileged` | Raw packet capture |
| autodefense | `NET_ADMIN`, `SYS_ADMIN`, `--privileged` | iptables manipulation, NFStream sniffing |
| loki | None | Log storage only |
| grafana | None | Dashboard only |

### 6.2. Network Isolation

- Suricata & AutoDefense use `--network host` for packet visibility
- Loki & Grafana use bridge network for isolation
- No exposed ports except Grafana (3000)

### 6.3. Data Protection

- Logs stored in `./logs/` with appropriate permissions
- Models encrypted at rest (optional)
- No sensitive data in container images

---

## 7. Troubleshooting

### 7.1. Common Issues

| Issue | Solution |
|-------|----------|
| Container won't start | Check `docker compose logs` |
| NFStream can't sniff interface | Verify interface name with `ip link` |
| iptables rules not applying | Check container has `--privileged` |
| Models not loading | Verify `models/` volume mount |
| Grafana can't connect to Loki | Check Docker network connectivity |

### 7.2. Debug Commands

```bash
# Check all container logs
docker compose logs

# Check specific container
docker compose logs autodefense

# Enter container for debugging
docker compose exec autodefense bash

# Check iptables rules
docker compose exec autodefense iptables -L -n -v

# Check network interfaces
docker compose exec autodefense ip link show

# Test NFStream manually
docker compose exec autodefense python3 -c "from nfstream import NFStreamer; print('OK')"
```

---

## 8. Future Enhancements

### 8.1. Planned Features

- [ ] Integration with SIEM (Elasticsearch + Kibana)
- [ ] Threat intelligence feeds integration
- [ ] Automated incident response playbooks
- [ ] Multi-interface support
- [ ] Distributed deployment (multiple sensors)

### 8.2. ML Improvements

- [ ] Online learning (model updates in production)
- [ ] Ensemble models (XGBoost + Deep Learning)
- [ ] Anomaly detection (unsupervised)
- [ ] Explainable AI (SHAP values)

---

## 9. Summary

Hệ thống IDPS này cung cấp một giải pháp bảo mật mạng **fully automated** với các đặc điểm chính:

1. **Zero-touch Operation:** Tự động phát hiện và block mà không cần can thiệp thủ công
2. **Multi-layer Detection:** Kết hợp signature-based (Suricata) và ML-based (XGBoost)
3. **Real-time Response:** Phản hồi < 100ms
4. **Comprehensive Monitoring:** Loki + Grafana dashboard
5. **Containerized Deployment:** Docker Compose cho dễ dàng scale và maintain

Workflow từ packet capture đến auto-block diễn ra hoàn toàn tự động, đảm bảo hệ thống luôn được bảo vệ 24/7.
