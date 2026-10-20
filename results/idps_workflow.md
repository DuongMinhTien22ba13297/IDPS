# 🛡️ IDPS System — Workflow Toàn Bộ

> **Cập nhật lần cuối:** 2026-05-28T21:02 ICT  
> **Đồng bộ từ VM:** `dmtien@192.168.226.151`  
> **Source files:** `src/autodefense_daemon.py`, `src/threat_evaluator.py`, `src/suricata_correlator.py`, `src/auto_firewall.py`, `configs/thresholds.json`

---

## 1. Kiến Trúc Tổng Quan

Hệ thống có **3 luồng** hoạt động song song trong Docker container:

```mermaid
flowchart TB
    subgraph CONFIG["⚙️ KHỞI TẠO (main)"]
        THR_JSON["configs/thresholds.json"]
        TE_INIT["ThreatEvaluator.__init__()"]
        SC_INIT["SuricataCorrelator.__init__()"]

        THR_JSON -- "_load_thresholds()" --> TE_INIT
        TE_INIT -- "evaluator.suricata_only_max_score" --> SC_INIT
    end

    subgraph INPUT["📡 NGUỒN ĐẦU VÀO"]
        NIC["Network Interface\n(ens33)"]
        EVE["Suricata eve.json\n/app/logs/suricata/eve.json"]
    end

    subgraph DAEMON["🔄 autodefense_daemon.py — Main Thread"]
        NFStream["NFStreamer\n(per-flow capture)"]
        PIPELINE["process_flow()"]
    end

    subgraph CORRELATOR["🔍 suricata_correlator.py — Background Thread"]
        READER["_read_alerts_loop()\npoll every 500ms"]
        CACHE["In-Memory Cache\nDict[IP → deque of alerts]\nTTL: 5 phút, max 50/IP"]
        CLEANUP["_cleanup_expired_alerts()"]
    end

    subgraph OUTPUT["📤 ĐẦU RA"]
        IPTABLES["iptables DROP"]
        LOKI["Grafana / Loki"]
        AUDIT["action_audit.log"]
    end

    CONFIG -.-> DAEMON
    CONFIG -.-> CORRELATOR

    NIC --> NFStream --> PIPELINE
    EVE --> READER --> CACHE
    CACHE --> CLEANUP
    PIPELINE -. "correlate(src_ip)" .-> CACHE

    PIPELINE --> IPTABLES
    PIPELINE --> LOKI
    PIPELINE --> AUDIT
```

---

## 2. Pipeline Xử Lý Chi Tiết (process_flow)

```mermaid
flowchart TD
    START(["🌐 Flow mới từ NFStreamer"])
    START --> IPV4_CHECK

    IPV4_CHECK{"IPv6 hoặc\n0.0.0.0?"}
    IPV4_CHECK -- "Có" --> SKIP_IP(["🚫 return"])
    IPV4_CHECK -- "Không" --> BL

    BL{"Bước 1\nis_blacklisted(src_ip)?"}
    BL -- "CÓ" --> REBLOCK["firewall.block_ip()\nreason=BLACKLISTED_RECHECK"]
    REBLOCK --> BL_OUT(["⛔ LOG: BLACKLISTED_DROP\nreturn"])
    BL -- "KHÔNG" --> WL

    WL{"Bước 2\nis_whitelisted(src_ip)?"}
    WL -- "CÓ" --> WL_OUT(["✅ LOG: BENIGN bypassed\nreturn"])
    WL -- "KHÔNG" --> FE

    FE["Bước 3a: Feature Extraction\nextract_features(flow)\n→ numpy array shape (30,)"]
    FE --> FE_CHECK{"len == 30?"}
    FE_CHECK -- "Không" --> FE_SKIP(["⚠️ skip"])
    FE_CHECK -- "Có" --> ML

    ML["Bước 3b: ML Inference\nevaluator.evaluate(features)\n→ result dict"]
    ML --> CORR

    CORR["Bước 3.5: Suricata Correlation\ncorrelator.correlate(\n  src_ip, dst_port,\n  ml_attack_type, ml_confidence\n)\n→ correlation_score, details"]
    CORR --> FUSION

    FUSION["Bước 3.6: Fusion\nfinal_confidence =\nmin(ml_confidence + correlation_score, 1.0)"]
    FUSION --> DROP_Q

    DROP_Q{"suricata_action_drop\n== True?"}
    DROP_Q -- "CÓ" --> OVERRIDE["SURICATA OVERRIDE\nis_attack = True\nattack_type = Suricata_L7_DROP\nfinal_confidence = max(fc, 0.90)"]
    DROP_Q -- "KHÔNG" --> DEC
    OVERRIDE --> DEC

    DEC{"Bước 4: Decision Engine\n(thresholds.json)"}
    DEC -- "is_attack AND\nfc > 0.85" --> BLOCK
    DEC -- "fc > 0.60" --> ALERT
    DEC -- "fc ≤ 0.60" --> BENIGN

    BLOCK["🔴 AUTO_BLOCK\nfirewall.block_ip(src_ip)\nip_manager.add_to_blacklist()\n→ action_audit.log\n→ Loki/Grafana"]
    ALERT["🟡 SUSPICIOUS\n→ LOG: SUSPICIOUS\n(corr_score, suri_alerts)\n→ Loki/Grafana"]
    BENIGN["🟢 BENIGN\n→ LOG: BENIGN\n→ Loki/Grafana"]
```

---

## 3. ML Inference — 2 Tầng XGBoost

```mermaid
flowchart LR
    FEAT["features\nshape=(30,)"]

    subgraph BINARY["🔵 Tầng 1: Binary Classification\nactive_model.pkl"]
        B1["predict_proba(X)"]
        B2["binary_attack_score\n= proba[class=1]"]
    end

    subgraph MULTI["🟣 Tầng 2: Multi-class Classification\nclassification_model.pkl + label_encoder.pkl"]
        M1["predict_proba(X)"]
        M2["argmax → predicted class"]
        M3["label_encoder.inverse_transform()"]
        M4["multi_attack_score\n= 1.0 - P(BENIGN)"]
    end

    COMBINE["confidence = max(\n  binary_attack_score,\n  multi_attack_score\n)"]

    FEAT --> B1 --> B2 --> COMBINE
    FEAT --> M1 --> M2 --> M3
    M1 --> M4 --> COMBINE

    COMBINE --> RESULT["Result dict:\n• is_attack = confidence > 0.85\n• confidence: float\n• attack_type: str or None\n• binary_score, multi_score\n• class_probabilities: dict"]

    style BINARY fill:#1a3a5c,color:#fff
    style MULTI fill:#3a1a5c,color:#fff
```

**7 classes:** `BENIGN` · `Brute Force` · `DoS/DDoS` · `PortScan` · `Web Attack` · `Botnet` · `Exploitation/Rare`

**Edge case:** Multi=BENIGN nhưng Binary cao (> 0.60) → `attack_type = "Suspicious (Binary=Attack, Multi=<highest_non_benign>)"`

---

## 4. Suricata Correlation — Scoring Logic

```mermaid
flowchart TD
    START(["correlate(src_ip, dst_port, ml_attack_type, ml_confidence)"])
    START --> HAS_ALERTS

    HAS_ALERTS{"Có alerts trong cache\ncho src_ip\ntrong 5 phút gần nhất?"}
    HAS_ALERTS -- "KHÔNG" --> RET_ZERO(["return 0.0, details"])
    HAS_ALERTS -- "CÓ" --> REPEAT_CHECK

    REPEAT_CHECK{"ml_attack_type\ncó giá trị?\n(ML phát hiện tấn công)"}
    REPEAT_CHECK -- "KHÔNG\n(ML=Benign)" --> ALERT_LOOP
    REPEAT_CHECK -- "CÓ" --> COUNT_CHECK

    COUNT_CHECK{"Số alerts\ntừ src_ip?"}
    COUNT_CHECK -- "≥ 3" --> REPEAT_3["+0.15\nrepeat_offender = True"]
    COUNT_CHECK -- "= 2" --> REPEAT_2["+0.05"]
    COUNT_CHECK -- "< 2" --> ALERT_LOOP

    REPEAT_3 --> ALERT_LOOP
    REPEAT_2 --> ALERT_LOOP

    ALERT_LOOP["Duyệt từng alert\n(dedup bằng seen_attack_types set\nvà seen_drop_sids set)"]

    ALERT_LOOP --> MAP["_map_signature_to_attack_type()\nkeyword matching → ML attack type"]

    MAP --> BRANCH{"Phân nhánh\ntheo ml_attack_type"}

    BRANCH -- "Nhánh A\nML = Benign" --> A["suricata_only_detection\n+0.10 per unique type"]
    BRANCH -- "Nhánh B\nML type == Suricata type" --> B["matching_signature\n+0.20 per unique match\n✅ Xác nhận chéo"]
    BRANCH -- "Nhánh C\nML type ≠ Suricata type\n(cả hai đều Attack)" --> C["different_attack_types\n+0.30 per unique type\n⚠️ Đa hình thái"]

    A --> DROP_Q2
    B --> DROP_Q2
    C --> DROP_Q2

    DROP_Q2{"alert.action =\ndrop / blocked / reject\n(unique SID)?"}
    DROP_Q2 -- "CÓ" --> DROP_SCORE["+0.50\nsuricata_action_drop = True"]
    DROP_Q2 -- "KHÔNG" --> NEXT_ALERT

    DROP_SCORE --> NEXT_ALERT
    NEXT_ALERT["Tiếp tục alert kế tiếp..."]
    NEXT_ALERT -.-> ALERT_LOOP

    NEXT_ALERT --> SEV_MULT

    SEV_MULT["Nhân severity_boost\n(hệ số theo severity CAO NHẤT)\nsev 1 (Info) → ×0.30\nsev 2 (Warning) → ×0.50\nsev 3 (Notice) → ×0.70\nsev 4 (Critical) → ×0.85"]

    SEV_MULT --> CAP_CHECK{"ml_attack_type\nrỗng?"}
    CAP_CHECK -- "CÓ (Benign)" --> CAP_BENIGN["Hard cap:\nmin(score, suricata_only_max_score)\n= min(score, 0.30)"]
    CAP_CHECK -- "KHÔNG (Attack)" --> CAP_ATTACK["Cap:\nmin(score, 0.90)"]

    CAP_BENIGN --> RET(["return correlation_score, details"])
    CAP_ATTACK --> RET
```

### Bảng điểm tóm tắt

| Điều kiện | Điểm | Dedup | Ghi chú |
|---|:---:|---|---|
| **Nhánh A** — ML=Benign, Suricata có alert | `+0.10` / loại | `seen_attack_types` | Cap cứng ≤ 0.30 |
| **Nhánh B** — ML type = Suricata type | `+0.20` / loại | `seen_attack_types` | Cross-validation |
| **Nhánh C** — ML type ≠ Suricata type | `+0.30` / loại | `seen_attack_types` | Multi-vector attack |
| **Repeat offender** (≥3 alerts, ML có tín hiệu) | `+0.15` | — | Chỉ khi ML đã phát hiện |
| **Repeat offender** (=2 alerts, ML có tín hiệu) | `+0.05` | — | — |
| **DROP action** (custom L7 rule) | `+0.50` / SID | `seen_drop_sids` | Mỗi signature_id 1 lần |
| **× severity_boost** | ×0.30 ~ ×0.85 | — | Nhân toàn bộ score |

---

## 5. Luồng Đọc Config — `thresholds.json`

```mermaid
flowchart LR
    JSON["configs/thresholds.json"]

    subgraph TE["ThreatEvaluator._load_thresholds()"]
        T1["auto_block_threshold = 0.85"]
        T2["alert_threshold = 0.60"]
        T3["whitelist_alert_threshold = 0.85"]
        T4["suricata_only_max_score = 0.30"]
    end

    JSON --> TE

    T1 --> DAEMON["autodefense_daemon.py\n(Decision Engine)"]
    T2 --> DAEMON
    T3 --> DAEMON
    T4 --> SC["SuricataCorrelator()\nconstructor parameter"]

    SC --> CORR_CAP["correlate()\nHard cap khi ML=Benign"]

    style JSON fill:#2d4a22,color:#fff
    style TE fill:#1a3a5c,color:#fff
```

### Bảng tham số hiện tại

| Tham số | Giá trị | Dùng bởi | Mục đích |
|---|:---:|---|---|
| `auto_block_threshold` | **0.85** | `ThreatEvaluator` → Decision Engine | `fc > 0.85` → AUTO_BLOCK |
| `alert_threshold` | **0.60** | `ThreatEvaluator` → Decision Engine | `fc > 0.60` → SUSPICIOUS |
| `whitelist_alert_threshold` | **0.85** | `ThreatEvaluator` | Ngưỡng cảnh báo cho whitelist IP |
| `suricata_only_max_score` | **0.30** | `ThreatEvaluator` → `SuricataCorrelator` | Hard cap corr_score khi ML=Benign |

> Tất cả 4 tham số đều **✅ Active** — được đọc từ file và sử dụng trong runtime.

### Vùng quyết định

```
final_confidence = min(ml_confidence + correlation_score, 1.0)

  0.0 ──────────────── 0.60 ──────────────── 0.85 ──── 1.0
   │      🟢 BENIGN      │    🟡 SUSPICIOUS    │  🔴 AUTO_BLOCK │
   │   (không làm gì)    │  (log + Grafana)    │  (iptables DROP │
   │                     │                     │   + Blacklist)  │
```

---

## 6. AutoFirewall — iptables Logic

```mermaid
flowchart TD
    CALL(["firewall.block_ip(src_ip, reason)"])
    CALL --> V1

    V1{"IP hợp lệ?\n(ipaddress.ip_address)"}
    V1 -- "Không" --> R1(["❌ return False"])
    V1 -- "Có" --> V2

    V2{"Protected IP?\n127.0.0.1\n192.168.226.1\n192.168.226.151"}
    V2 -- "Có" --> R2(["🛡️ return False\nPROTECTED"])
    V2 -- "Không" --> V3

    V3{"Trong _blocked_ips\ncache?"}
    V3 -- "Có" --> R3(["⏭️ return False\nDuplicate"])
    V3 -- "Không" --> V4

    V4{"iptables -C\nrule đã tồn tại?"}
    V4 -- "Có" --> SYNC["sync cache\n_blocked_ips.add()"] --> R3
    V4 -- "Không" --> EXEC

    EXEC["iptables -I INPUT\n-s src_ip -j DROP\ntimeout = 1s"]
    EXEC --> OK["✅ _blocked_ips.add(src_ip)\nreturn True"]
```

---

## 7. Timeline Flow — Từ Packet Đến Block

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant NFS as NFStreamer
    participant DAE as autodefense_daemon
    participant ML as ThreatEvaluator
    participant CORR as SuricataCorrelator
    participant FW as AutoFirewall
    participant BL as IPManager (Blacklist)
    participant LOKI as Grafana / Loki

    Note over CORR: Background thread<br/>đọc eve.json mỗi 500ms<br/>cache alerts (TTL 5min)

    NIC->>NFS: Raw packets
    NFS->>DAE: Flow object

    DAE->>DAE: Bước 1: Check Blacklist
    DAE->>DAE: Bước 2: Check Whitelist

    DAE->>ML: Bước 3: evaluate(features[30])
    ML-->>DAE: {confidence, attack_type, binary_score, multi_score}

    DAE->>CORR: Bước 3.5: correlate(src_ip, attack_type, confidence)
    CORR-->>DAE: (correlation_score, details)

    DAE->>DAE: Bước 3.6: Fusion<br/>fc = min(ml + corr, 1.0)

    alt suricata_action_drop
        DAE->>DAE: Override: is_attack=True, fc=max(fc, 0.90)
    end

    alt fc > 0.85 AND is_attack
        DAE->>FW: block_ip(src_ip)
        FW->>FW: iptables -I INPUT -s IP -j DROP
        DAE->>BL: add_to_blacklist(src_ip)
        DAE->>LOKI: LOG AUTO_BLOCKED
    else fc > 0.60
        DAE->>LOKI: LOG SUSPICIOUS
    else fc ≤ 0.60
        DAE->>LOKI: LOG BENIGN
    end
```

---

## 8. Tóm Tắt Hiện Tại

### ✅ Điểm mạnh
- **2 tầng ML** (Binary + Multi-class) — robust hơn single model
- **Config tập trung** — tất cả thresholds đọc từ `thresholds.json`, không còn dead config
- **Dedup scoring** — `seen_attack_types` + `seen_drop_sids` tránh score inflation
- **Severity multiplier** — ET Info/Policy alerts (sev=1) chỉ có 30% ảnh hưởng
- **Hard cap Benign** — `suricata_only_max_score = 0.30` ngăn ET Open alert tự block
- **Suricata L7 Override** — custom rule DROP → override ML Benign
- **Protected IPs** — không bao giờ block gateway/server

### ⚠️ Điểm cần cải thiện
1. **[Thấp]** Xem xét scenario ML confidence thấp + Suricata DROP mạnh → liệu auto-block có hợp lý không (khi final_confidence > 0.85)
