

Dựa trên kiến trúc dự án, đây là hệ thống **Zero-Touch IDPS** (Intrusion Detection and Prevention System) sử dụng ML. Dưới đây là các loại sơ đồ tôi đề xuất để trình bày:

---

## 1. Sơ đồ Kiến trúc Tổng quan (System Architecture)

**Mục đích:** Cho người xem hiểu nhanh hệ thống gồm những thành phần nào và chúng tương tác ra sao.

**Các thành phần cần thể hiện:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                           NETWORK TRAFFIC                               │
│                         (ens33 interface)                               │
└─────────────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
┌─────────────────────────────┐    ┌─────────────────────────────┐
│        SURICATA             │    │       NFSTREAM              │
│    (IDS - EVE JSON logs)    │    │  (Flow Feature Extraction)  │
└─────────────────────────────┘    └─────────────────────────────┘
                    │                           │
                    ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      AUTODEFENSE DAEMON (Python)                       │
│  ┌──────────┐  ┌───────────┐  ┌──────────────┐  ┌─────────────────┐     │
│  │IPManager │  │Evaluator  │  │Correlator    │  │  AutoFirewall   │     │
│  │(BL/WL)   │  │(ML Models)│  │(Suricata)    │  │   (iptables)   │     │
│  └──────────┘  └───────────┘  └──────────────┘  └─────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
┌─────────────────────────────┐    ┌─────────────────────────────┐
│         LOKI                │    │        IPTABLES              │
│    (Log Aggregation)        │    │    (Auto-Block IP)           │
└─────────────────────────────┘    └─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────┐
│        GRAFANA              │
│    (Dashboard/Monitoring)   │
└─────────────────────────────┘
```

---

## 2. Sơ đồ Pipeline Xử lý Luồng (Flow Processing Pipeline)

**Mục đích:** Thể hiện luồng xử lý từ khi bắt packet đến khi block IP - đây là "trái tim" của hệ thống.

```
                    Flow arrives from NFStream
                              │
                              ▼
                    ┌─────────────────────┐
                    │  1. BLACKLIST CHECK  │
                    │   IPManager.is_      │
                    │   blacklisted()      │
                    └─────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │ NO                             │ YES
              ▼                                ▼
    ┌─────────────────────┐          ┌─────────────────────┐
    │  2. WHITELIST CHECK  │          │   AUTO_BLOCK (DROP) │
    │   IPManager.is_      │          │   + Log to audit    │
    │   whitelisted()      │          └─────────────────────┘
    └─────────────────────┘
              │
      ┌───────┴───────┐
      │ NO            │ YES (Monitor only)
      ▼               ▼
┌─────────────────────┐
│ 3. FEATURE          │
│    EXTRACTION        │────────── Event logged
│ (30 features vector) │
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 4. ML INFERENCE      │
│  ┌─────────────────┐ │
│  │ Binary (attack?)│ │
│  │ Multi-class     │ │
│  │ (attack type)   │ │
│  └─────────────────┘ │
└─────────────────────┘
      │
      ▼ (if confidence > threshold)
┌─────────────────────┐
│ 5. SURICATA          │
│    CORRELATION       │
│ (cross-verify)       │
└─────────────────────┘
      │
      ▼
┌─────────────────────┐
│ 6. DECISION ENGINE   │
│  Combined Score >    │
│  threshold?         │
└─────────────────────┘
      │
      ├── NO ──► Log BENIGN / SUSPICIOUS
      │
      └── YES ──► AUTO_BLOCK + Add to Blacklist
```

---

## 3. Sơ đồ ML Pipeline (Training & Inference)

**Mục đích:** Trình bày cách train model và cách model được sử dụng trong production.

```
┌─────────────────────────────────────────────────────────────────┐
│                      OFFLINE TRAINING (Phase 1-1.5)             │
├─────────────────────────────────────────────────────────────────┤
│  CIC-IDS2017 Dataset                                             │
│        │                                                        │
│        ▼                                                        │
│  ┌─────────────────┐                                          │
│  │ Data Preprocess  │ ── Label Grouping ── SMOTE Resampling    │
│  │ (filter script)  │                                          │
│  └─────────────────┘                                          │
│        │                                                        │
│        ▼                                                        │
│  ┌─────────────────┐                                          │
│  │ Feature Selection│ ── 30 selected features                   │
│  │ (top 30)        │                                          │
│  └─────────────────┘                                          │
│        │                                                        │
│        ▼                                                        │
│  ┌─────────────────┐     ┌─────────────────┐                   │
│  │ Binary Model    │     │ Multiclass Model │                   │
│  │ (attack vs      │     │ (8 attack types │                   │
│  │  benign)        │     │  + benign)       │                   │
│  │ XGBoost         │     │ XGBoost          │                   │
│  └────────┬────────┘     └────────┬────────┘                   │
│           │                        │                             │
│           ▼                        ▼                             │
│  active_model.pkl     classification_model.pkl                  │
└─────────────────────────────────────────────────────────────────┘
           │                        │
           └──────────┬─────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                      REAL-TIME INFERENCE (Phase 2-3)            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Raw Flow ──► Feature Vector (30 dims)                         │
│                     │                                          │
│                     ▼                                          │
│        ┌────────────────────────┐                             │
│        │    Binary Predict      │                             │
│        └───────────┬────────────┘                             │
│                    │ is_attack?                                │
│                    ▼                                           │
│        ┌────────────────────────┐                             │
│        │   Multiclass Predict   │                             │
│        │   (Get attack type)    │                             │
│        └────────────────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Sơ đồ Docker Architecture

**Mục đích:** Thể hiện cấu trúc container và volume sharing.

```
┌──────────────────────────────────────────────────────────────────┐
│                     docker-compose.yml                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  ┌─────────┐ │
│  │ SURICATA    │  │ AUTODEFENSE  │  │  LOKI    │  │ GRAFANA │ │
│  │ container   │  │  container   │  │ container│  │container│ │
│  └──────┬──────┘  └──────┬───────┘  └─────┬────┘  └────┬────┘  │
│         │               │                 │            │       │
│         │               │                 │            │       │
│         ▼               ▼                 ▼            │       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    SHARED VOLUMES                        │   │
│  │                                                          │   │
│  │   /logs/suricata/eve.json ◄─────────── (writes)         │   │
│  │          │                              (reads)          │   │
│  │          ▼                                              │   │
│  │   /src/*.py            /models/*.pkl    /configs/*.ini  │   │
│  │   /logs/autodefense.log                      (config)  │   │
│  │   /logs/action_audit.log                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. Sơ đồ Phased Implementation

**Mục đích:** Trình bày lộ trình phát triển dự án theo từng giai đoạn.

```
Phase 1                    Phase 1.5                 Phase 2
Data Preprocess      ─►    ML Training         ─►    Deployment
──────────────────         ───────────              ───────────
• Script dọn dẹp           • Hyperparameter        • Suricata daemon
• Label grouping             tuning                 • autodefense
• SMOTE resampling         • XGBoost models          daemon
• 30 feature selection       (binary +              • NFStream
                             multiclass)             integration

      Phase 3                      Phase 4
  Auto-Prevention            Auto-Monitoring
  ──────────────             ───────────────
  • auto_firewall.py          • Loki logging
  • iptables integration      • Grafana dashboard
  • Blacklist/whitelist       • Auto-refresh
  • Zero-touch decision         (5s)
```

---

## 6. Sơ đồ Decision Matrix

**Mục đích:** Thể hiện các điều kiện ra quyết định của hệ thống.

```
┌──────────────────────────────────────────────────────────────┐
│                    AUTONOMOUS DECISION ENGINE                │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Combined Score = ML_Confidence + Correlation_Score         │
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │                                                    │     │
│  │   Combined Score > Auto_block_threshold?          │     │
│  │                    │                               │     │
│  │      ┌─────────────┴──────────────┐                │     │
│  │      │                            │                 │     │
│  │      ▼                            ▼                 │     │
│  │   [YES]                       [NO]                │     │
│  │      │                            │                 │     │
│  │      ▼                            ▼                 │     │
│  │   AUTO_BLOCK              ┌───────────────────┐   │     │
│  │   + Add to Blacklist      │ ML_Confidence >  │   │     │
│  │                            │ Alert_threshold? │   │     │
│  │                            └─────────┬─────────┘   │     │
│  │                                      │              │     │
│  │                          ┌───────────┴────────┐   │     │
│  │                          │                    │     │     │
│  │                          ▼                    ▼     │     │
│  │                       [YES]                [NO]     │     │
│  │                          │                    │      │     │
│  │                          ▼                    ▼      │     │
│  │                   SUSPICIOUS            BENIGN        │     │
│  │                                                            │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│  Correlation_Score > 0.2? → Reduce threshold by 0.1         │
│  (Correlation boost detection speed)                         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Tool khuyến nghị cho từng loại sơ đồ

| Loại sơ đồ             | Tool                               | Lý do                      |
| ---------------------- | ---------------------------------- | -------------------------- |
| Architecture, Pipeline | **Draw.io / Diagrams.net**         | Dễ vẽ, export được PNG/SVG |
| Component Diagram      | **Mermaid** (trong docs)           | Code-based, dễ maintain    |
| Timeline/Phase         | **Lucidchart** hoặc **Excalidraw** | Đẹp cho presentation       |
| Dashboard mockup       | **Figma** hoặc **Grafana thật**    | Demo trực tiếp             |

---

Bạn muốn tôi cụ thể hóa sơ đồ nào? Tôi có thể vẽ bằng Mermaid (code-based) hoặc ASCII diagram.