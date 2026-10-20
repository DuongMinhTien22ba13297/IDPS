# Runtime 21-Feature Upgrade Validation

Date: 2026-09-08  
Model experiment: `20260908_botnet_excluded_v1`

## Scope

The production inference runtime was upgraded from a hard-coded 15-feature
contract to a metadata-validated 21-feature contract. Both XGBoost models are
evaluated for every completed flow. The real-time extractor now emits the exact
feature order recorded in `models/model_metadata.json`.

The TCP initial-window plugin was also corrected to parse the TCP window field
from the packet header, matching the offline `CustomFeaturePlugin` used to
generate the NFStream training corpus. The former runtime implementation used
`packet.ip_size`, which was not equivalent to the training feature.

## Modified runtime files

- `src/realtime_extractor.py`
- `src/threat_evaluator.py`
- `src/autodefense_daemon.py`
- `docker/autodefense/requirements.txt`
- `tests/test_runtime_21_features.py` (new)
- `experiments/20260908_runtime_21features_v1/live_packet_injector.py` (new)
- `experiments/20260908_runtime_21features_v1/live_runtime_smoke.py` (new)
- `experiments/20260908_runtime_21features_v1/e2e_live_daemon_smoke.sh` (new)

Pre-change source and model artifacts are stored under:

`C:\IDPS\backups\20260908_runtime_21features_v1`

## Promoted production artifacts

| Artifact | SHA-256 |
|---|---|
| `active_model.pkl` | `BC97E57E96DB2364A7BEEE3B8717089A8E7C15B11BE210D0FFC785A9F795D0EF` |
| `classification_model.pkl` | `09FB01BC824F5A57CE4048551D8EC6317B4E658A1E14D9EF39FB1ADC2C8DC4A0` |
| `label_encoder.pkl` | `D9EC493658BD249B4C949DEC680F80FBD32561C2769E8CC4CE033935E23757D3` |
| `model_metadata.json` | `20E285313F0AC743A4A7324EAA8FC726DE217EDEF5AFB09E7703A4568BDEF950` |

Every production hash matched its source under
`experiments/20260908_botnet_excluded_v1/models` after promotion.

## Validation performed

```powershell
python -m py_compile src\realtime_extractor.py src\threat_evaluator.py src\autodefense_daemon.py
python -m unittest discover -s tests -p 'test_*.py' -v
```

Result: **8 tests passed**.

The tests cover:

- exact equality between the runtime feature order and locked model metadata;
- numerical parity between all 21 runtime formulas and `extract_57_features`;
- TCP window extraction from synthetic IPv4/TCP header bytes;
- rejection of unknown features and wrong vector shapes;
- consistency of binary model, multiclass model, metadata, and label encoder;
- inference on a real row from the chronological final-test artifact;
- loadability of the legacy 15-feature artifacts from the rollback backup.

A separate 512-row comparison was run between direct XGBoost batch inference
and `ThreatEvaluator.evaluate`. The maximum absolute difference was `0.0` for
both the binary attack probability and multiclass non-BENIGN probability.

## Ubuntu VM deployment and live acceptance

Target: `192.168.226.151` (Ubuntu 24.04.4 LTS)  
Deploy start: `2026-09-08T01:44:52Z`  
Remote rollback backup:
`/home/dmtien/IDPS/backups/20260908_runtime_21features_live_v1`

The verified source and model artifacts were copied into the VM production
tree only after the existing source, models, configuration, container state,
iptables rules, and nftables rules were backed up. Production SHA-256 values
match the promoted local artifacts. A container preflight loaded both models
with warnings treated as errors and confirmed 21 ordered features and five
classes.

The `autodefense` container was restarted in place. Its startup log confirms:

- experiment `20260908_botnet_excluded_v1`;
- `features=21`, `classes=5`;
- classes `BENIGN`, `Brute Force`, `DoS/DDoS`, `PortScan`, and `Web Attack`;
- NFStream ready on the production `ens33` interface.

The production daemon processed bounded synthetic TCP traffic from the RFC 2544
benchmark address `198.18.0.10` on `ens33`. At `02:04:33Z`, it classified the
completed flow as PortScan with final score `0.916`, binary score `0.246`, and
multiclass score `0.916`; inference took `11.6 ms`. The emitted probability
event contained exactly five classes and no Botnet class. The daemon exercised
the auto-block path, then automatically removed the IP from both iptables and
`blacklist.json` after the configured 60-second TTL. A second completed flow
showed the same decision with `5.0 ms` inference.

An isolated live-path smoke test used a temporary `veth` pair so the test frame
arrived as genuine inbound Ethernet traffic. NFStream captured a two-packet TCP
flow and produced all 21 finite runtime values, including
`Init_Win_bytes_forward=64240`, `SYN Flag Count=1`, and `RST Flag Count=1`.
The models returned five probabilities, no Botnet class, and a benign decision
with score `0.321`. The full daemon loop then processed the same live path on
port `22400`, logged the decision, and pushed its `ml_probs` event to Loki.
The temporary `veth` pair was deleted after the test.

Loki initially lacked its Compose-declared host port on the old container. Only
the Loki service was recreated, preserving its bind-mounted data. The health
endpoint now returns `ready`, label discovery succeeds, and the port `22400`
decision/probability event is queryable. Docker's firewall delta consists of
the intended Loki `192.168.226.151:3100` publication plus normal counter and
timestamp changes; no test-source firewall rule remains.

Final operational checks:

- `autodefense`: running, restart count `0`;
- all six Compose services: up;
- no feature-shape, extraction, or multiclass-inference errors since restart;
- no Loki connection errors after recovery;
- test IP absent from both iptables and `blacklist.json`.

The external Kali scenario runner at `172.16.1.10` was unreachable (`No route
to host`), so the repository's full multi-scenario attack suite was not run.
This does not invalidate the completed live capture/inference/decision/logging
smoke tests, but the external scenario suite remains a separate acceptance test
when that VM is available.
