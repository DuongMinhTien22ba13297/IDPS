# Ubuntu deployment record — 20260913_connection_count_10s_v2

## Target and scope

- Target: `dmtien@192.168.226.151`
- Project root: `/home/dmtien/IDPS`
- Service restarted: `autodefense` only
- Deployment mode after restart: `MONITOR_ONLY_MODE=true`
- Authentication: existing SSH key authentication; no password was placed in a command or log.

## Compatibility finding

The VM was missing `src/connection_count.py`; its `realtime_extractor.py` and
`autodefense_daemon.py` did not match the release. Deploying only the model
would therefore have been incompatible with the selected 21-feature schema.

## Staged release contents

Models uploaded to:
`/home/dmtien/IDPS/deployments/20260913_connection_count_10s_v2/models/`

- `active_model.pkl`: `cda7b54cddf846514ab192649b79217f8ff4be137027434a290b592e864150a4`
- `classification_model.pkl`: `c6f9625c4aa823239ca052ee09797b32b92c06c3f993e0f2ad7d7e8e46b8391c`
- `label_encoder.pkl`: `d9ec493658bd249b4c949dec680f80fbd32561c2769e8cc4ce033935e23757d3`
- `model_metadata.json`: `d605a3a2090af5772c8f6e8d2b72cade3b5cd61222f67b9fa2cb327fad49e691`

Runtime files uploaded to:
`/home/dmtien/IDPS/deployments/20260913_connection_count_10s_v2/src/`

- `connection_count.py`: `ac2a29fd4cd3e13d1b9d3647b38753889d40b2eadc5abda0c8053c107cfda57c`
- `realtime_extractor.py`: `577a17c4da0434382e4864ab9ff00e02717edfadbd70d3e8de831ddf12588f7b`
- `autodefense_daemon.py`: `6b1145a325958f453af60658510d87a1fd83cb9e70db2ced5cbfc131e93a2ffb`

`python3 -m py_compile` and all remote SHA-256 values passed before activation.

## Backup and activation

The prior model artifacts and two replaced runtime files were copied to:

`/home/dmtien/IDPS/backups/20260913_151500_before_xgb_connection_count_v2/`

The backup includes a marker that `connection_count.py` was absent before this
release. The release then replaced the four model artifacts and three runtime
files, followed by:

```bash
cd /home/dmtien/IDPS
docker compose -f docker/docker-compose.yml restart autodefense
```

## Post-deployment verification

The container was running after restart. An in-container model probe reported:

```text
experiment_id: 20260913_connection_count_10s_v2
feature_count: 21
feature[6]: Connection Count 10s
```

Startup logs confirmed model schema validation, five expected classes, and:

```text
Connection Count runtime: enabled=True window_seconds=10.0 n_meters=1
```

No live attack was generated as part of deployment. The next validation stage is
a controlled live DoS run and review of the corresponding Loki/Grafana records.

## Runtime default-schema compatibility fix

A post-deployment audit found that `autodefense` was safe because it explicitly
passed `ThreatEvaluator.feature_names` to `extract_features`, but the module-level
`realtime_extractor.FEATURE_NAMES` default still described the earlier baseline
model. Other callers that omitted `feature_names` could therefore construct the
wrong 21-value vector without a shape error.

The default list was changed to the exact ordered `selected_features` list in the
v2 metadata. Local verification passed 20 unit/integration tests, artifact verify,
and an exact-order assertion. The updated extractor SHA-256 is:

`73b8a560eba7988e4b897083d622966a434f093b70e1fbc0a0432781eea6c622`

Before updating the VM, the prior deployed extractor was backed up at:

`/home/dmtien/IDPS/backups/20260913_153200_before_runtime_default_v2_fix/`

The container was restarted again. The in-container compatibility probe returned:

```text
default feature count: 21
FEATURE_NAMES == ThreatEvaluator.feature_names: True
experiment_id: 20260913_connection_count_10s_v2
```

Startup logs again confirmed the v2 schema, stateful 10-second connection counter,
one NFStream meter, and a ready capture loop.
