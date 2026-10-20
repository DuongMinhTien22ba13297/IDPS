# Connection Count 10s — comparison with baseline

## Experiment status

- Baseline: `20260908_botnet_excluded_v1`
- Candidate: `20260913_connection_count_10s_v2`
- Source dataset SHA-256: `fd277e4a6a8dd8088b724f80d0fca6d8c3d7f7453d4ad525e8eff10b85a5f579`
- Development rows: 1,320,394 in both experiments
- Final-test rows: 330,125 in both experiments
- After dropping `Connection Count 10s`, every development and final-test cell is identical to the baseline.
- The final test set was not used for tuning or feature selection.

## Feature definition

`Connection Count 10s` is the number of flow starts sharing
`(src_ip, dst_ip, dst_port, protocol)` in the causal interval `(t - 10 s, t]`,
including the current flow. Training computes the value after sorting by key,
flow start time, and original row position. Runtime maintains the same statistic
with a stateful sliding window.

The feature was supplied as an ordinary candidate. It was not forced into the
selected set. The trained XGBoost pipeline selected it at rank 7 of 21, with
importance `0.0313277542591095`.

## Selected-feature change

Added relative to the baseline 21-feature model:

- `Connection Count 10s`
- `Flow Packets/s`
- `Min Packet Length`
- `Bwd Packet Length Mean`

Removed relative to the baseline 21-feature model:

- `Max Packet Length`
- `Packet Length Std`
- `Fwd Packet Length Max`
- `Fwd Packet Length Std`

## Final-test comparison

| Metric | Baseline | Connection-count v2 | Delta |
|---|---:|---:|---:|
| Binary accuracy | 0.996483 | 0.996486 | +0.000003 |
| Binary FPR | 0.004492 | 0.004366 | -0.000126 |
| Binary FNR | 0.001007 | 0.001321 | +0.000314 |
| Multiclass accuracy | 0.996398 | 0.996474 | +0.000076 |
| Multiclass macro-F1 | 0.990701 | 0.991778 | +0.001076 |
| Runtime-fusion accuracy | 0.995741 | 0.995665 | -0.000076 |
| Runtime-fusion macro-F1 | 0.971550 | 0.975162 | +0.003611 |
| Runtime-fusion attack FPR | 0.004450 | 0.004319 | -0.000130 |
| Runtime-fusion attack FNR | 0.003605 | 0.004363 | +0.000758 |
| DoS multiclass precision | 0.982240 | 0.982766 | +0.000526 |
| DoS multiclass recall | 1.000000 | 1.000000 | 0.000000 |
| DoS multiclass F1 | 0.991040 | 0.991308 | +0.000268 |
| DoS fusion precision | 0.982273 | 0.982865 | +0.000592 |
| DoS fusion recall | 0.999983 | 1.000000 | +0.000017 |
| DoS fusion F1 | 0.991049 | 0.991358 | +0.000310 |

## Interpretation and limitation

The new feature improves multiclass macro-F1, fusion macro-F1, and the DoS
precision/F1 measured inside the CICIDS2017-derived split. It does not improve
every metric: fusion accuracy is slightly lower and fusion attack FNR is higher.

The CICIDS2017 DoS traffic has a much higher same-key 10-second connection count
than the other classes (median 915 versus benign median 2). This is useful signal,
but it may partly encode the dataset's attack campaign and network topology.
Therefore, these offline results do not prove that live HULK traffic is fixed.
Deployment and a fresh live test must be treated as a separate validation stage.

## Deployment decision

This candidate is trained, verified, and ready for deployment testing. It has not
replaced the current production model and has not been copied to the Ubuntu VM.
