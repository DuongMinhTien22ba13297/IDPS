# Reproducible Experiment Report: 20260913_connection_count_10s_v2

## Scope and protocol

Botnet, Infiltration and Heartbleed were excluded from supervised ML training. The model family was selected exclusively by five-fold cross-validation on the development partition. The chronological final test partition was not used for model, hyperparameter or feature selection; predictions were generated once after the configuration was locked.
Connection Count 10s was supplied as an ordinary candidate feature and was not forced into the selected subset. It counts flow starts for the same (source IP, destination IP, destination port, protocol) in the causal interval (t-10s, t], including the current flow.

## Model selection on development data

| Model | CV macro-F1 mean | CV SD | Best trial | Trials |
|---|---:|---:|---:|---:|
| lightgbm | 0.988858 | 0.001705 | 22 | 30 |
| random_forest | 0.991660 | 0.001363 | 3 | 30 |
| xgboost | 0.994305 | 0.000349 | 27 | 30 |

Selected model: **xgboost**.

## Final test

Final test rows: **330,125**.

### Binary component

| TN | FP | FN | TP | Accuracy | Weighted F1 | FPR | FNR |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 236,724 | 1,038 | 122 | 92,241 | 0.996486 | 0.996491 | 0.004366 | 0.001321 |

### Multiclass component

Accuracy: 0.996474; macro-F1: 0.991778; weighted-F1: 0.996483.

### Deployed dual-model ML decision rule

At threshold 0.85: accuracy 0.995665; macro-F1 0.975162; attack FPR 0.004319; attack FNR 0.004363.

Latency values in the JSON artifact are amortized bulk-inference measurements and are not end-to-end attack-detection latency.
