# Reproducible Experiment Report: 20260913_connection_count_10s_v1

## Scope and protocol

Botnet, Infiltration and Heartbleed were excluded from supervised ML training. The model family was selected exclusively by five-fold cross-validation on the development partition. The chronological final test partition was not used for model, hyperparameter or feature selection; predictions were generated once after the configuration was locked.

## Model selection on development data

| Model | CV macro-F1 mean | CV SD | Best trial | Trials |
|---|---:|---:|---:|---:|
| lightgbm | 0.988572 | 0.001359 | 20 | 30 |
| random_forest | 0.992840 | 0.001059 | 28 | 30 |
| xgboost | 0.995584 | 0.000355 | 29 | 30 |

Selected model: **xgboost**.

## Final test

Final test rows: **438,404**.

### Binary component

| TN | FP | FN | TP | Accuracy | Weighted F1 | FPR | FNR |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 344,821 | 1,220 | 97 | 92,266 | 0.996996 | 0.997003 | 0.003526 | 0.001050 |

### Multiclass component

Accuracy: 0.997003; macro-F1: 0.991701; weighted-F1: 0.997013.

### Deployed dual-model ML decision rule

At threshold 0.85: accuracy 0.996558; macro-F1 0.973866; attack FPR 0.003416; attack FNR 0.003530.

Latency values in the JSON artifact are amortized bulk-inference measurements and are not end-to-end attack-detection latency.
