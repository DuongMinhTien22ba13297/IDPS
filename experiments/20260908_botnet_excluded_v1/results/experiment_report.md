# Reproducible Experiment Report: 20260908_botnet_excluded_v1

## Scope and protocol

Botnet, Infiltration and Heartbleed were excluded from supervised ML training. The model family was selected exclusively by five-fold cross-validation on the development partition. The chronological final test partition was not used for model, hyperparameter or feature selection; predictions were generated once after the configuration was locked.

## Model selection on development data

| Model | CV macro-F1 mean | CV SD | Best trial | Trials |
|---|---:|---:|---:|---:|
| lightgbm | 0.964517 | 0.003156 | 23 | 30 |
| random_forest | 0.987258 | 0.001313 | 14 | 30 |
| xgboost | 0.994152 | 0.000673 | 29 | 30 |

Selected model: **xgboost**.

## Final test

Final test rows: **330,125**.

### Binary component

| TN | FP | FN | TP | Accuracy | Weighted F1 | FPR | FNR |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 236,694 | 1,068 | 93 | 92,270 | 0.996483 | 0.996489 | 0.004492 | 0.001007 |

### Multiclass component

Accuracy: 0.996398; macro-F1: 0.990701; weighted-F1: 0.996408.

### Deployed dual-model ML decision rule

At threshold 0.85: accuracy 0.995741; macro-F1 0.971550; attack FPR 0.004450; attack FNR 0.003605.

Latency values in the JSON artifact are amortized bulk-inference measurements and are not end-to-end attack-detection latency.
