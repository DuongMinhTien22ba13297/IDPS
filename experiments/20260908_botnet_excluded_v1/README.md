# Experiment 20260908_botnet_excluded_v1

This directory contains the reproducible five-class rerun requested for the thesis. Botnet, Infiltration, and Heartbleed are excluded from supervised ML training.

## Main report artifacts

- `results/report_insert.tex`: report-ready English text and LaTeX tables.
- `results/experiment_report.md`: concise result summary.
- `results/data_lineage.json`: source counts, exclusions, split boundaries, and dataset hashes.
- `results/model_selection.json`: model-selection rule, fold scores, mean/SD, parameters, and winner.
- `results/final_evaluation.json`: component and runtime-fusion metrics plus latency protocol.
- `results/artifact_manifest.json`: verified SHA-256 hashes of required artifacts.
- `results/optuna_trials_*.csv`: all trial records, including failed/interrupted trials and 30 completed trials per model.

## Logs and commands

- `commands.ps1`: clean reproducibility commands.
- `logs/command_history.log`: commands actually executed, including resumptions.
- `logs/prepare.log`, `logs/tune.log`, `logs/train-evaluate.log`, `logs/verify.log`: timestamped execution logs.
- `logs/environment_*.json`: Python, OS, CPU count, and package versions.

## Safety and promotion

No original dataset or production model was overwritten. Pre-run copies of the thesis, training scripts, current production models, and reports are stored in `C:\IDPS\backups\20260908_botnet_excluded_v1`.

The experiment-selected feature vector contains 21 features. The current production runtime expects a fixed 15-element vector, so these models must not be copied into `C:\IDPS\models` until `realtime_extractor.py` and the runtime shape validation are updated and tested together.
