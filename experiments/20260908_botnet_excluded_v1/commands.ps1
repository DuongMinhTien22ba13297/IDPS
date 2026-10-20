$ErrorActionPreference = 'Stop'
$experimentId = '20260908_botnet_excluded_v1'
$script = 'C:\IDPS\src\run_botnet_excluded_experiment.py'

# 1. Prepare the five-class development/final-test datasets.
python -u $script --stage prepare --experiment-id $experimentId
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2. Run 30 seeded Optuna trials per model with five-fold CV.
python -u $script --stage tune --experiment-id $experimentId --trials 30 --rf-jobs -1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3. Lock the CV winner, train it, and evaluate the final test once.
python -u $script --stage train-evaluate --experiment-id $experimentId
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 4. Verify labels, hashes, model files, reports, and manifests.
python -u $script --stage verify --experiment-id $experimentId
exit $LASTEXITCODE
