"""Read-only comparison of observed live vectors with the locked training data."""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

ROOT = Path(__file__).resolve().parents[2]
DIAG = Path(__file__).resolve().parent
metadata = json.loads((ROOT / 'models/model_metadata.json').read_text(encoding='utf-8'))
observations = json.loads((DIAG / 'live_log_summary.json').read_text(encoding='utf-8'))
names = metadata['selected_features']
classes = metadata['classes']
development = pd.read_csv(
    ROOT / 'experiments/20260908_botnet_excluded_v1/data/development.csv',
    usecols=['Label', *names],
)
binary = joblib.load(ROOT / 'models/active_model.pkl')
multiclass = joblib.load(ROOT / 'models/classification_model.pkl')
summary = {'development_rows': len(development), 'class_distributions': {}, 'live_examples': []}
important = ['Init_Win_bytes_forward', 'Bwd Packets/s', 'Max Packet Length',
             'RST Flag Count', 'PSH Flag Count', 'Total Fwd Packets',
             'Flow IAT Std', 'Fwd IAT Min']
for label, group in development.groupby('Label'):
    summary['class_distributions'][label] = {
        'count': len(group),
        'quantiles': {name: group[name].quantile([0.05, 0.5, 0.95]).to_list() for name in important},
        'top_tcp_windows': {str(k): int(v) for k, v in group['Init_Win_bytes_forward'].value_counts().head(5).items()},
    }

for port, target in [('21', 'Brute Force'), ('80', 'DoS/DDoS')]:
    for observation in observations['ports'][port]['examples']:
        row = np.array([observation['features'][name] for name in names], dtype=np.float64).reshape(1, -1)
        frame = pd.DataFrame(row, columns=names)
        pbin = float(binary.predict_proba(frame)[0, 1])
        pmulti = multiclass.predict_proba(frame)[0]
        # Exact tree contributions in raw-margin space, not probability effects.
        contribs = multiclass.get_booster().predict(xgb.DMatrix(frame), pred_contribs=True)[0]
        margin_diff = contribs[classes.index('BENIGN')] - contribs[classes.index(target)]
        ranked = sorted(zip(names, margin_diff[:-1]), key=lambda item: abs(float(item[1])), reverse=True)
        summary['live_examples'].append({
            'port': int(port), 'flow': observation['flow'], 'observed_time_utc': observation['time'],
            'recomputed_binary': pbin,
            'recomputed_multiclass': {label: float(pmulti[i]) for i, label in enumerate(classes)},
            'recomputed_ml_score': max(pbin, 1.0-float(pmulti[classes.index('BENIGN')])),
            'benign_minus_target_margin_contributions': [
                {'feature': name, 'live_value': observation['features'][name], 'contribution': float(value)}
                for name, value in ranked[:8]
            ],
            'target_class': target,
        })
print(json.dumps(summary, indent=2))
