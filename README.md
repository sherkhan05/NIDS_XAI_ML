# NIDS-XAI

Network intrusion detection with explainable AI. Detects and classifies attacks on the NSL-KDD dataset and shows a per-prediction SHAP breakdown, so an analyst can see **why** a flow was flagged.

## Results

Evaluated on KDDTest+ (see `ml/eval_report.json` for full confusion matrices):

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Binary (Normal vs Attack) | 89.17% | 94.75% | 85.72% | 90.01% | 96.10% |
| Multiclass (attack type) | 82.74% | — | — | 64.67% (macro) | — |

Multiclass per-class F1: DoS 91.0%, Normal 88.2%, Probe 70.3%, R2L 44.9%, U2R 29.0%.
R2L and U2R are the hardest classes — the dataset has few of them (2,752 and 200
test rows respectively), which drags their recall down to ~30% and ~20%.

## Architecture

```
React + Vite UI  ──/api/*──▶  FastAPI backend (backend/app.py)
(src/, dist/)                 ├─ SQLite (nids.db)
                              └─ XGBoost + SHAP (ml/)
```

- **Frontend:** React 19 + Vite
- **Backend:** FastAPI on `localhost:8000`; loads models and the SHAP explainer from `ml/` at startup
- **ML:** two XGBoost models (binary, multiclass), one-hot encoder, standard scaler, label encoder, temperature-scaled probabilities

## Features

- **Predict**
  - *Preset mode:* choose one of 20 real KDDTest+ rows.
  - *Manual mode:* enter 6 features; the other 35 are filled from training medians/modes. This is a rough demo, not a validated prediction.
- **Explain:** SHAP values for the predicted class, showing which features pushed the prediction up or down.
- **History & Alerts:** stored analyses, with automatic alerts for high-confidence attacks.
- **Dashboard:** total analyses, attack-type distribution, open alerts.
- **Accounts:** sign up, then log in.

## Requirements

- Python 3.11
- Node 24+ (npm 11+)

## Quick Start

Run in two terminals.

**Backend**
```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```
Check `http://localhost:8000/health`. It should return `{"status":"ok"}`.

**Frontend**
```bash
npm install
npm run dev
```
Open <http://localhost:5173>. Vite proxies `/api/*` to the backend.

**Use it**
1. Sign up (username ≥ 3 chars, password ≥ 4 chars), then log in.
2. Pick a preset or enter manual features, then click **Detect**.
3. Click **View Explanation** for the SHAP breakdown.

> Demo admin account: `admin` / `admin123`. Change it before any non-local use.

## Project Layout

```
NIDS_XAI/
├── backend/        # app.py (endpoints, prediction, SHAP), database.py, requirements.txt
├── ml/             # models/, data/, notebooks/, eval_report.json,
│                   # feature_defaults.json, pipeline_config.json, presets.csv
├── src/            # App.jsx, usePredict.js, main.jsx, styles.css
├── dist/           # production build
└── vercel.json     # optional Vercel config
```

## Scripts

```bash
npm run build   # production build to dist/
npm run lint
```

## Deployment Notes

- The backend is local-only by design. To host the frontend, run `npm run build`, deploy `dist/` to Vercel, and point the `/api` rewrite in `vercel.json` at a public backend.
- `nids.db` is created on first run. Copy it when moving machines, or history is lost.

## Limitations

- Trained and evaluated on NSL-KDD, which is dated; performance on modern traffic is untested.
- Manual mode uses imputed values for 35 of 41 features.
- Demo-grade authentication (see below).

## License

MIT