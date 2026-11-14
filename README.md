# NIDS-XAI

Network Intrusion Detection System with Explainable AI.

A two-tier web application for detecting and classifying network attacks on the
KDDTest+ dataset, with per-prediction SHAP explanations so an analyst can see
**why** a flow was flagged.

## Architecture

```
┌─────────────────────────┐     /api/* (Vite dev proxy)
│   React + Vite UI       │ ────────────────────────┐
│   (src/, dist/)         │                         │
└─────────────────────────┘                         ▼
                                    ┌─────────────────────────┐
                                    │   FastAPI backend       │
                                    │   (backend/app.py)      │
                                    │   SQLite (nids.db)      │
                                    │   XGBoost + SHAP (ml/)  │
                                    └─────────────────────────┘
```

- **Frontend**: React 19 + Vite, served from `dist/`.
- **Backend**: FastAPI on `http://localhost:8000`. Loads the trained XGBoost
  models and SHAP explainer from `ml/` at startup.
- **ML**: two XGBoost models (binary Normal-vs-Attack, multiclass attack type),
  one-hot encoder, standard scaler, label encoder, temperature-scaled
  probabilities, and SHAP explanations.

## Features

- **Predict** — single-sample intrusion detection.
  - *Preset mode*: pick a real KDDTest+ row (scientifically valid baseline).
  - *Manual mode*: enter 6 human-readable features; the other 35 are filled
    from training medians/modes (clearly labelled as a rough demo).
- **Explainable AI** — SHAP analysis of the predicted class showing which
  features pushed the prediction up or down.
- **History & Alerts** — stored flow analyses and auto-generated alerts for
  high-confidence attacks.
- **Dashboard Stats** — total analyses, attack-type distribution, open alerts.
- **User accounts** — Sign Up / Login. New users register first, then sign in
  with the credentials they set.

## Quick Start (fully local)

Run these in **two separate terminals**.

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

The backend loads the models from `../ml` automatically. Visit
`http://localhost:8000/health` — it should return `{"status":"ok"}`.

### 2. Frontend

```bash
npm install
npm run dev
```

Open <http://localhost:5173>. The Vite dev server proxies `/api/*` to the
backend, so the app works as soon as both servers are up.

### 3. Use it

1. **Sign Up** with a username (≥3 chars) and password (≥4 chars).
2. On the next screen (Login), type the same credentials.
3. Pick a preset sample or enter manual features and click **Detect**.
4. Click **View Explanation** for the SHAP breakdown.

Default admin account (if you need it): `admin` / `admin123`.

## Project Layout

```
NIDS_XAI/
├── backend/                 # FastAPI app + SQLite DB
│   ├── app.py               # endpoints, prediction pipeline, SHAP
│   ├── database.py          # users, flows, alerts
│   ├── nids.db              # SQLite (created on first run)
│   └── requirements.txt
├── ml/                      # models, data, evaluation
│   ├── models/              # trained XGBoost + encoders (.pkl)
│   ├── data/                # KDDTest+ / KDDTrain+ / predictions
│   ├── eval_report.json     # accuracy, F1, confusion matrices
│   ├── feature_defaults.json
│   ├── pipeline_config.json
│   ├── presets.csv          # 20 preset samples for the UI
│   └── notebooks/           # training notebook
├── src/                     # React frontend
│   ├── App.jsx              # tabs, auth screen, prediction UI
│   ├── usePredict.js        # API client + React hooks
│   ├── main.jsx
│   └── styles.css
├── dist/                    # production build output
└── vercel.json              # Vercel config (optional, for hosting)
```

## Build / Lint

```bash
npm run build   # outputs to dist/
npm run lint
```

## Notes

- The backend is **local-only** by design (see the architecture above). To serve
  the frontend publicly, run `npm run build` and deploy `dist/` to Vercel —
  then point the `/api` rewrite in `vercel.json` at a publicly reachable backend.
- `nids.db` is created automatically on first backend run. If you move the
  backend to another machine, copy `backend/nids.db` or the flow history is lost.
- Passwords are stored as SHA-256 hashes, never in plaintext.