---
name: phases-completed
description: Summary of project phases and their completion status
metadata:
  type: project

## Project Overview

NIDS-XAI: Network Intrusion Detection System with Explainable AI, built on the
KDDTest+ dataset. Two-tier web app — React/Vite frontend + FastAPI backend with
XGBoost models and SHAP.

## Completed Phases

### Backend (`backend/`)
- FastAPI endpoints: `/predict`, `/presets`, `/history`, `/stats`, `/alerts`,
  `/eval`, `/eval/confusion-matrix`, plus public `/register` and `/login`.
- Model integration: XGBoost binary + multiclass, one-hot encoder, standard
  scaler, label encoder, temperature scaling, SHAP explanations.
- SQLite (`nids.db`) for users, flows, alerts.
- Auto-alerts for high-confidence attacks.

### ML Pipeline (`ml/`)
- Models trained and evaluated on KDDTest+; metrics in `eval_report.json`.
- Preprocessing pipeline (StandardScaler + OneHotEncoder) matches training.
- Presets (`presets.csv`) for the UI.

### Frontend (`src/`)
- React 19 + Vite dashboard: Predict, History & Alerts, Dashboard Stats, Alerts.
- AuthScreen with Sign Up / Login tabs; defaults to Sign Up.
- After signup the form clears so the user types fresh credentials on Login.
- Password field has an eye icon to toggle visibility.
- API client (`usePredict.js`) with React hooks; errors surface the real
  message instead of "Unknown error".

### Deployment prep
- `vercel.json` created: `/api/*` rewrite to `${BACKEND_URL}`, CORS headers.
- Build output fixed: `vite.config.js` `outDir` changed from `'../dist'` to
  `'dist'` so builds land inside the repo root.

## Verified
- `npm run build` passes (19 modules).
- Backend smoke tests via curl: health, register, duplicate-register (409),
  login, wrong-password (401), authenticated /presets.
- Dev proxy (`npm run dev`) forwards `/api/*` to the backend correctly.

## Remaining / Known
- Backend is local-only by design. For a public frontend, deploy `dist/` to
  Vercel and set the `BACKEND_URL` env var.
- `README.md` is the source of truth for run instructions.
- `nids.db` is machine-local; moving the backend loses flow history unless the
  file is copied.
- Passwords stored as SHA-256 hashes (intentional, not plaintext).