# NIDS-XAI — Project Context

Network Intrusion Detection System with Explainable AI (KDDTest+ dataset).
Two-tier web app: React/Vite frontend + FastAPI backend with XGBoost + SHAP.

## Run it (fully local, two terminals)

```bash
# Terminal 1 — backend
cd backend && pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000

# Terminal 2 — frontend
npm install && npm run dev   # open http://localhost:5173
```

The Vite dev server proxies `/api/*` to the backend. The backend loads models
from `../ml` at startup. `http://localhost:8000/health` returns `{"status":"ok"}`.

## Auth flow

Users **sign up first**, then log in with the credentials they set.
`POST /register` and `POST /login` are public; everything else needs the
Basic-auth token the frontend stores from those responses. Default admin:
`admin` / `admin123`.

Frontend: `AuthScreen` has Sign Up / Login tabs, defaults to Sign Up. After a
successful signup the form clears so the user types fresh credentials on Login.
The password field has an eye icon. Errors are shown via `authError` only —
`loginError`/`registerError` from the hooks must not leak across tabs.

## Key files

- `backend/app.py` — endpoints, prediction pipeline, SHAP, temperature scaling
- `backend/database.py` — users/flows/alerts, `create_user`/`user_exists`/`verify_user`
- `src/App.jsx` — tabs, auth screen, prediction UI
- `src/usePredict.js` — API client + React hooks (`usePredict`, `usePresets`, `useAuth`, `useRegister`)
- `vite.config.js` — dev proxy to backend; `outDir: 'dist'`
- `vercel.json` — `/api/*` rewrite to `${BACKEND_URL}` (only needed for public hosting)
- `ml/` — trained models, data, `eval_report.json`, `feature_defaults.json`, `pipeline_config.json`, `presets.csv`

## Conventions

- Backend is **local-only** by design. For a public frontend, deploy `dist/` to
  Vercel and set the `BACKEND_URL` env var.
- `npm run build` outputs to `dist/` inside the repo.
- Passwords are stored as SHA-256 hashes, never plaintext.
- `nids.db` is machine-local; copying the file is the only way to preserve flow
  history when moving the backend.

## Gotchas

- The backend **must be running** for the dev proxy to work — otherwise signup
  shows "Unknown error" (a non-JSON error page from the proxy).
- `error={authError || loginError || registerError}` in the auth screen leaks
  stale login errors into Sign Up mode. Use `error={authError}` and set it
  fresh on every attempt.
- `vite.config.js` used to write to `../dist` (outside the repo) — it's now
  `'dist'` so Vercel finds the build output.