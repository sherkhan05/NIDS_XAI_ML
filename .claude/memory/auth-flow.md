---
name: auth-flow
description: User authentication flow for NIDS-XAI - signup then login
metadata:
  type: project

## Overview

NIDS-XAI uses a **signup → login → dashboard** flow. New users register first,
then sign in with the credentials they set.

## Backend (`backend/app.py`, `backend/database.py`)

- **`POST /register`** (public): creates a new user. Returns
  `{"token": "user:pass", "user": {...}}`. 409 if username taken.
- **`POST /login`** (public): verifies credentials, returns the same token
  shape. 401 if invalid.
- Token is a Basic-auth string (`username:password`) — the frontend stores it
  and reuses it for all subsequent authenticated requests.
- Passwords stored as SHA-256 hashes (intentional — never plaintext).
- Default admin `admin`/`admin123` still exists from `init_db()`.

## Frontend (`src/App.jsx`, `src/usePredict.js`)

- `AuthScreen` component (defined outside `App`) has **Sign Up / Login** tabs.
- `App` defaults to `authMode = 'signup'` so new users see signup first.
- After successful signup, `setCreds({username:'',password:''})` clears the form
  and switches to Login so the user types their own credentials.
- `useRegister()` hook in `usePredict.js` wraps `api.register()`.
- Error display uses `authError` only — `loginError`/`registerError` from the
  hooks do NOT leak across tabs (that caused a stale "Invalid credentials"
  message showing during Sign Up).

## Verified
- `npm run build` passes (19 modules).
- Register / duplicate-register / login / wrong-password / authenticated
  `/presets` all tested OK via curl.

## Notes
- Backend must be running (`uvicorn app:app --port 8000`) for the dev proxy to
  forward `/api/*` requests. Without it, signup shows "Unknown error".