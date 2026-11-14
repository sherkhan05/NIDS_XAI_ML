/**
 * API hook for NIDS-XAI backend.
 * Wraps fetch calls to the FastAPI backend (Basic auth).
 */
import { useState, useCallback, useEffect } from 'react';

const API_BASE = '/api';

class APIClient {
  constructor() {
    this.token = null;
  }

  setToken(token) {
    this.token = token;
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.token) {
      // Backend uses HTTPBasic; encode "username:password" WITHOUT trailing colon
      headers['Authorization'] = `Basic ${btoa(this.token)}`;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'omit',
    });

    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const error = await response.json();
        detail = error.detail || error.message || detail;
      } catch {
        // Body isn't JSON (e.g. a proxy 502 page) — show whatever it was.
        try {
          const text = await response.text();
          if (text) detail = text.slice(0, 200);
        } catch { /* ignore */ }
      }
      throw new Error(detail);
    }

    return response.json();
  }

  async predict(payload) {
    return this.request('/predict', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async register(payload) {
    return this.request('/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async login(payload) {
    return this.request('/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async listPresets() {
    return this.request('/presets');
  }

  async getHistory(limit = 50, offset = 0, prediction = null) {
    let url = `/history?limit=${limit}&offset=${offset}`;
    if (prediction) url += `&prediction=${encodeURIComponent(prediction)}`;
    return this.request(url);
  }

  async getStats() {
    return this.request('/stats');
  }

  async getAlerts(limit = 50, status = null) {
    let url = `/alerts?limit=${limit}`;
    if (status) url += `&status=${status}`;
    return this.request(url);
  }

  async getEvaluation() {
    return this.request('/eval');
  }

  async getConfusionMatrix() {
    return this.request('/eval/confusion-matrix');
  }

  async updateAlertStatus(alertId, status) {
    return this.request(`/alerts/${alertId}/status`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    });
  }
}

const api = new APIClient();

export function useAuth() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loginError, setLoginError] = useState(null);

  const login = useCallback(async (username, password) => {
    // Set the token BEFORE the async probe so concurrent hooks (presets/history)
    // that fire in the same render cycle carry valid credentials.
    api.setToken(`${username}:${password}`);
    try {
      // Probe with a cheap endpoint; if it 401s, creds are bad.
      await api.listPresets();
      setIsAuthenticated(true);
      setLoginError(null);
      return true;
    } catch (err) {
      api.setToken(null);
      setIsAuthenticated(false);
      setLoginError(err.message);
      return false;
    }
  }, []);

  return { isAuthenticated, loginError, login };
}

export function usePredict() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const predict = useCallback(async (payload) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.predict(payload);
      setResult(data);
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { predict, loading, error, result };
}

export function useRegister() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const register = useCallback(async (username, password) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.register({ username, password });
      // Store the token so subsequent requests are authenticated.
      api.setToken(data.token);
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { register, loading, error };
}

export function usePresets() {
  const [presets, setPresets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchPresets = useCallback(async () => {
    setError(null);
    try {
      const data = await api.listPresets();
      setPresets(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Do NOT auto-fetch on mount — the API requires a valid auth token first,
  // and the caller (App) controls when to load presets after authentication.
  return { presets, loading, error, refetch: fetchPresets };
}

export default api;