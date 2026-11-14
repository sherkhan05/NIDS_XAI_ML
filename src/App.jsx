import React, { useState, useEffect } from 'react'
import api, { usePredict, usePresets, useAuth, useRegister } from './usePredict'
import './styles.css'

// Defined OUTSIDE App so it is a stable component type — otherwise React
// remounts the form on every keystroke and the cursor jumps out of the field.
function AuthScreen({ mode, creds, onChange, onSubmit, error, submitLabel, onSwitchMode }) {
  const [showPassword, setShowPassword] = useState(false)

  return (
    <div className="login-wrapper">
      <div className="login-card-box">
        <h2>NIDS-XAI</h2>
        <p>Network Intrusion Detection System</p>

        <div className="input-mode-tabs" style={{ marginBottom: '20px' }}>
          <button
            className={`mode-btn ${mode === 'login' ? 'active' : ''}`}
            onClick={() => onSwitchMode('login')}
          >
            Login
          </button>
          <button
            className={`mode-btn ${mode === 'signup' ? 'active' : ''}`}
            onClick={() => onSwitchMode('signup')}
          >
            Sign Up
          </button>
        </div>

        <form onSubmit={onSubmit}>
          <div className="form-group" style={{ marginBottom: '16px' }}>
            <label>Username</label>
            <input
              type="text"
              value={creds.username}
              onChange={onChange}
              name="username"
              required
              minLength={3}
            />
          </div>
          <div className="form-group" style={{ marginBottom: '20px', position: 'relative' }}>
            <label>Password</label>
            <input
              type={showPassword ? 'text' : 'password'}
              value={creds.password}
              onChange={onChange}
              name="password"
              required
              minLength={4}
              style={{ paddingRight: '40px' }}
            />
            <button
              type="button"
              onClick={() => setShowPassword(v => !v)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              style={{
                position: 'absolute',
                right: '8px',
                bottom: '8px',
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--text-muted)',
                padding: '4px',
                borderRadius: '4px',
              }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-h)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
            >
              {showPassword ? (
                // Eye with a slash through it
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                  <path d="M9.88 9.88a3 3 0 0 0 4.24 4.24" />
                </svg>
              ) : (
                // Open eye
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              )}
            </button>
          </div>
          {error && <div style={{ color: 'red', fontSize: '0.85rem', marginBottom: '16px' }}>{error}</div>}
          <button type="submit" className="btn-dark" style={{ width: '100%', padding: '12px' }}>{submitLabel}</button>
        </form>
      </div>
    </div>
  )
}

function PredictSection({
  subView,
  prediction,
  inputMode,
  selectedPresetIdx,
  manualData,
  presets,
  presetsLoading,
  presetsError,
  predictLoading,
  predictError,
  onSetInputMode: setInputMode,
  onSetPresetIdx: setSelectedPresetIdx,
  onManualChange: handleManualChange,
  onExecute: handleExecute,
  onSetSubView: setSubView,
  onSetPrediction: setPrediction,
}) {
  if (subView === 'explanation' && prediction) {
      return (
        <div className="dashboard-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
            <h2 className="section-title" style={{ margin: 0 }}>Explainable AI - SHAP Analysis</h2>
            <button className="btn-outline" onClick={() => setSubView('result')}>&lt; Back to Result</button>
          </div>
          <p style={{ color: 'var(--text-muted)', marginBottom: '20px' }}>
            Why was this flow classified as <strong>{prediction.prediction}</strong>?
          </p>
          <div className="shap-container">
            {prediction.explanation?.features?.map((feat, idx) => {
              const isPos = feat.shap_value >= 0
              const absVal = Math.abs(feat.shap_value)
              const widthPct = Math.min(100, Math.max(10, absVal * 40))
              return (
                <div key={idx} className="shap-row">
                  <span className="shap-name">{feat.name}</span>
                  <div className="shap-bar-track">
                    <div
                      className={`shap-bar ${isPos ? 'positive' : 'negative'}`}
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                  <span className="shap-val">{feat.shap_value >= 0 ? '+' : ''}{feat.shap_value.toFixed(4)}</span>
                </div>
              )
            })}
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '24px' }}>
            Positive values push the prediction toward the predicted class; negative values push away.
          </p>
        </div>
      )
    }

    if (subView === 'result' && prediction) {
      return (
        <div className="dashboard-card">
          <h2 className="section-title">Detection Result</h2>
          <div className="results-grid">
            <div className={`result-box primary ${prediction.is_attack ? 'attack' : ''}`}>
              <div className="result-label" style={{ color: prediction.is_attack ? 'var(--accent-red)' : 'var(--accent-green)' }}>Prediction</div>
              <div className={`result-value ${prediction.is_attack ? 'attack' : 'normal'}`}>
                {prediction.is_attack ? 'ATTACK' : 'NORMAL'}
              </div>
              <div className="result-sub">Confidence: {(prediction.model_score * 100).toFixed(1)}%</div>
            </div>
            <div className="result-box">
              <div className="result-label">Attack Category</div>
              <div className="result-value" style={{ color: prediction.is_attack ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                {prediction.prediction}
              </div>
              <div className="result-sub">Classification completed in &lt; 2 seconds (target)</div>
            </div>
          </div>

          <div className="input-summary-section">
            <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '12px' }}>Input summary</h3>
            <div className="summary-grid">
              <div className="summary-item">
                <label>Protocol</label>
                <span>{prediction.mode === 'preset' ? presets?.[selectedPresetIdx]?.protocol_type : manualData.protocol_type}</span>
              </div>
              <div className="summary-item">
                <label>Service</label>
                <span>{prediction.mode === 'preset' ? presets?.[selectedPresetIdx]?.service : manualData.service}</span>
              </div>
              <div className="summary-item">
                <label>Flag</label>
                <span>{prediction.mode === 'preset' ? presets?.[selectedPresetIdx]?.flag : manualData.flag}</span>
              </div>
              <div className="summary-item">
                <label>Duration</label>
                <span>{prediction.mode === 'preset' ? presets?.[selectedPresetIdx]?.duration : manualData.duration}</span>
              </div>
              <div className="summary-item">
                <label>Src Bytes</label>
                <span>{prediction.mode === 'preset' ? presets?.[selectedPresetIdx]?.src_bytes : manualData.src_bytes}</span>
              </div>
              <div className="summary-item">
                <label>Dst Bytes</label>
                <span>{prediction.mode === 'preset' ? presets?.[selectedPresetIdx]?.dst_bytes : manualData.dst_bytes}</span>
              </div>
            </div>
          </div>

          <div className="action-buttons">
            <button className="btn-dark" onClick={() => setSubView('explanation')}>View Explanation</button>
            <button className="btn-outline" onClick={() => { setPrediction(null); setSubView('input'); }}>New Detection</button>
          </div>
        </div>
      )
    }

    return (
      <div className="dashboard-card">
        <h2 className="section-title">Network Traffic Sample Input</h2>
        <div className="input-mode-tabs">
          <button
            className={`mode-btn ${inputMode === 'preset' ? 'active' : ''}`}
            onClick={() => setInputMode('preset')}
          >
            Preset Sample
          </button>
          <button
            className={`mode-btn ${inputMode === 'manual' ? 'active' : ''}`}
            onClick={() => setInputMode('manual')}
          >
            Manual Input
          </button>
        </div>

        <form onSubmit={handleExecute}>
          {inputMode === 'preset' ? (
            <div className="form-group" style={{ marginBottom: '24px' }}>
              <label>Select KDDTest+ Preset Sample</label>
              {presetsLoading ? (
                <div>Loading presets...</div>
              ) : presetsError ? (
                <div style={{ color: 'red' }}>Error: {presetsError}</div>
              ) : (
                <select
                  value={selectedPresetIdx}
                  onChange={(e) => setSelectedPresetIdx(Number(e.target.value))}
                >
                  {presets?.map((p) => (
                    <option key={p.index} value={p.index}>
                      Row {p.index} — Protocol: {p.protocol_type}, Service: {p.service}, Flag: {p.flag}, True: {p.true_class} ({p.attack_type})
                    </option>
                  ))}
                </select>
              )}
            </div>
          ) : (
            <div className="form-grid">
              <div className="form-group">
                <label>Protocol Type</label>
                <select name="protocol_type" value={manualData.protocol_type} onChange={handleManualChange}>
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                  <option value="icmp">icmp</option>
                </select>
              </div>
              <div className="form-group">
                <label>Service</label>
                <select name="service" value={manualData.service} onChange={handleManualChange}>
                  {['http', 'ftp', 'smtp', 'telnet', 'private', 'domain_u', 'eco_i', 'ecr_i', 'finger', 'other'].map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Flag</label>
                <select name="flag" value={manualData.flag} onChange={handleManualChange}>
                  {['SF', 'S0', 'REJ', 'RSTO', 'SH', 'OTH'].map(f => (
                    <option key={f} value={f}>{f}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Duration</label>
                <input type="number" name="duration" value={manualData.duration} onChange={handleManualChange} step="0.1" />
              </div>
              <div className="form-group">
                <label>Source Bytes</label>
                <input type="number" name="src_bytes" value={manualData.src_bytes} onChange={handleManualChange} />
              </div>
              <div className="form-group">
                <label>Destination Bytes</label>
                <input type="number" name="dst_bytes" value={manualData.dst_bytes} onChange={handleManualChange} />
              </div>
            </div>
          )}

          <div className="form-footer">
            <button type="submit" className="btn-detect" disabled={predictLoading}>
              {predictLoading ? 'Analyzing...' : 'Detect'}
            </button>
          </div>
          {predictError && <div style={{ color: 'red', marginTop: '12px' }}>Error: {predictError}</div>}
        </form>
      </div>
    )
  }


function App() {
  // The backend stores timestamps as UTC strings (e.g. "2026-11-03 09:53:40").
  // Force UTC rendering so the browser's local timezone (PST/UTC-8) doesn't
  // shift the displayed time by 8 hours.
  const formatTime = (ts) =>
    new Date(ts).toLocaleTimeString('en-US', { timeZone: 'UTC' })

  const [activeTab, setActiveTab] = useState('predict')
  const [subView, setSubView] = useState('input') // 'input', 'result', 'explanation'
  const [prediction, setPrediction] = useState(null)
  // Increments after each new detection so History/Stats re-fetch fresh data.
  const [dataVersion, setDataVersion] = useState(0)
  const [creds, setCreds] = useState({ username: '', password: '' })
  const [authReady, setAuthReady] = useState(false)
  // Manual-input form state lives here (in App) so PredictSection — which is
  // defined outside App — does not remount and wipe the fields on every render.
  const [inputMode, setInputMode] = useState('preset')
  const [selectedPresetIdx, setSelectedPresetIdx] = useState(0)
  const [manualData, setManualData] = useState({
    protocol_type: 'tcp',
    service: 'http',
    flag: 'SF',
    duration: 0,
    src_bytes: 0,
    dst_bytes: 5450
  })
  const { predict, loading: predictLoading, error: predictError, result } = usePredict()
  const { presets, loading: presetsLoading, error: presetsError, refetch: refetchPresets } = usePresets()
  const { isAuthenticated, loginError, login } = useAuth()
  const { register, loading: registerLoading, error: registerError } = useRegister()

  // Auth mode: 'signup' (default for new users) or 'login'.
  const [authMode, setAuthMode] = useState('signup')
  const [authError, setAuthError] = useState(null)

  // New users sign up first, then log in with the credentials they set.
  const handleAuthSubmit = (e) => {
    e.preventDefault()
    setAuthError(null)
    if (authMode === 'signup') {
      register(creds.username, creds.password)
        .then(() => {
          // Clear the form so the user types their own credentials on Login.
          setCreds({ username: '', password: '' })
          setAuthMode('login')
        })
        .catch((err) => setAuthError(err.message))
    } else {
      login(creds.username, creds.password).catch((err) => setAuthError(err.message))
    }
  }

  const handleSwitchMode = (mode) => {
    setAuthMode(mode)
    setAuthError(null)
  }

  const handleCredsChange = (e) => {
    const { name, value } = e.target
    setCreds(prev => ({ ...prev, [name]: value }))
  }

  const handleManualChange = (e) => {
    const { name, value } = e.target
    setManualData(prev => ({
      ...prev,
      [name]: ['duration', 'src_bytes', 'dst_bytes'].includes(name)
        ? parseFloat(value) || 0
        : value
    }))
  }

  // After successful auth, load presets (presets need a valid token).
  useEffect(() => {
    if (isAuthenticated) {
      setAuthReady(true)
      refetchPresets()
    }
  }, [isAuthenticated, refetchPresets])

  useEffect(() => {
    if (result) {
      setPrediction(result)
      setSubView('result')
      // Trigger a re-fetch of History & Stats so they show the just-saved flow.
      setDataVersion(v => v + 1)
    }
  }, [result])

  const handlePresetPrediction = (rowIndex) => {
    predict({ mode: 'preset', preset: { row_index: rowIndex } })
  }

  const handleManualPrediction = (manualData) => {
    predict({ mode: 'manual', manual: manualData })
  }

  const handleExecute = (e) => {
    e.preventDefault()
    if (inputMode === 'preset') {
      handlePresetPrediction(selectedPresetIdx)
    } else {
      handleManualPrediction(manualData)
    }
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case 'predict':
        return (
          <PredictSection
            subView={subView}
            prediction={prediction}
            inputMode={inputMode}
            selectedPresetIdx={selectedPresetIdx}
            manualData={manualData}
            presets={presets}
            presetsLoading={presetsLoading}
            presetsError={presetsError}
            predictLoading={predictLoading}
            predictError={predictError}
            onSetInputMode={setInputMode}
            onSetPresetIdx={setSelectedPresetIdx}
            onManualChange={handleManualChange}
            onExecute={handleExecute}
            onSetSubView={setSubView}
            onSetPrediction={setPrediction}
          />
        )
      case 'history':
        return <HistoryTab />
      case 'stats':
        return <StatsTab />
      case 'alerts':
        return <AlertsTab />
      default:
        return null
    }
  }


  const HistoryTab = () => {
    const [flows, setFlows] = useState([])
    const [loading, setLoading] = useState(true)
    const [filterPred, setFilterPred] = useState('')

    useEffect(() => {
      if (!isAuthenticated) return
      api.getHistory(50, 0, filterPred || null).then(data => {
        setFlows(data)
        setLoading(false)
      }).catch(() => setLoading(false))
    }, [isAuthenticated, dataVersion, filterPred])

    if (loading) return <div className="dashboard-card">Loading history...</div>

    return (
      <div className="dashboard-card">
        <h2 className="section-title">Detection History & Alerts</h2>
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Protocol</th>
              <th>Service</th>
              <th>Prediction</th>
              <th>Attack Type</th>
              <th>Confidence</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {flows.map(f => (
              <tr key={f.id}>
                <td>{formatTime(f.analyzed_at)}</td>
                <td>{f.protocol_type}</td>
                <td>{f.service}</td>
                <td>
                  <span className={f.is_attack ? 'badge-attack' : 'badge-normal'}>
                    {f.is_attack ? 'ATTACK' : 'NORMAL'}
                  </span>
                </td>
                <td>{f.prediction}</td>
                <td>{(f.model_score * 100).toFixed(1)}%</td>
                <td><span className="status-open">Open</span></td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <select
            style={{ padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)' }}
            value={filterPred}
            onChange={(e) => setFilterPred(e.target.value)}
          >
            <option value="">Filter: Attack Type (All)</option>
            <option value="DoS">DoS</option>
            <option value="Probe">Probe</option>
            <option value="R2L">R2L</option>
            <option value="U2R">U2R</option>
            <option value="Normal">Normal</option>
          </select>
          <button className="btn-dark" onClick={() => alert('Report export triggered!')}>Export Report</button>
        </div>
      </div>
    )
  }

  const StatsTab = () => {
    const [stats, setStats] = useState(null)
    const [alerts, setAlerts] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
      if (!isAuthenticated) return
      Promise.all([
        api.getStats(),
        api.getAlerts(50)
      ]).then(([statsData, alertsData]) => {
        setStats(statsData)
        setAlerts(alertsData)
        setLoading(false)
      }).catch(() => setLoading(false))
    }, [isAuthenticated, dataVersion])

    if (loading) return <div className="dashboard-card">Loading dashboard statistics...</div>
    if (!stats) return null

    const totalAttacks = Object.entries(stats.by_prediction)
      .filter(([k]) => k !== 'Normal')
      .reduce((sum, [, v]) => sum + v, 0)
    const normalCount = stats.by_prediction['Normal'] || 0

    return (
      <div className="dashboard-card">
        <h2 className="section-title">Analyst Dashboard</h2>
        <div className="stats-cards-grid">
          <div className="stat-card-box">
            <div className="stat-card-label">Total Analyses</div>
            <div className="stat-card-val">{stats.total_flows}</div>
          </div>
          <div className="stat-card-box">
            <div className="stat-card-label">Attacks Detected</div>
            <div className="stat-card-val" style={{ color: 'var(--accent-red)' }}>{totalAttacks}</div>
          </div>
          <div className="stat-card-box">
            <div className="stat-card-label">Normal</div>
            <div className="stat-card-val" style={{ color: 'var(--accent-green)' }}>{normalCount}</div>
          </div>
          <div className="stat-card-box">
            <div className="stat-card-label">Open Alerts</div>
            <div className="stat-card-val" style={{ color: 'var(--accent-yellow)' }}>{stats.open_alerts}</div>
          </div>
        </div>

        <div className="dashboard-grid-lower">
          <div className="distribution-section">
            <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '20px' }}>Attack Type Distribution</h3>
            {Object.entries(stats.by_prediction).map(([pred, count]) => {
              const maxCount = Math.max(...Object.values(stats.by_prediction), 1)
              const pct = (count / stats.total_flows) * 100
              const cssClass = pred.toLowerCase()
              return (
                <div key={pred} className="dist-bar-item">
                  <span style={{ fontWeight: '600', fontSize: '0.9rem' }}>{pred}</span>
                  <div className="dist-bar-track">
                    <div className={`dist-bar-fill ${cssClass}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{count}</span>
                </div>
              )
            })}
          </div>

          <div className="recent-alerts-box">
            <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '20px' }}>Recent Alerts</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {alerts.length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '10px 0' }}>
                  No alerts yet. Run a detection to generate one.
                </p>
              ) : (
                alerts.slice(0, 5).map(a => {
                  const colorMap = {
                    DoS: 'var(--accent-red)',
                    Probe: 'var(--accent-yellow)',
                    R2L: '#1e293b',
                    U2R: '#8b5cf6',
                    Normal: 'var(--accent-green)'
                  }
                  return (
                    <div key={a.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border-color)' }}>
                      <span style={{ color: colorMap[a.prediction] || 'var(--text-main)', fontWeight: '600' }}>{a.prediction}</span>
                      <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{(a.model_score * 100).toFixed(1)}% Confidence</span>
                      <span style={{ fontSize: '0.85rem' }}>{a.status}</span>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '24px' }}>
          The dashboard is designed for analyst review of predictions and explanations.
        </p>
      </div>
    )
  }

  const AlertsTab = () => {
    const [alerts, setAlerts] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
      if (!isAuthenticated) return
      api.getAlerts(50).then(data => {
        setAlerts(data)
        setLoading(false)
      }).catch(() => setLoading(false))
    }, [isAuthenticated, dataVersion])

    if (loading) return <div className="dashboard-card">Loading alerts...</div>

    return (
      <div className="dashboard-card">
        <h2 className="section-title">Detection History & Alerts</h2>
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Protocol</th>
              <th>Service</th>
              <th>Prediction</th>
              <th>Attack Type</th>
              <th>Confidence</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(a => (
              <tr key={a.id}>
                <td>{formatTime(a.created_at)}</td>
                <td>{a.protocol_type}</td>
                <td>{a.service}</td>
                <td>
                  <span className={a.prediction === 'Normal' ? 'badge-normal' : 'badge-attack'}>
                    {a.prediction === 'Normal' ? 'NORMAL' : 'ATTACK'}
                  </span>
                </td>
                <td>{a.prediction}</td>
                <td>{(a.model_score * 100).toFixed(1)}%</td>
                <td><span className="status-open">{a.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length === 0 && (
          <p style={{ color: 'var(--text-muted)', padding: '20px 0' }}>No alerts yet. Run a detection to create one.</p>
        )}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <select
            style={{ padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border-color)' }}
            disabled
          >
            <option value="">Filter: Attack Type (All)</option>
            <option value="DoS">DoS</option>
            <option value="Probe">Probe</option>
            <option value="R2L">R2L</option>
            <option value="U2R">U2R</option>
            <option value="Normal">Normal</option>
          </select>
          <button className="btn-dark" onClick={() => alert('Report export triggered!')}>Export Report</button>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return (
      <AuthScreen
        mode={authMode}
        creds={creds}
        onChange={handleCredsChange}
        onSubmit={handleAuthSubmit}
        error={authError}
        submitLabel={authMode === 'signup' ? 'Sign Up' : 'Login'}
        onSwitchMode={handleSwitchMode}
      />
    )
  }

  return (
    <div className="app-container">
      <header className="app-header">
        <h1>Analyst Dashboard</h1>
        <div className="header-right">
          <button className="logout-btn" onClick={() => { api.setToken(null); setIsAuthenticated(false); }}>Logout</button>
        </div>
      </header>

      <nav className="nav-tabs">
        <button
          className={`nav-tab ${activeTab === 'predict' ? 'active' : ''}`}
          onClick={() => { setActiveTab('predict'); setSubView('input'); }}
        >
          Predict
        </button>
        <button
          className={`nav-tab ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          History & Alerts
        </button>
        <button
          className={`nav-tab ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
        >
          Dashboard Stats
        </button>
      </nav>

      <main className="app-content">
        {renderTabContent()}
      </main>
    </div>
  )
}

export default App
