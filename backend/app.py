"""
FastAPI backend for NIDS-XAI (Network Intrusion Detection System with Explainable AI).

Serves:
- /predict: single-sample classification (preset or manual mode)
- /presets: list of preset KDDTest+ rows
- /history: stored flow analyses
- /stats: dashboard statistics
- /alerts: alert management
- /eval: precomputed evaluation data
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
import uvicorn

from database import (
    save_flow, get_flows, get_flow_stats, get_alerts, update_alert_status,
    verify_user, create_user, user_exists
)

# ============================================================================
# Load Model Artifacts
# ============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(os.path.dirname(BASE_DIR), "ml")

# Load models and preprocessors
clf_binary = joblib.load(os.path.join(ML_DIR, "models", "xgb_binary_tuned.pkl"))
clf_multi = joblib.load(os.path.join(ML_DIR, "models", "xgb_multi_model.pkl"))
encoder = joblib.load(os.path.join(ML_DIR, "models", "onehot_encoder.pkl"))
scaler = joblib.load(os.path.join(ML_DIR, "models", "standard_scaler.pkl"))
label_encoder = joblib.load(os.path.join(ML_DIR, "models", "label_encoder.pkl"))

# Load configs
with open(os.path.join(ML_DIR, "pipeline_config.json")) as f:
    pipeline_config = json.load(f)

with open(os.path.join(ML_DIR, "feature_defaults.json")) as f:
    feature_defaults = json.load(f)

# Load preset data
presets_df = pd.read_csv(os.path.join(ML_DIR, "presets.csv"))

# Load precomputed evaluation
with open(os.path.join(ML_DIR, "eval_report.json")) as f:
    eval_report = json.load(f)

# Extract config values
THRESHOLD = pipeline_config["binary_threshold"]  # 0.02
TEMPERATURE = pipeline_config["temperature"]  # 4.0635
LOW_CONF_THRESHOLD = pipeline_config["low_confidence_threshold"]  # 0.6
CLASS_ORDER = pipeline_config["class_order"]  # ["DoS", "Normal", "Probe", "R2L", "U2R"]

MANUAL_FIELDS = feature_defaults["manual_fields"]
DEFAULTS = feature_defaults["defaults"]
FEATURE_ORDER = feature_defaults["feature_order"]

# Categorical feature info
CAT_COLS = ["protocol_type", "service", "flag"]
NUM_COLS = [c for c in FEATURE_ORDER if c not in CAT_COLS]

# Class names from label encoder
CLASS_NAMES = list(label_encoder.classes_)

# Initialize SHAP explainer (lazy-loaded)
_explainer = None


def get_explainer():
    """Lazy-load SHAP TreeExplainer for the multiclass model."""
    global _explainer
    if _explainer is None:
        import shap
        _explainer = shap.TreeExplainer(clf_multi)
    return _explainer


# ============================================================================
# Helper Functions
# ============================================================================
def temp_scale(proba: np.ndarray, T: float) -> np.ndarray:
    """Temperature scaling: soften probabilities without changing labels."""
    L = np.log(np.clip(proba, 1e-12, 1.0)) / T
    L = L - L.max(axis=1, keepdims=True)
    E = np.exp(L)
    return E / E.sum(axis=1, keepdims=True)


def preprocess_raw(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply the exact same preprocessing as training:
    - Numeric features: StandardScaler (fitted on train)
    - Categorical: OneHotEncoder with handle_unknown='ignore'
    """
    # Ensure columns are in the correct order
    raw_df = raw_df[FEATURE_ORDER]

    # Numeric transformation
    num_transformed = pd.DataFrame(
        scaler.transform(raw_df[NUM_COLS]),
        columns=NUM_COLS,
        index=raw_df.index
    )

    # Categorical transformation
    cat_transformed = pd.DataFrame(
        encoder.transform(raw_df[CAT_COLS]),
        columns=encoder.get_feature_names_out(CAT_COLS),
        index=raw_df.index
    )

    # Combine in same order as training
    X = pd.concat([num_transformed, cat_transformed], axis=1)
    return X


def run_pipeline(raw_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Run the complete prediction pipeline on a raw feature DataFrame.
    Returns dict with prediction, scores, top3, and SHAP explanation.
    """
    X = preprocess_raw(raw_df)

    # Binary model: attack score
    p_attack = clf_binary.predict_proba(X)[:, 1]
    is_attack = p_attack >= THRESHOLD

    # Multiclass model: calibrated scores
    raw_proba = clf_multi.predict_proba(X)
    cal_proba = temp_scale(raw_proba, TEMPERATURE)

    normal_idx = CLASS_NAMES.index("Normal")

    # Determine final prediction
    attack_only_proba = cal_proba.copy()
    attack_only_proba[:, normal_idx] = -1  # exclude Normal when attack detected
    pred_idx = np.where(is_attack, attack_only_proba.argmax(axis=1), normal_idx)

    prediction = np.array(CLASS_NAMES)[pred_idx]
    model_score = cal_proba[np.arange(len(pred_idx)), pred_idx]
    low_confidence = model_score < LOW_CONF_THRESHOLD

    # Top-3 classes for each sample
    top3_list = []
    for i in range(len(cal_proba)):
        # Sort all classes by score descending
        sorted_indices = np.argsort(-cal_proba[i])
        # Ensure shown class is first
        shown = pred_idx[i]
        others = [j for j in sorted_indices if j != shown][:2]
        top3 = [{"class": CLASS_NAMES[j], "score": round(float(cal_proba[i, j]), 4)}
                for j in [shown] + others]
        top3_list.append(top3)

    # SHAP explanation for the predicted class
    explainer = get_explainer()
    shap_values = explainer.shap_values(X)

    # Multiclass SHAP returns a list of arrays (one per class).
    # Normalize to a single (n_samples, n_features) array indexed by class.
    if isinstance(shap_values, list):
        # shap_values[c] has shape (n_samples, n_features)
        shap_by_class = shap_values
    else:
        # Single array of shape (n_samples, n_features, n_classes)
        shap_by_class = [shap_values[:, :, c] for c in range(shap_values.shape[2])]

    explanations = []
    for i in range(len(X)):
        pred_class_idx = pred_idx[i]
        sample_sv = shap_by_class[pred_class_idx][i]

        # Top 5 features by absolute SHAP value
        top_indices = np.argsort(np.abs(sample_sv))[-5:][::-1]  # descending
        top_features = X.columns[top_indices]
        top_values = X.iloc[i, top_indices]
        top_shap = sample_sv[top_indices]

        explanations.append({
            "features": [
                {
                    "name": str(top_features[j]),
                    "value": float(top_values.iloc[j]),
                    "shap_value": float(top_shap[j])
                }
                for j in range(len(top_features))
            ]
        })

    # Build result
    results = []
    for i in range(len(raw_df)):
        results.append({
            "prediction": str(prediction[i]),
            "is_attack": bool(is_attack[i]),
            "attack_score": round(float(p_attack[i]), 4),
            "model_score": round(float(model_score[i]), 4),
            "low_confidence": bool(low_confidence[i]),
            "top3": top3_list[i],
            "explanation": explanations[i]
        })

    return results


# ============================================================================
# Pydantic Models
# ============================================================================
class ManualInput(BaseModel):
    """6 human-readable features for manual mode."""
    protocol_type: str = Field(..., description="tcp, udp, or icmp")
    service: str = Field(..., description="Service name (e.g., http, ftp, smtp)")
    flag: str = Field(..., description="TCP flag (e.g., SF, S0, REJ)")
    duration: float = Field(..., ge=0, description="Connection duration")
    src_bytes: float = Field(..., ge=0, description="Source to destination bytes")
    dst_bytes: float = Field(..., ge=0, description="Destination to source bytes")


class PresetInput(BaseModel):
    """Preset mode input."""
    row_index: int = Field(..., ge=0, description="Index into presets.csv")


class PredictRequest(BaseModel):
    """Unified prediction request."""
    mode: str = Field(..., pattern="^(preset|manual)$")
    manual: Optional[ManualInput] = None
    preset: Optional[PresetInput] = None


class PredictResponse(BaseModel):
    """Single prediction result."""
    model_config = {"protected_namespaces": ()}
    prediction: str
    is_attack: bool
    attack_score: float
    model_score: float
    low_confidence: bool
    top3: List[Dict[str, Any]]
    explanation: Dict[str, List[Dict[str, Any]]]
    mode: str
    is_demo_mode: bool = False  # True for manual mode


class PresetInfo(BaseModel):
    """Preset row summary for dropdown."""
    index: int
    protocol_type: str
    service: str
    flag: str
    duration: float
    src_bytes: float
    dst_bytes: float
    true_class: str
    attack_type: str


class StatsResponse(BaseModel):
    """Dashboard statistics."""
    total_flows: int
    by_prediction: Dict[str, int]
    low_confidence_count: int
    open_alerts: int
    alerts_by_severity: Dict[str, int]


class AlertResponse(BaseModel):
    """Alert with flow details."""
    id: int
    flow_id: int
    severity: str
    status: str
    created_at: str
    prediction: str
    model_score: float
    protocol_type: str
    service: str
    duration: float
    src_bytes: float
    dst_bytes: float


# ============================================================================
# FastAPI App
# ============================================================================
app = FastAPI(
    title="NIDS-XAI API",
    description="Network Intrusion Detection System with Explainable AI",
    version="1.0.0",
)

# CORS for React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Authentication (simple)
# ============================================================================
def get_current_user(
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """Simple auth dependency — requires valid username/password."""
    user = verify_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


# ============================================================================
# Endpoints (without /api prefix for nginx/vite proxy)
# ============================================================================
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=4)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    """Basic-auth token the frontend stores and reuses for all subsequent calls."""
    token: str
    user: Dict[str, Any]


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "ok", "version": "1.0.0"}


@app.post("/register", response_model=LoginResponse)
def register(req: RegisterRequest):
    """Public endpoint — create a new user account."""
    if user_exists(req.username):
        raise HTTPException(status_code=409, detail="Username already taken")
    user = create_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=409, detail="Username already taken")
    return LoginResponse(token=f"{req.username}:{req.password}", user=user)


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    """Public endpoint — authenticate and return a Basic-auth token."""
    user = verify_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return LoginResponse(token=f"{req.username}:{req.password}", user=user)


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest, user=Depends(get_current_user)):
    """
    Run single-sample intrusion detection.

    **Preset mode**: Uses a real KDDTest+ row (scientifically valid).
    **Manual mode**: User provides 6 features; 35 others auto-filled from training medians/modes.
    Results from manual mode are a ROUGH DEMO - clearly labeled as such.
    """
    if request.mode == "preset":
        if not request.preset:
            raise HTTPException(400, "preset required for preset mode")

        idx = request.preset.row_index
        if idx >= len(presets_df):
            raise HTTPException(404, f"Preset index {idx} not found (max {len(presets_df)-1})")

        row = presets_df.iloc[idx]
        # Get the 41 features for this preset row
        raw_row = row[FEATURE_ORDER].to_dict()
        is_demo = False

    elif request.mode == "manual":
        if not request.manual:
            raise HTTPException(400, "manual required for manual mode")

        # Start with all defaults
        raw_row = DEFAULTS.copy()
        # Override with user-provided 6 fields
        for field in MANUAL_FIELDS:
            raw_row[field] = getattr(request.manual, field)
        is_demo = True

    else:
        raise HTTPException(400, "mode must be 'preset' or 'manual'")

    # Create single-row DataFrame
    raw_df = pd.DataFrame([raw_row])

    # Run pipeline
    results = run_pipeline(raw_df)
    result = results[0]

    # Store in database
    flow_id = save_flow(
        protocol_type=raw_row["protocol_type"],
        service=raw_row["service"],
        flag=raw_row["flag"],
        duration=raw_row["duration"],
        src_bytes=raw_row["src_bytes"],
        dst_bytes=raw_row["dst_bytes"],
        feature_json=raw_row,
        prediction=result["prediction"],
        is_attack=result["is_attack"],
        attack_score=result["attack_score"],
        model_score=result["model_score"],
        low_confidence=result["low_confidence"],
        top3=result["top3"],
        explanation_json=result["explanation"]
    )

    return PredictResponse(
        **result,
        mode=request.mode,
        is_demo_mode=is_demo
    )


@app.get("/presets", response_model=List[PresetInfo])
def list_presets(user=Depends(get_current_user)):
    """List all preset KDDTest+ rows for dropdown."""
    presets = []
    for idx, row in presets_df.iterrows():
        presets.append(PresetInfo(
            index=idx,
            protocol_type=row["protocol_type"],
            service=row["service"],
            flag=row["flag"],
            duration=float(row["duration"]),
            src_bytes=float(row["src_bytes"]),
            dst_bytes=float(row["dst_bytes"]),
            true_class=row["class"],
            attack_type=row["attack_type"]
        ))
    return presets


@app.get("/history")
def get_history(
    limit: int = 50,
    offset: int = 0,
    prediction: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Get flow analysis history."""
    flows = get_flows(limit=limit, offset=offset, prediction=prediction)
    # Parse JSON fields
    for flow in flows:
        flow["feature_json"] = json.loads(flow["feature_json"])
        flow["top3"] = json.loads(flow["top3"])
        flow["explanation_json"] = json.loads(flow["explanation_json"])
    return flows


@app.get("/stats", response_model=StatsResponse)
def get_stats(user=Depends(get_current_user)):
    """Get dashboard statistics."""
    return get_flow_stats()


@app.get("/alerts", response_model=List[AlertResponse])
def list_alerts(
    limit: int = 50,
    status: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Get alerts."""
    return get_alerts(limit=limit, status=status)


@app.post("/alerts/{alert_id}/status")
def update_alert(
    alert_id: int,
    status: str,
    user=Depends(get_current_user)
):
    """Update alert status (open, investigating, resolved)."""
    if status not in ["open", "investigating", "resolved", "dismissed"]:
        raise HTTPException(400, "Invalid status")
    update_alert_status(alert_id, status, user["id"])
    return {"success": True}


@app.get("/eval")
def get_evaluation(user=Depends(get_current_user)):
    """Get precomputed evaluation report (static from notebook)."""
    return eval_report


@app.get("/eval/confusion-matrix")
def get_confusion_matrix(user=Depends(get_current_user)):
    """Get confusion matrix data for heatmap."""
    return {
        "multiclass": eval_report["multiclass"]["confusion_matrix"],
        "binary": eval_report["binary"]["confusion_matrix"],
        "labels": eval_report["classes"]
    }


# ============================================================================
# Main
# ============================================================================
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)