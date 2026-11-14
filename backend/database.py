"""
SQLite database operations for NIDS-XAI.
Stores flow analysis history and alert records.
"""
import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "nids.db")


def get_connection():
    """Get a SQLite connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_connection()
    cursor = conn.cursor()

    # Users table for basic login
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Flows table - stores each analyzed network flow
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            protocol_type TEXT NOT NULL,
            service TEXT NOT NULL,
            flag TEXT NOT NULL,
            duration REAL NOT NULL,
            src_bytes REAL NOT NULL,
            dst_bytes REAL NOT NULL,
            feature_json TEXT NOT NULL,
            prediction TEXT NOT NULL,
            is_attack BOOLEAN NOT NULL,
            attack_score REAL NOT NULL,
            model_score REAL NOT NULL,
            low_confidence BOOLEAN NOT NULL,
            top3 TEXT NOT NULL,
            explanation_json TEXT NOT NULL
        )
    """)

    # Alerts table - high-priority detections
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            reviewed_by INTEGER,
            reviewed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (flow_id) REFERENCES flows(id),
            FOREIGN KEY (reviewed_by) REFERENCES users(id)
        )
    """)

    # Create indexes for common queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_analyzed_at ON flows(analyzed_at DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_prediction ON flows(prediction)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")

    # Insert default admin user if not exists (password: admin123)
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        import hashlib
        pw_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       ("admin", pw_hash, "admin"))

    conn.commit()
    conn.close()


def save_flow(
    protocol_type: str,
    service: str,
    flag: str,
    duration: float,
    src_bytes: float,
    dst_bytes: float,
    feature_json: Dict[str, Any],
    prediction: str,
    is_attack: bool,
    attack_score: float,
    model_score: float,
    low_confidence: bool,
    top3: List[Dict[str, Any]],
    explanation_json: Dict[str, Any]
) -> int:
    """Save a flow analysis result and return the flow ID."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO flows (
            protocol_type, service, flag, duration, src_bytes, dst_bytes,
            feature_json, prediction, is_attack, attack_score, model_score,
            low_confidence, top3, explanation_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        protocol_type, service, flag, duration, src_bytes, dst_bytes,
        json.dumps(feature_json), prediction, is_attack, attack_score, model_score,
        low_confidence, json.dumps(top3), json.dumps(explanation_json)
    ))

    flow_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Auto-create alert for high-confidence attacks
    if is_attack and model_score >= 0.6:
        create_alert(flow_id, "high" if model_score >= 0.8 else "medium")

    return flow_id


def create_alert(flow_id: int, severity: str):
    """Create an alert for a flow."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (flow_id, severity, status)
        VALUES (?, ?, 'open')
    """, (flow_id, severity))

    conn.commit()
    conn.close()


def get_flows(limit: int = 100, offset: int = 0, prediction: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve flow history with optional filtering."""
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM flows"
    params = []

    if prediction:
        query += " WHERE prediction = ?"
        params.append(prediction)

    query += " ORDER BY analyzed_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_flow_stats() -> Dict[str, Any]:
    """Get summary statistics for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    # Total flows
    cursor.execute("SELECT COUNT(*) FROM flows")
    total = cursor.fetchone()[0]

    # By prediction type
    cursor.execute("""
        SELECT prediction, COUNT(*) as count
        FROM flows
        GROUP BY prediction
    """)
    by_prediction = {row[0]: row[1] for row in cursor.fetchall()}

    # Low confidence count
    cursor.execute("SELECT COUNT(*) FROM flows WHERE low_confidence = 1")
    low_conf = cursor.fetchone()[0]

    # Alert stats
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'open'")
    open_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    alerts_by_severity = {row[0]: row[1] for row in cursor.fetchall()}

    conn.close()

    return {
        "total_flows": total,
        "by_prediction": by_prediction,
        "low_confidence_count": low_conf,
        "open_alerts": open_alerts,
        "alerts_by_severity": alerts_by_severity
    }


def get_alerts(limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get alerts with flow details."""
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        SELECT a.*, f.prediction, f.model_score, f.protocol_type, f.service,
               f.duration, f.src_bytes, f.dst_bytes
        FROM alerts a
        JOIN flows f ON a.flow_id = f.id
    """
    params = []

    if status:
        query += " WHERE a.status = ?"
        params.append(status)

    query += " ORDER BY a.created_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def update_alert_status(alert_id: int, status: str, reviewed_by: int = 1):
    """Update alert status."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (status, reviewed_by, alert_id))

    conn.commit()
    conn.close()


def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify user credentials."""
    import hashlib
    pw_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
                   (username, pw_hash))
    row = cursor.fetchone()
    conn.close()

    return dict(row) if row else None


def user_exists(username: str) -> bool:
    """Check whether a username is already taken."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def create_user(username: str, password: str, role: str = "analyst") -> Optional[Dict[str, Any]]:
    """
    Register a new user. Returns the created user dict, or None if the
    username is already taken.
    """
    import hashlib
    pw_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, pw_hash, role),
        )
        conn.commit()
        user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return None
    finally:
        conn.close()

    return {"id": user_id, "username": username, "role": role}


# Initialize on import
init_db()