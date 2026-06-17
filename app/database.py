"""
PhishGuard AI - Database Layer
SQLite-backed storage for analysis history.
"""

import json
import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path("phishguard.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TEXT    NOT NULL,
                source      TEXT    NOT NULL DEFAULT 'paste',
                filename    TEXT,
                subject     TEXT,
                sender      TEXT,
                classification  TEXT NOT NULL,
                is_phishing     INTEGER NOT NULL,
                phishing_prob   REAL NOT NULL,
                risk_level      TEXT NOT NULL,
                confidence      TEXT NOT NULL,
                indicator_count INTEGER NOT NULL DEFAULT 0,
                indicators_json TEXT,
                features_json   TEXT,
                model_name      TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_date
            ON analyses(analyzed_at DESC)
        """)
        conn.commit()
    logger.info("Database initialised.")


def save_analysis(result: Dict[str, Any], source: str = "paste",
                  filename: Optional[str] = None,
                  subject: str = "", sender: str = "") -> int:
    """Persist an analysis result. Returns the row id."""
    with get_connection() as conn:
        cur = conn.execute("""
            INSERT INTO analyses
                (analyzed_at, source, filename, subject, sender,
                 classification, is_phishing, phishing_prob,
                 risk_level, confidence, indicator_count,
                 indicators_json, features_json, model_name)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.utcnow().isoformat(),
            source,
            filename,
            subject[:255] if subject else "",
            sender[:255] if sender else "",
            result["classification"],
            int(result["is_phishing"]),
            result["phishing_probability"],
            result["risk"]["level"],
            result["confidence"],
            result.get("indicator_count", 0),
            json.dumps(result.get("indicators", [])),
            json.dumps(result.get("feature_values", {})),
            result.get("model_info", {}).get("name", ""),
        ))
        conn.commit()
        return cur.lastrowid


def get_history(limit: int = 50, offset: int = 0) -> List[Dict]:
    """Fetch analysis history, newest first."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, analyzed_at, source, filename, subject, sender,
                   classification, is_phishing, phishing_prob,
                   risk_level, confidence, indicator_count, model_name
            FROM analyses
            ORDER BY analyzed_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()
    return [dict(r) for r in rows]


def get_analysis(analysis_id: int) -> Optional[Dict]:
    """Fetch a single analysis by ID (includes full JSON fields)."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["indicators"] = json.loads(d.pop("indicators_json") or "[]")
    d["features"] = json.loads(d.pop("features_json") or "{}")
    return d


def get_stats() -> Dict[str, Any]:
    """Return aggregate statistics for the dashboard."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        phishing = conn.execute(
            "SELECT COUNT(*) FROM analyses WHERE is_phishing=1"
        ).fetchone()[0]
        safe = total - phishing
        by_risk = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT risk_level, COUNT(*) FROM analyses GROUP BY risk_level"
            ).fetchall()
        }
    return {
        "total": total,
        "phishing": phishing,
        "safe": safe,
        "phishing_rate": round(phishing / total * 100, 1) if total else 0,
        "by_risk": by_risk,
    }
