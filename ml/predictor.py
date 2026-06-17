"""
PhishGuard AI - Predictor
Runs phishing classification with explainability and risk scoring.
"""

import logging
from typing import Dict, Any, List

import numpy as np

from ml.feature_extractor import (
    extract_features, features_to_vector, explain_features
)
from ml.trainer import load_model

logger = logging.getLogger(__name__)

# ── Risk Level Thresholds ──────────────────────────────────────────────────────

RISK_LEVELS = [
    (0.85, "critical", "🔴 CRITICAL",  "#dc2626"),
    (0.65, "high",     "🟠 HIGH",      "#ea580c"),
    (0.40, "medium",   "🟡 MEDIUM",    "#ca8a04"),
    (0.00, "low",      "🟢 LOW",       "#16a34a"),
]


def probability_to_risk(prob: float) -> Dict[str, str]:
    """Convert phishing probability to a risk level."""
    for threshold, level, label, color in RISK_LEVELS:
        if prob >= threshold:
            return {"level": level, "label": label, "color": color}
    return {"level": "low", "label": "🟢 LOW", "color": "#16a34a"}


def confidence_label(prob: float) -> str:
    """Return a human-readable confidence description."""
    if prob >= 0.90 or prob <= 0.10:
        return "Very High"
    if prob >= 0.75 or prob <= 0.25:
        return "High"
    if prob >= 0.60 or prob <= 0.40:
        return "Moderate"
    return "Low"


# ── Core Prediction ────────────────────────────────────────────────────────────

def predict(
    subject: str = "",
    body: str = "",
    sender: str = "",
    reply_to: str = "",
    headers: str = ""
) -> Dict[str, Any]:
    """
    Classify an email as PHISHING or SAFE.

    Returns a rich result dict including:
        - classification  : "PHISHING" | "SAFE"
        - phishing_probability : float 0-1
        - confidence      : str
        - risk            : dict (level, label, color)
        - indicators      : list of triggered indicators with severity
        - feature_values  : raw feature dict for debugging
        - model_info      : model name and version from metadata
    """
    model, scaler, meta = load_model()

    # Extract features
    features = extract_features(
        subject=subject,
        body=body,
        sender=sender,
        reply_to=reply_to,
        headers=headers
    )
    vector = np.array(features_to_vector(features)).reshape(1, -1)
    vector_scaled = scaler.transform(vector)

    # Predict
    prediction = int(model.predict(vector_scaled)[0])
    try:
        proba = model.predict_proba(vector_scaled)[0]
        phishing_prob = float(proba[1])
    except AttributeError:
        phishing_prob = float(prediction)

    # Round for display
    phishing_prob_pct = round(phishing_prob * 100, 1)
    safe_prob_pct = round((1 - phishing_prob) * 100, 1)

    # Risk + confidence
    risk = probability_to_risk(phishing_prob)
    confidence = confidence_label(phishing_prob)

    # Explainability
    indicators = explain_features(features)

    # Sort indicators by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    indicators.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return {
        "classification": "PHISHING" if prediction == 1 else "SAFE",
        "is_phishing": bool(prediction),
        "phishing_probability": phishing_prob,
        "phishing_probability_pct": phishing_prob_pct,
        "safe_probability_pct": safe_prob_pct,
        "confidence": confidence,
        "risk": risk,
        "indicators": indicators,
        "indicator_count": len(indicators),
        "feature_values": features,
        "model_info": {
            "name": meta.get("model_name", "Unknown"),
            "version": meta.get("version", "1.0.0"),
            "trained_at": meta.get("trained_at", ""),
        }
    }


def predict_from_eml_text(raw_email: str) -> Dict[str, Any]:
    """
    Parse a raw .eml formatted string and run prediction.
    Handles basic RFC 2822 header parsing.
    """
    import email as email_lib

    try:
        msg = email_lib.message_from_string(raw_email)
        subject = msg.get("Subject", "") or ""
        sender = msg.get("From", "") or ""
        reply_to = msg.get("Reply-To", "") or ""

        # Extract text body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        body += part.get_payload(decode=True).decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        )
                    except Exception:
                        body += str(part.get_payload())
        else:
            try:
                body = msg.get_payload(decode=True).decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                body = str(msg.get_payload())

        # Reconstruct raw headers for header analysis
        headers = "\n".join(f"{k}: {v}" for k, v in msg.items())

    except Exception as exc:
        logger.warning(f"Failed to parse .eml, treating as plain text: {exc}")
        subject = ""
        sender = ""
        reply_to = ""
        body = raw_email
        headers = ""

    return predict(
        subject=subject,
        body=body,
        sender=sender,
        reply_to=reply_to,
        headers=headers
    )
