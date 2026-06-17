"""
PhishGuard AI - REST API
Endpoints: POST /api/analyze, POST /api/train, GET /api/health
"""

import logging
import tempfile
import os
from pathlib import Path

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

from app.database import save_analysis, get_history, get_stats
from ml.predictor import predict, predict_from_eml_text

logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__)


def _rate_limit(limit_str):
    """Apply rate limiting if flask-limiter is available, else no-op."""
    try:
        from app import limiter
        return limiter.limit(limit_str)
    except Exception:
        def noop(fn): return fn
        return noop


# ── Health ────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health():
    model_ready = Path("models/phishguard_best.pkl").exists()
    meta = {}
    if model_ready:
        try:
            import json
            with open("models/model_meta.json") as f:
                meta = json.load(f)
        except Exception:
            pass
    return jsonify({
        "status": "ok",
        "service": "PhishGuard AI",
        "version": "1.0.0",
        "model_ready": model_ready,
        "model_name": meta.get("model_name"),
        "model_trained_at": meta.get("trained_at"),
    }), 200


# ── Analyze ───────────────────────────────────────────────────────

@api_bp.route("/analyze", methods=["POST"])
def analyze():
    """
    POST /api/analyze
    JSON body or multipart .eml upload.
    """
    if not Path("models/phishguard_best.pkl").exists():
        return jsonify({"error": "Model not trained. POST /api/train first."}), 503

    try:
        if request.files.get("eml_file"):
            f = request.files["eml_file"]
            raw = f.read().decode("utf-8", errors="replace")
            result = predict_from_eml_text(raw)
            save_analysis(result, source="api-upload",
                          filename=secure_filename(f.filename or "upload.eml"))
            return jsonify(_format_result(result)), 200

        data = request.get_json(silent=True) or {}
        subject  = str(data.get("subject",  ""))[:2000]
        body     = str(data.get("body",     ""))[:50000]
        sender   = str(data.get("sender",   ""))[:500]
        reply_to = str(data.get("reply_to", ""))[:500]
        headers  = str(data.get("headers",  ""))[:5000]

        if not body and not subject:
            return jsonify({"error": "Provide 'body' or 'subject' field."}), 400

        result = predict(subject=subject, body=body,
                         sender=sender, reply_to=reply_to, headers=headers)
        save_analysis(result, source="api", subject=subject, sender=sender)
        return jsonify(_format_result(result)), 200

    except Exception as exc:
        logger.error(f"API analyze error: {exc}")
        return jsonify({"error": str(exc)}), 500


# ── Train ─────────────────────────────────────────────────────────

@api_bp.route("/train", methods=["POST"])
def train():
    """POST /api/train — train the model."""
    from ml.trainer import run_training_pipeline
    csv_path = None
    try:
        if request.files.get("dataset"):
            f = request.files["dataset"]
            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
                f.save(tmp.name)
                csv_path = tmp.name
        summary = run_training_pipeline(csv_path)
        return jsonify(summary), 200
    except Exception as exc:
        logger.error(f"API train error: {exc}")
        return jsonify({"error": str(exc)}), 500
    finally:
        if csv_path and os.path.exists(csv_path):
            os.unlink(csv_path)


# ── History ───────────────────────────────────────────────────────

@api_bp.route("/history", methods=["GET"])
def history():
    limit  = min(request.args.get("limit",  20, type=int), 100)
    offset = request.args.get("offset", 0, type=int)
    rows = get_history(limit=limit, offset=offset)
    return jsonify({"results": rows, "count": len(rows)}), 200


# ── Stats ─────────────────────────────────────────────────────────

@api_bp.route("/stats", methods=["GET"])
def stats():
    return jsonify(get_stats()), 200


# ── Helpers ───────────────────────────────────────────────────────

def _format_result(result: dict) -> dict:
    return {
        "classification":           result["classification"],
        "is_phishing":              result["is_phishing"],
        "phishing_probability":     result["phishing_probability"],
        "phishing_probability_pct": result["phishing_probability_pct"],
        "confidence":               result["confidence"],
        "risk": {
            "level": result["risk"]["level"],
            "label": result["risk"]["label"],
        },
        "indicators":      result.get("indicators", []),
        "indicator_count": result.get("indicator_count", 0),
        "model_info":      result.get("model_info", {}),
    }
