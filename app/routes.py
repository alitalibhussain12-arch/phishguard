"""
PhishGuard AI - Web Routes
Dashboard, analysis submission, and history views.
"""

import os
import logging
import tempfile
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, jsonify, current_app
)
from werkzeug.utils import secure_filename

from app.database import save_analysis, get_history, get_analysis, get_stats
from ml.predictor import predict, predict_from_eml_text

logger = logging.getLogger(__name__)
main_bp = Blueprint("main", __name__)


def _allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in current_app.config.get("UPLOAD_EXTENSIONS", {".eml", ".txt"})


# ── Dashboard ─────────────────────────────────────────────────────────────────

@main_bp.route("/")
def index():
    """Landing page / dashboard overview."""
    try:
        stats = get_stats()
        history = get_history(limit=5)
        model_ready = Path("models/phishguard_best.pkl").exists()
    except Exception as exc:
        logger.error(f"Index error: {exc}")
        stats = {"total": 0, "phishing": 0, "safe": 0, "phishing_rate": 0}
        history = []
        model_ready = False
    return render_template("index.html", stats=stats,
                           history=history, model_ready=model_ready)


# ── Analyze ───────────────────────────────────────────────────────────────────

@main_bp.route("/analyze", methods=["GET", "POST"])
def analyze():
    """Email analysis page — paste text or upload .eml."""
    if request.method == "GET":
        return render_template("analyze.html")

    source = "paste"
    subject = request.form.get("subject", "").strip()
    sender = request.form.get("sender", "").strip()
    reply_to = request.form.get("reply_to", "").strip()
    body = request.form.get("body", "").strip()
    filename = None

    # ── File upload path ──
    if "eml_file" in request.files:
        f = request.files["eml_file"]
        if f and f.filename and _allowed_file(f.filename):
            filename = secure_filename(f.filename)
            source = "upload"
            try:
                raw = f.read().decode("utf-8", errors="replace")
                try:
                    result = predict_from_eml_text(raw)
                except FileNotFoundError:
                    flash("Model not trained yet. Please run training first.", "warning")
                    return redirect(url_for("main.train_page"))
                row_id = save_analysis(result, source=source,
                                       filename=filename,
                                       subject=subject, sender=sender)
                return redirect(url_for("main.result", analysis_id=row_id))
            except Exception as exc:
                logger.error(f"File analysis error: {exc}")
                flash(f"Error analysing file: {exc}", "danger")
                return render_template("analyze.html")

    # ── Paste path ──
    if not body:
        flash("Please provide email content.", "warning")
        return render_template("analyze.html")

    try:
        result = predict(
            subject=subject, body=body,
            sender=sender, reply_to=reply_to
        )
    except FileNotFoundError:
        flash("Model not trained yet. Please run training first.", "warning")
        return redirect(url_for("main.train_page"))
    except Exception as exc:
        logger.error(f"Prediction error: {exc}")
        flash(f"Analysis error: {exc}", "danger")
        return render_template("analyze.html")

    row_id = save_analysis(result, source=source,
                           filename=filename, subject=subject, sender=sender)
    return redirect(url_for("main.result", analysis_id=row_id))


# ── Result ────────────────────────────────────────────────────────────────────

@main_bp.route("/result/<int:analysis_id>")
def result(analysis_id: int):
    """Display a single analysis result."""
    data = get_analysis(analysis_id)
    if not data:
        flash("Analysis not found.", "danger")
        return redirect(url_for("main.index"))
    return render_template("result.html", data=data)


# ── History ───────────────────────────────────────────────────────────────────

@main_bp.route("/history")
def history():
    """Analysis history page."""
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 20
    rows = get_history(limit=per_page, offset=(page - 1) * per_page)
    return render_template("history.html", rows=rows, page=page, per_page=per_page)


# ── Train ─────────────────────────────────────────────────────────────────────

@main_bp.route("/train", methods=["GET", "POST"])
def train_page():
    """Model training trigger page."""
    if request.method == "GET":
        return render_template("train.html")

    from ml.trainer import run_training_pipeline
    csv_path = None

    if "dataset" in request.files:
        f = request.files["dataset"]
        if f and f.filename:
            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
                f.save(tmp.name)
                csv_path = tmp.name

    try:
        summary = run_training_pipeline(csv_path)
        flash(summary["message"], "success")
    except Exception as exc:
        logger.error(f"Training error: {exc}")
        flash(f"Training failed: {exc}", "danger")
    finally:
        if csv_path and os.path.exists(csv_path):
            os.unlink(csv_path)

    return redirect(url_for("main.train_page"))


# ── Error handlers ────────────────────────────────────────────────────────────

@main_bp.app_errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404,
                           message="Page not found."), 404


@main_bp.app_errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413,
                           message="File too large (max 5 MB)."), 413


@main_bp.app_errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500,
                           message="Internal server error."), 500
