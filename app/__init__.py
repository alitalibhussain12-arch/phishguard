"""
PhishGuard AI - Flask Application Factory
"""

import os
import logging
from pathlib import Path

from flask import Flask

# Flask-Limiter is optional — degrades gracefully if not installed
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    _LIMITER_AVAILABLE = True
except ImportError:
    _LIMITER_AVAILABLE = False

from app.database import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class _NoOpLimiter:
    """Stub limiter used when flask-limiter is not installed."""
    def init_app(self, app): pass
    def limit(self, *a, **kw):
        def decorator(fn): return fn
        return decorator


if _LIMITER_AVAILABLE:
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "60 per hour"],
        storage_uri="memory://"
    )
else:
    logger.warning("flask-limiter not installed — rate limiting disabled. "
                   "Install with: pip install flask-limiter")
    limiter = _NoOpLimiter()


def create_app(config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32).hex()),
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        UPLOAD_EXTENSIONS={".eml", ".txt"},
        DEBUG=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
    if config:
        app.config.update(config)

    limiter.init_app(app)
    init_db()

    from app.routes import main_bp
    from api.routes import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    logger.info("PhishGuard AI application started.")
    return app
