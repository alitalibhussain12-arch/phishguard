# ═══════════════════════════════════════════════════════════════
# PhishGuard AI — Dockerfile
# Multi-stage build for a lean production image
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Builder ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into a prefix
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="PhishGuard AI <github.com/yourusername/phishguard>" \
      version="1.0.0" \
      description="AI-powered phishing email detection tool"

# Create non-root user for security
RUN groupadd -r phishguard && useradd -r -g phishguard -d /app -s /sbin/nologin phishguard

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=phishguard:phishguard . .

# Create writable directories
RUN mkdir -p models datasets && \
    chown -R phishguard:phishguard /app

# Switch to non-root user
USER phishguard

# Environment defaults (override at runtime)
ENV FLASK_ENV=production \
    FLASK_DEBUG=false \
    PORT=5000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

# Default: start Gunicorn production server
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--threads", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "wsgi:application"]
