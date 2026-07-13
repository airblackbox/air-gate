# AIR Blackbox Gate — The AI Action Firewall
# Multi-stage build for minimal image size

FROM python:3.12-slim AS base

# Prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install system deps (none needed currently, but keeps the pattern)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies ─────────────────────────────────────────────────
FROM base AS deps

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application ──────────────────────────────────────────────────
FROM deps AS app

# Copy application code
COPY air_gate/ ./air_gate/
COPY gate_config.yaml .
COPY pyproject.toml .

# Create data directory for SQLite
RUN mkdir -p /data

# Default environment
ENV GATE_SIGNING_KEY=change-me-in-production \
    GATE_STORAGE_PATH=/data/gate_events.db \
    GATE_CONFIG_PATH=gate_config.yaml \
    PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "air_gate.proxy:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
