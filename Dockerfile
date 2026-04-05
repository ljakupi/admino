# Stage 1: builder — install Python dependencies into a prefix
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools only in builder stage
RUN pip install --no-cache-dir hatchling==1.27.0

COPY pyproject.toml .
COPY src/ src/

# Install the package and all runtime dependencies into /install prefix
RUN pip install --no-cache-dir --prefix=/install .

# -------------------------------------------------------------------
# Stage 2: runtime — minimal image with Tesseract + non-root user
# -------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Install system runtime dependencies
# tesseract-ocr: required by pytesseract for OCR on uploaded images
# tesseract-ocr-eng: English language data for Tesseract
# curl: used by healthcheck only; not available to application code
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user: uid=1000 matches typical host user to avoid
# volume permission issues. Container never runs as root.
RUN groupadd --gid 1000 admino \
    && useradd --uid 1000 --gid admino --no-create-home --shell /sbin/nologin admino

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source
WORKDIR /app
COPY --chown=admino:admino src/ src/

# Create data and config directories; they will be volume-mounted at runtime
# but must exist in the image so the container starts cleanly if volumes are empty
RUN mkdir -p /app/data/db /app/data/logs /app/data/images /app/data/tokens /app/config \
    && chown -R admino:admino /app

# Copy and enable the entrypoint script
COPY --chown=admino:admino entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

USER admino

EXPOSE 8000

# Health check: verify the HTTP server is responding before routing traffic
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
# NOTE: --host 0.0.0.0 is correct for Docker (bind to all container interfaces).
# config.yaml's server.host applies to non-Docker deployments only.
# Access logging is enabled so HTTP probes leave a trace for security observability.
CMD ["uvicorn", "admino.main:app", "--host", "0.0.0.0", "--port", "8000"]
