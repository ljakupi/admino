# Stage 1: builder — install Python dependencies into a prefix
# Pin to a specific patch release to prevent silent supply-chain changes.
# For maximum reproducibility, pin to a digest:
#   FROM python:3.12.8-slim@sha256:<digest> AS builder
# Obtain the current digest with: docker inspect --format='{{index .RepoDigests 0}}' python:3.12.8-slim
FROM python:3.12.8-slim AS builder

WORKDIR /build

# Install build tools only in builder stage
RUN pip install --no-cache-dir hatchling==1.27.0

COPY pyproject.toml .
COPY src/ src/

# Install the package and all runtime dependencies into /install prefix.
# The `all-providers` extra bundles the Anthropic and OpenAI SDKs so the image
# supports any provider chosen in config.yaml (ollama / anthropic / openai)
# without rebuilding. Ollama uses only httpx and needs no extra.
RUN pip install --no-cache-dir --prefix=/install ".[all-providers]"

# -------------------------------------------------------------------
# Stage 2: runtime — minimal image with a non-root user
# -------------------------------------------------------------------
FROM python:3.12.8-slim AS runtime

# Install system runtime dependencies
# iptables: egress whitelist enforcement in entrypoint.sh (requires NET_ADMIN cap)
# curl: used by healthcheck only; not available to application code
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables \
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

# Copy PWA static files. server.py resolves the static directory from
# /app/static when running inside the image (see server.py create_app).
COPY --chown=admino:admino static/ /app/static/

# Create data and config directories; they will be volume-mounted at runtime
# but must exist in the image so the container starts cleanly if volumes are empty
RUN mkdir -p /app/data/logs /app/data/tokens /app/config /app/documents \
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
# NOTE: main.py calls uvicorn.run() internally after wiring all dependencies.
# PYTHONPATH is not needed because the package is installed into /usr/local by the builder stage.
# config.yaml's server.host applies to non-Docker deployments only.
CMD ["python", "-m", "admino.main"]
