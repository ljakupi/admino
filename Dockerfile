# Stage 1: frontend-builder — compile the Vue PWA so a fresh clone (static/ is
# gitignored) can be built into a runnable image with no host-side npm build.
# Pin to a specific patch release to prevent silent supply-chain changes.
# For maximum reproducibility, pin to a digest:
#   FROM node:20.19.5-slim@sha256:<digest> AS frontend-builder
# Obtain the current digest with: docker inspect --format='{{index .RepoDigests 0}}' node:20.19.5-slim
FROM node:20.19.5-slim AS frontend-builder

WORKDIR /build/static-src

# Install dependencies first so this layer is cached unless package*.json changes
COPY static-src/package.json static-src/package-lock.json ./
RUN npm ci

# Copy the rest of the frontend source and build the production PWA.
# vite.config.ts sets outDir to ../static, so the build lands at /build/static.
COPY static-src/ ./
RUN npm run build

# -------------------------------------------------------------------
# Stage 2: builder — install Python dependencies into a prefix
# Pin to a specific patch release to prevent silent supply-chain changes.
# For maximum reproducibility, pin to a digest:
#   FROM python:3.12.8-slim@sha256:<digest> AS builder
# Obtain the current digest with: docker inspect --format='{{index .RepoDigests 0}}' python:3.12.8-slim
FROM python:3.12.8-slim AS builder

WORKDIR /build

# uv installs the dependencies from uv.lock. It lives in this stage only: the
# runtime stage copies /install and nothing else, so uv never ships. uv itself
# comes from PyPI, pinned to an exact version with hashes in requirements-uv.txt.
# UV_PYTHON_DOWNLOADS=never: uv must use this image's Python, never fetch one.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1 \
    UV_LINK_MODE=copy
COPY requirements-uv.txt .
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements-uv.txt

COPY pyproject.toml uv.lock ./

# Runtime dependencies: exactly the versions and hashes in uv.lock (no dev
# group, plus the `all-providers` extra so the image supports every provider
# selectable in config.yaml / Settings -> Agent without rebuilding). --locked
# fails the build when uv.lock is out of date with pyproject.toml; nothing
# resolves a version range here. --no-build: a package without a wheel fails
# the build instead of being built from source with unpinned build tools.
# The OpenAI SDK is a core dependency.
RUN uv export --locked --no-dev --extra all-providers --no-emit-project \
        --format requirements-txt --no-header --output-file /tmp/runtime.txt \
    && uv pip install --require-hashes --no-build --no-deps --compile-bytecode \
        --prefix /install -r /tmp/runtime.txt

# The build backend (hatchling) is locked too, in the `build` dependency group.
# It goes into a throwaway venv, never into /install.
RUN uv export --locked --only-group build --no-emit-project \
        --format requirements-txt --no-header --output-file /tmp/build.txt \
    && uv venv /opt/build-venv \
    && uv pip install --python /opt/build-venv --require-hashes --no-build --no-deps \
        -r /tmp/build.txt

# Build admino against that backend without build isolation (an isolated build
# would resolve build-system.requires from PyPI), then install the wheel.
COPY src/ src/
RUN uv build --wheel --no-build-isolation --python /opt/build-venv/bin/python \
        --out-dir /tmp/wheels \
    && uv pip install --no-deps --compile-bytecode --prefix /install /tmp/wheels/*.whl

# -------------------------------------------------------------------
# Stage 3: runtime — minimal image with a non-root user
# -------------------------------------------------------------------
FROM python:3.12.8-slim AS runtime

# Install system runtime dependencies
# iptables: egress whitelist enforcement in entrypoint.sh (requires NET_ADMIN cap)
# gosu:     drop from root to the unprivileged admino user in entrypoint.sh
#           AFTER the iptables rules are applied. iptables needs root/NET_ADMIN,
#           which a non-root process does NOT hold in its effective set even
#           with `cap_add: NET_ADMIN`, so the entrypoint must start as root.
# curl:     used by healthcheck only; not available to application code
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables \
        gosu \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user: uid=1000 matches typical host user to avoid
# volume permission issues. Container never runs as root.
RUN groupadd --gid 1000 admino \
    && useradd --uid 1000 --gid admino --no-create-home --shell /sbin/nologin admino

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source. Root-owned on purpose (no --chown): the document
# conversion child (GH-188) runs as admino, and a compromised parser must not be
# able to plant /app/admino or rewrite code the server imports on its next start.
WORKDIR /app
COPY src/ src/

# Copy PWA static files built by the frontend-builder stage. server.py
# resolves the static directory from /app/static when running inside the
# image (see server.py create_app). Root-owned (no --chown) so the conversion
# child cannot rewrite the JS served to every user.
COPY --from=frontend-builder /build/static/ /app/static/

# Create the config directory; it is volume-mounted at runtime but must exist
# in the image so the container starts cleanly if the volume is empty.
# /app/data/attachments is the mount point of the admino-attachments named
# volume (GH-187): a fresh named volume copies this directory's ownership, so
# creating it here (then chown -R below) gives admino a writable volume.
# Only /app/data is admino's: /app and /app/config stay root-owned.
RUN mkdir -p /app/config /app/data/attachments \
    && chown -R admino:admino /app/data

# Copy and enable the entrypoint script. Root-owned and execute-only for
# non-root (0555): the app process (admino, after the gosu drop) can execute it
# but NOT overwrite it. This closes a container-restart persistence vector where
# a compromised app rewrites the entrypoint to bypass egress enforcement on the
# next start. Nothing needs to modify it at runtime.
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0555 /entrypoint.sh

# The container starts as root ON PURPOSE: entrypoint.sh applies the iptables
# egress whitelist (which needs root/NET_ADMIN) and then drops to the
# unprivileged admino user via `gosu admino` before exec'ing the app. The
# application process therefore runs as admino (uid 1000), never as root.
# Do NOT add `USER admino` here — it would run the entrypoint unprivileged and
# iptables would fail with an empty effective capability set, aborting startup
# (or silently skipping enforcement). Privilege drop happens in entrypoint.sh.

EXPOSE 8000

# Health check: verify the HTTP server is responding before routing traffic
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
# NOTE: main.py calls uvicorn.run() internally after wiring all dependencies.
# PYTHONPATH is not needed because the package is installed into /usr/local by the builder stage.
# config.yaml's server.host applies to non-Docker deployments only.
# -P keeps the working directory (/app) off sys.path, so nothing planted there
# can shadow the installed admino package.
CMD ["python", "-P", "-m", "admino.main"]
