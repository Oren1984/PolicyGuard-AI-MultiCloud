# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Trusts any extra CA certificates dropped in ./certs (e.g. a corporate or
# antivirus TLS-inspection root -- see docs/ENVIRONMENT_LIMITATIONS.md) before
# installing dependencies. The directory is empty by default (kept via
# certs/.gitkeep; real certs are gitignored), so this is a no-op on a normal,
# unrestricted network -- it does not weaken TLS verification, it only adds a
# locally-trusted root to the set already trusted.
COPY certs/ /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates

COPY pyproject.toml ./
COPY src ./src

# Only the runtime dependency set is installed here (pyproject.toml's
# top-level `dependencies`), never the `[dev]` extra (pytest/ruff/mypy/etc.)
# -- the final image is a runtime image, not a dev/test image.
# PIP_CERT points pip at the system CA bundle (which now includes any extra
# trusted root from ./certs above) instead of its own bundled certifi list.
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install .


FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system policyguard \
    && useradd --system --gid policyguard --home-dir /app --shell /usr/sbin/nologin policyguard

WORKDIR /app

COPY --from=builder /install /usr/local
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY templates ./templates
COPY static ./static
# demo/scripts/{run,seed_demo_data,reset_demo_data}.py -- so `docker compose
# exec app python demo/scripts/...` works without a separate host checkout.
COPY demo ./demo

RUN chown -R policyguard:policyguard /app

USER policyguard

EXPOSE 8000

# GET /health is a pure liveness check (no DB dependency) -- see
# src/api/routes/health.py -- so it's safe to use as the container
# healthcheck without coupling container health to database availability.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
