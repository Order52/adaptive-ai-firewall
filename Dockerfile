# Production image for the AI-Adaptive-Firewall controller (CTRL01).
# Runs `afw serve`: pipeline + reconciler + HTTPS API + dashboard.
#
# Build:   docker build -t afw-controller .
# Run:     docker run -p 8080:8080 \
#            -v $PWD/config:/app/config:ro \
#            -v afw-secrets:/app/secrets \
#            -v afw-var:/app/var \
#            -e AFW_TLS_CERT=/app/secrets/pki/server.pem \
#            -e AFW_TLS_KEY=/app/secrets/pki/server.key \
#            afw-controller
#
# Secrets (API tokens, TLS keys, lab credentials) are never baked into the
# image — they are supplied at runtime via volumes/env vars, same as the
# bare-metal CTRL01 deployment (see docs/DEPLOYMENT.md).

FROM ghcr.io/astral-sh/uv:0.13.1 AS uv

FROM python:3.12-slim-bookworm AS builder

COPY --from=uv /uv /uvx /usr/local/bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-install-project --no-dev

COPY src ./src
COPY README.md ./
RUN uv sync --locked --no-dev

FROM python:3.12-slim-bookworm AS runtime

RUN groupadd --system afw && useradd --system --gid afw --home-dir /app afw
WORKDIR /app

COPY --from=builder --chown=afw:afw /app/.venv /app/.venv
COPY --chown=afw:afw config ./config

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    AFW_DATA_DIR=/app/var \
    AFW_API_TOKENS_FILE=/app/secrets/api_tokens.yaml

RUN mkdir -p /app/var /app/secrets && chown -R afw:afw /app/var /app/secrets

USER afw
EXPOSE 8080
VOLUME ["/app/var", "/app/secrets"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "\
import os, ssl, sys, urllib.request; \
scheme = 'https' if os.environ.get('AFW_TLS_CERT') else 'http'; \
ctx = ssl._create_unverified_context() if scheme == 'https' else None; \
sys.exit(0 if urllib.request.urlopen(f'{scheme}://127.0.0.1:8080/api/health', timeout=3, context=ctx).status == 200 else 1)"

ENTRYPOINT ["afw"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
