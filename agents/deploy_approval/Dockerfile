# Deploy Approval Agent image. Python 3.12. Official Docker Hub / PyPI defaults.
# PYPI_MIRROR must be HTTPS (TLS is always verified; --trusted-host is removed).
# Override mirrors via --build-arg MIRROR_BASE / --build-arg PYPI_MIRROR.
ARG MIRROR_BASE=docker.io
FROM ${MIRROR_BASE}/library/python:3.12-slim

ARG PYPI_MIRROR=https://pypi.org/simple

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY agents/deploy_approval/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -i "${PYPI_MIRROR}" -r requirements.txt

COPY agents/ /app/agents/
WORKDIR /app

EXPOSE 25001

# Non-root runtime user (no Docker socket / SSH mounted).
RUN groupadd -r app && useradd -r -g app -d /app -s /sbin/nologin app \
    && chown -R app:app /app
USER app

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://127.0.0.1:25001/healthz || exit 1

CMD ["python3", "-m", "agents.deploy_approval.server"]
