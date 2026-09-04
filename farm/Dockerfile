FROM python:3.12-slim
# PRIVATE farm worker. Orchestrator only. LICENSE-LOCK: no scanner packages.
# Build context is the repo root (see farm/docker-compose.yml).
WORKDIR /app
COPY dropbox /app/dropbox
COPY shared /app/shared
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DRY_RUN=1
ENV GRC_LIVE_SCAN=0
ENV CISO_PUSH=0
ENV RISKREADY_PUSH=0
ENV DROPBOX_DEMO=1
ENV DROPBOX_LIVE=0
ENV OUT_DIR=/out
ENV IN_DIR=/in
CMD ["python", "-m", "dropbox", "orchestrate"]
