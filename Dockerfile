FROM python:3.12-slim
WORKDIR /pack
ENV PYTHONPATH=/pack
ENV PYTHONUNBUFFERED=1
ENV DRY_RUN=1
ENV CISO_PUSH=0
ENV RISKREADY_PUSH=0
ENV GRC_LIVE_SCAN=0
RUN pip install --no-cache-dir "pytest>=8.0"
COPY . /pack
CMD ["python", "collectors/grc_loader.py"]
