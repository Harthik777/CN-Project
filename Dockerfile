FROM node:24-bookworm-slim AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN cd frontend && npm ci
COPY frontend ./frontend
COPY assets/dashboard_data.json ./assets/dashboard_data.json
COPY artifacts/packet_flow/browser_model.json artifacts/packet_flow/sample_capture.pcap ./artifacts/packet_flow/
RUN cd frontend && npm run build

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 HOME=/home/app \
    SENTINEL_DB_PATH=/home/app/state/sentinel.sqlite3
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 app
WORKDIR /home/app/project
COPY requirements-api.txt requirements-dev.txt ./
RUN pip install --no-cache-dir torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements-api.txt
COPY --chown=app:app config.py ./
COPY --chown=app:app src ./src
COPY --chown=app:app backend ./backend
COPY --chown=app:app artifacts/model_bundle.joblib artifacts/autoencoder.pt artifacts/sequence_autoencoder.pt ./artifacts/
COPY --chown=app:app artifacts/packet_flow ./artifacts/packet_flow
COPY --chown=app:app docs/THIRD_PARTY_NOTICES.md ./THIRD_PARTY_NOTICES.md
COPY --from=frontend-build --chown=app:app /build/assets/SentinelUEBA-React-Console.html ./assets/SentinelUEBA-React-Console.html
COPY --from=frontend-build --chown=app:app /build/assets/sw.js ./assets/sw.js
RUN mkdir -p /home/app/state && chown -R app:app /home/app
USER app
EXPOSE 7860
HEALTHCHECK --interval=30s --start-period=90s --timeout=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/api/health',timeout=8)"
CMD ["python", "-m", "uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1", "--no-access-log"]
