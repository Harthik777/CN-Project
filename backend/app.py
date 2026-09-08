"""Public, bounded replay API. Run one worker against a durable local volume."""
import hashlib
import json
import logging
import os
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.schemas import Batch, Feedback, NewSession
from backend.scenarios import scenarios
from backend.store import MAX_EVENTS, Store

ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("sentinel.api")


class ModelScorer:
    def __init__(self):
        import torch
        from src.inference import load_models
        torch.set_num_threads(1)
        self.models = load_models()
        digest = hashlib.sha256()
        paths = [ROOT / "artifacts" / f for f in
                 ("model_bundle.joblib", "autoencoder.pt", "sequence_autoencoder.pt")]
        paths += sorted((ROOT / "src").glob("*.py")) + [ROOT / "config.py"]
        for path in paths:
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
        self.model_id = digest.hexdigest()
        self.thresholds = {k: float(v["threshold"]) for k, v in self.models[0]["thresholds"].items()}

    def __call__(self, events, policy):
        import pandas as pd
        from src.inference import score
        result = score(pd.DataFrame(events), policy=policy, models=self.models, use_feedback=False)
        # Ground truth is unavailable at inference and is not returned as normal.
        result = result.drop(columns=["label", "scenario"], errors="ignore")
        output = json.loads(result.to_json(orient="records", date_format="iso", double_precision=15))
        timestamps = {row["event_id"]: row["timestamp"] for row in events}
        for row in output:
            row["timestamp"] = timestamps[row["event_id"]]
        return output


def create_app(db_path=None, scorer=None):
    store = Store(db_path or os.getenv("SENTINEL_DB_PATH", str(ROOT / "output" / "service" / "sentinel.sqlite3")))

    @asynccontextmanager
    async def lifespan(app):
        app.state.scorer = scorer or ModelScorer()
        yield

    app = FastAPI(title="SentinelUEBA Live Replay API", version="3.0.0", lifespan=lifespan,
                  description="Real model inference on bounded chronological replays. Synthetic demonstration inputs; no production detection claims.")
    app.state.store = store
    bearer = HTTPBearer(auto_error=False)

    def token(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if not credentials:
            raise HTTPException(401, "Session bearer token required")
        return credentials.credentials

    # A global bounded request window avoids unbounded attacker-controlled keys.
    request_times, creation_times = deque(), deque()
    rate_lock = threading.Lock()

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if request.method == "POST":
            now = time.monotonic()
            with rate_lock:
                for window in (request_times, creation_times):
                    while window and window[0] < now-60:
                        window.popleft()
                if len(request_times) >= 120 or (request.url.path == "/api/sessions" and len(creation_times) >= 20):
                    return JSONResponse({"detail": "Demo request limit reached; retry in one minute"}, status_code=429, headers={"Retry-After": "60"})
                request_times.append(now)
                if request.url.path == "/api/sessions":
                    creation_times.append(now)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 512*1024:
                    return JSONResponse({"detail": "Request exceeds 512 KiB"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(status_code=422, content={"detail": "; ".join(
            f"{'.'.join(map(str, error['loc']))}: {error['msg']}" for error in exc.errors()[:8])})

    @app.get("/api/health")
    def health():
        model = app.state.scorer
        with store.connect() as db:
            db.execute("SELECT 1").fetchone()
        return {"status": "ok", "version": "3.0.0", "model_id": model.model_id,
                "thresholds": model.thresholds, "max_events": MAX_EVENTS,
                "storage": os.getenv("SENTINEL_STORAGE_LABEL", "SQLite on host disk; 24-hour demo sessions"),
                "inference": "saved models, past-only features, chronological event-log replay",
                "benchmark": "synthetic; live session outcomes are not benchmark metrics"}

    @app.get("/api/scenarios")
    def demo_scenarios():
        return scenarios()

    @app.post("/api/sessions", status_code=201)
    def create_session(body: NewSession):
        return store.create(body.policy, app.state.scorer.model_id)

    @app.get("/api/sessions/{sid}")
    def session(sid: str, credential: str = Depends(token)):
        return store.snapshot(sid, credential)

    @app.post("/api/sessions/{sid}/events")
    def ingest(sid: str, body: Batch, credential: str = Depends(token)):
        try:
            return store.ingest(sid, credential,
                [e.model_dump(mode="json") for e in body.events],
                app.state.scorer, app.state.scorer.model_id)
        except HTTPException:
            raise
        except Exception:
            log.exception("Scoring failed; transaction rolled back")
            raise HTTPException(503, "Scoring failed; no events were committed. Retry or check service health.")

    @app.post("/api/sessions/{sid}/feedback")
    def feedback(sid: str, body: Feedback, credential: str = Depends(token)):
        return store.save_feedback(sid, credential, body.model_dump())

    @app.get("/")
    def index():
        return FileResponse(ROOT / "assets" / "SentinelUEBA-React-Console.html")

    # CORS also wraps early body-size and rate-limit responses.
    app.add_middleware(CORSMiddleware,
        allow_origins=[v.strip() for v in os.getenv("SENTINEL_ALLOWED_ORIGINS", "https://harthik777.github.io,http://127.0.0.1:8765,http://localhost:5173").split(",") if v.strip()],
        allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])
    return app


app = create_app()
