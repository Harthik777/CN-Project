# Live investigation service

The live console sends raw synthetic access events to FastAPI. The server computes features, executes the saved autoencoder, Isolation Forest, GRU and classifier/fusion models, and returns scores and explanations. Analyst decisions are written to a SQLite audit history and fetched back by the browser.

## Run locally

Use Python 3.11 and Node 24. From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-api.txt
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python -m uvicorn backend.app:app --host 127.0.0.1 --port 7860 --workers 1
```

Open `http://127.0.0.1:7860/#live`. API documentation is at `/docs`. Create a session, score the baseline, score the campaign, inspect an event and save a review. Refresh server state or reload the browser to retrieve the same events and audit history.

```powershell
.\.venv\Scripts\python scripts/smoke_api.py --url http://127.0.0.1:7860
.\.venv\Scripts\python -m unittest discover -s tests -v
```

The smoke script tests the running HTTP service, including actual model execution and persisted feedback; it does not read the static dashboard's saved scores.

## Protocol and state

| Route | Purpose |
|---|---|
| `GET /api/health` | Model/source identity, thresholds, limits and storage status |
| `GET /api/scenarios` | Raw synthetic baseline and campaign inputs |
| `POST /api/sessions` | Create a session and return its bearer capability once |
| `GET /api/sessions/{id}` | Retrieve that session's scored events and review history |
| `POST /api/sessions/{id}/events` | Validate and score up to 250 chronological raw events |
| `POST /api/sessions/{id}/feedback` | Append an idempotent analyst review |

Session operations require the bearer token returned on creation. Only its hash is stored in SQLite. The UI stores the capability in its browser, scoped to the API origin, and excludes it from evidence exports. Different visitors receive isolated sessions. This is capability-based demo access, not organisational user identity or role-based access control.

Each session pins the model/source identity and threshold policy. Changing policy creates a fresh session. Event IDs are unique per session. Identical repeated events are skipped; conflicting reuse is rejected with HTTP 409. New events must follow the committed stream in UTC timestamp/event-ID order. Late events are explicitly rejected rather than silently changing earlier predictions. All items are validated before any write.

SQLite stores raw events and their computed outputs transactionally. Every append rebuilds causal model state by replaying the stored prefix plus the new batch. This gives restart and chunk equivalence without pickling mutable model state. It is intentionally bounded to 1,000 events per session and is not a high-throughput streaming implementation. Run exactly one worker. A busy scorer returns 429; inference failure returns 503 without committing the batch.

Feedback keeps historical revisions and has a separate idempotency key. Feedback does not change live scores or trigger training. No visitor's decisions are used in another session. Requests reject extra fields, including target labels and supplied risk scores. Limits include a 512 KiB body, 250 events per request, 200 sessions, 2,000 feedback records per session, and a bounded global request rate. Sessions expire after 24 hours.

## Deployment contract

The included multi-stage Dockerfile builds the frontend from source using Node 24, then runs a single API worker on port 7860 and serves the frontend from the same origin. Open `/#live` for the connected view. Mount a durable local volume at `/home/app/state` to retain the database across container replacement. Container-local disk without a volume is ephemeral. SQLite WAL should not be placed directly on an object-store/FUSE bucket mount; use storage with SQLite-compatible locking and durability.

Configuration:

- `SENTINEL_DB_PATH`: SQLite path, defaulting to `output/service/sentinel.sqlite3` locally.
- `SENTINEL_ALLOWED_ORIGINS`: comma-separated browser origins. Defaults include the GitHub Pages origin and local development origins.
- `SENTINEL_STORAGE_LABEL`: the accurate storage/retention description shown to visitors.
- `VITE_API_BASE`: frontend build-time API origin when hosted separately. Omit when the backend serves the HTML itself, and open `/#live`.

The service is deployed on Render Free in Singapore at [sentinelueba-harthik.onrender.com](https://sentinelueba-harthik.onrender.com/#live). Render built the Docker image and the public API passed real inference and feedback smoke tests. GitHub Pages serves a second frontend connected to the same API. The configured free instance has 512 MB RAM and uses ephemeral disk; there is no persistent volume. Idle sleep and container replacement can discard sessions. The website URL is stable and does not require a local tunnel or the developer's computer. See [PUBLIC_DEPLOYMENT.md](PUBLIC_DEPLOYMENT.md) for service identity and evidence.

## Evidence and boundaries

Local verification passed 41 tests, including actual-model agreement for uninterrupted, chunked and restarted ingestion. Labels and flags matched exactly; numeric channels were checked with absolute/relative tolerance of `1e-6`. The 168-event demonstration has 120 baseline accesses and 48 staged campaign events. Under top 2%, all 48 campaign events were flagged and 56 baseline events were also flagged. These are demonstration outcomes, not a new held-out evaluation or a claim of real-world precision.

The original synthetic benchmark remains available in the Alerts, Topology and Model audit views. Its data, metrics and browser-only review/export flow are separate from the live session and server audit trail. A production release still needs independently labelled telemetry evaluation, durable hosted storage, organisational authentication, operational monitoring and a more scalable incremental state engine.
