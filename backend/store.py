"""Transactional event log. Model state is recovered by chronological replay.

This deliberately bounded service replays at most 1,000 events per session.
It trades throughput for auditable restart and chunk equivalence.
"""
import hashlib
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from fastapi import HTTPException

MAX_EVENTS = 1000
TTL_SECONDS = 86400


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript("""
              PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, token_hash TEXT NOT NULL,
                created REAL NOT NULL, policy TEXT NOT NULL, model_id TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS events (
                session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                event_id INTEGER NOT NULL, raw TEXT NOT NULL, scored TEXT NOT NULL,
                PRIMARY KEY(session,event_id));
              CREATE TABLE IF NOT EXISTS feedback (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                request_id TEXT NOT NULL, body TEXT NOT NULL, created REAL NOT NULL,
                UNIQUE(session,request_id));
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, policy, model_id):
        token, sid = secrets.token_urlsafe(32), secrets.token_hex(16)
        with self.lock, self.connect() as db:
            db.execute("DELETE FROM sessions WHERE created < ?", (time.time()-TTL_SECONDS,))
            if db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] >= 200:
                raise HTTPException(429, "Demo session capacity reached. Try again later.")
            db.execute("INSERT INTO sessions VALUES (?,?,?,?,?)",
                       (sid, hashlib.sha256(token.encode()).hexdigest(), time.time(), policy, model_id))
        return {"session_id": sid, "token": token, "expires_in_seconds": TTL_SECONDS}

    def authorize(self, db, sid, token):
        row = db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        digest = hashlib.sha256((token or "").encode()).hexdigest()
        if not row or not secrets.compare_digest(row["token_hash"], digest):
            raise HTTPException(401, "Invalid session credentials")
        if row["created"] < time.time()-TTL_SECONDS:
            raise HTTPException(410, "Demo session expired; start a new session")
        return dict(row)

    def snapshot(self, sid, token):
        with self.lock, self.connect() as db:
            session = self.authorize(db, sid, token)
            events = [json.loads(r[0]) for r in db.execute(
                "SELECT scored FROM events WHERE session=? ORDER BY event_id", (sid,))]
            events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
            feedback = [dict(json.loads(r["body"]), sequence=r["seq"], saved_at=r["created"])
                        for r in db.execute("SELECT * FROM feedback WHERE session=? ORDER BY seq", (sid,))]
            return {"session_id": sid, "policy": session["policy"],
                    "model_id": session["model_id"], "events": events, "feedback": feedback,
                    "expires_at": session["created"]+TTL_SECONDS, "max_events": MAX_EVENTS}

    def ingest(self, sid, token, events, scorer, model_id):
        # One process and a bounded queue: no concurrent writes or model calls.
        if not self.lock.acquire(blocking=False):
            raise HTTPException(429, "Scorer is busy. Retry this same batch shortly.")
        try:
            with self.connect() as db:
                session = self.authorize(db, sid, token)
                if session["model_id"] != model_id:
                    raise HTTPException(409, "Model version changed; start a new session")
                existing = {r["event_id"]: json.loads(r["raw"]) for r in db.execute(
                    "SELECT event_id,raw FROM events WHERE session=?", (sid,))}
                new = {}
                for event in events:
                    event_id = event["event_id"]
                    old = existing.get(event_id, new.get(event_id))
                    if old is not None:
                        if old != event:
                            raise HTTPException(409, f"event_id {event_id} has conflicting content")
                    else:
                        new[event_id] = event
                if len(existing)+len(new) > MAX_EVENTS:
                    raise HTTPException(422, f"Session limit is {MAX_EVENTS} events")
                key = lambda e: (e["timestamp"], e["event_id"])
                ordered = list(new.values())
                if ordered != sorted(ordered, key=key):
                    raise HTTPException(422, "Send events in timestamp/event_id order")
                if existing and ordered and key(ordered[0]) <= max(map(key, existing.values())):
                    raise HTTPException(409, "Late events are rejected; start a new chronological replay")
                started = time.perf_counter()
                if new:
                    full = sorted([*existing.values(), *new.values()], key=key)
                    output = scorer(full, session["policy"])
                    if len(output) != len(full) or {r["event_id"] for r in output} != {r["event_id"] for r in full}:
                        raise RuntimeError("Scorer returned inconsistent event IDs")
                    by_id = {e["event_id"]: e for e in output}
                    for event_id, raw in new.items():
                        db.execute("INSERT INTO events VALUES (?,?,?,?)",
                                   (sid, event_id, encode(raw), encode(by_id[event_id])))
                result = {"accepted": len(new), "duplicates": len(events)-len(new),
                          "total_events": len(existing)+len(new),
                          "scoring_ms": round((time.perf_counter()-started)*1000, 2)}
            return result
        finally:
            self.lock.release()

    def save_feedback(self, sid, token, body):
        with self.lock, self.connect() as db:
            self.authorize(db, sid, token)
            if not db.execute("SELECT 1 FROM events WHERE session=? AND event_id=?",
                              (sid, body["event_id"])).fetchone():
                raise HTTPException(404, "Event does not belong to this session")
            previous = db.execute("SELECT body FROM feedback WHERE session=? AND request_id=?",
                                  (sid, body["request_id"])).fetchone()
            if previous:
                if previous[0] != encode(body):
                    raise HTTPException(409, "Feedback request_id has conflicting content")
                return {"saved": False, "duplicate": True}
            if db.execute("SELECT COUNT(*) FROM feedback WHERE session=?", (sid,)).fetchone()[0] >= 2000:
                raise HTTPException(429, "Feedback capacity reached")
            db.execute("INSERT INTO feedback(session,request_id,body,created) VALUES (?,?,?,?)",
                       (sid, body["request_id"], encode(body), time.time()))
            return {"saved": True, "duplicate": False}
