"""SQLite persistence for decoy telemetry."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    proto TEXT NOT NULL,
    path TEXT,
    score INTEGER NOT NULL,
    reasons TEXT NOT NULL,
    payload_hash TEXT,
    snippet TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_score ON events(score);
CREATE INDEX IF NOT EXISTS idx_events_proto ON events(proto);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_payload(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def clip_snippet(payload: str, max_len: int = 256) -> str:
    text = payload.replace("\x00", "")
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def redact_snippet(payload: str, password: str | None, max_len: int) -> str:
    text = payload.replace("\x00", "")
    if password and len(password) >= 3:
        text = text.replace(password, "***")
    return clip_snippet(text, max_len)


@dataclass(frozen=True)
class Event:
    timestamp: str
    src_ip: str
    src_port: int | None
    proto: str
    path: str | None
    score: int
    reasons: list[str]
    payload_hash: str | None
    snippet: str | None
    id: int | None = None


class EventStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        parent = Path(self.db_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(SCHEMA)
                conn.commit()
            finally:
                conn.close()

    def insert(self, event: Event) -> int:
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO events (
                        timestamp, src_ip, src_port, proto, path, score,
                        reasons, payload_hash, snippet
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.timestamp,
                        event.src_ip,
                        event.src_port,
                        event.proto,
                        event.path,
                        event.score,
                        json.dumps(event.reasons),
                        event.payload_hash,
                        event.snippet,
                    ),
                )
                conn.commit()
                return int(cursor.lastrowid)
            finally:
                conn.close()

    def query(
        self,
        *,
        min_score: int = 0,
        proto: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        sql = "SELECT * FROM events WHERE score >= ?"
        params: list[object] = [min_score]
        if proto:
            sql += " AND proto = ?"
            params.append(proto.lower())
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(sql, params).fetchall()
            finally:
                conn.close()
        return [self._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            id=row["id"],
            timestamp=row["timestamp"],
            src_ip=row["src_ip"],
            src_port=row["src_port"],
            proto=row["proto"],
            path=row["path"],
            score=row["score"],
            reasons=json.loads(row["reasons"]),
            payload_hash=row["payload_hash"],
            snippet=row["snippet"],
        )
