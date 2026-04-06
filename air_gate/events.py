"""
Tamper-evident signed event store using HMAC-SHA256 chains.

Every agent action produces a signed event. Events are cryptographically
chained so that any tampering (editing, deleting, reordering) is detectable.
This is not a log file — it's legal evidence.

Supports two storage backends:
  - JSONL (default for backward compatibility): gate_events.jsonl
  - SQLite (recommended): gate_events.db
"""

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class GateEvent(BaseModel):
    """A single signed event in the audit chain."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Who
    agent_id: str
    authorized_by: str = "pending"  # human who approved, or "auto-policy"

    # What
    action_type: str  # email, api_call, db_write, file_access, tool_call
    tool_name: str  # specific tool being called
    input_context: str = ""  # what prompt/memory led to this action
    payload: dict = Field(default_factory=dict)  # the actual data being sent

    # Result
    result: str = "pending"  # pending, approved, rejected, auto_allowed, blocked
    result_detail: str = ""

    # Chain integrity
    previous_hash: str = ""  # HMAC of previous event (empty for first)
    hmac_signature: str = ""  # HMAC of this event


class EventStore:
    """
    In-memory event store with HMAC-SHA256 chaining.

    Every event is signed with a secret key and chained to the previous event.
    If anyone tampers with any event, the chain breaks and verification fails.

    Storage backends:
      - SQLite (.db): Recommended. Zero-config, embedded, supports concurrent reads.
      - JSONL (.jsonl): Simple append-only file. Good for debugging.

    Backend is auto-detected from file extension, or set explicitly via backend param.
    """

    def __init__(self, signing_key: str, storage_path: str = "gate_events.jsonl", backend: str = None):
        self.signing_key = signing_key.encode("utf-8")
        self.storage_path = storage_path
        self.events: list[GateEvent] = []

        # Auto-detect backend from file extension
        if backend:
            self._backend = backend
        elif storage_path.endswith(".db"):
            self._backend = "sqlite"
        else:
            self._backend = "jsonl"

        # Initialize storage
        if self._backend == "sqlite":
            self._init_sqlite()

        self._load_existing()

    # ── HMAC Signing ────────────────────────────────────────────────

    def _compute_hmac(self, event: GateEvent) -> str:
        """Compute HMAC-SHA256 signature for an event."""
        content = json.dumps(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "agent_id": event.agent_id,
                "action_type": event.action_type,
                "tool_name": event.tool_name,
                "payload": event.payload,
                "result": event.result,
                "authorized_by": event.authorized_by,
                "previous_hash": event.previous_hash,
            },
            sort_keys=True,
        )
        return hmac.new(self.signing_key, content.encode("utf-8"), hashlib.sha256).hexdigest()

    # ── Core Operations ─────────────────────────────────────────────

    def record(self, event: GateEvent) -> GateEvent:
        """Record an event, sign it, and chain it to the previous event."""
        if self.events:
            event.previous_hash = self.events[-1].hmac_signature
        else:
            event.previous_hash = "GENESIS"

        event.hmac_signature = self._compute_hmac(event)

        self.events.append(event)
        self._persist(event)

        return event

    def update_result(self, event_id: str, result: str, authorized_by: str, detail: str = "") -> Optional[GateEvent]:
        """Update an event's result (e.g., when human approves/rejects)."""
        for event in self.events:
            if event.event_id == event_id:
                event.result = result
                event.authorized_by = authorized_by
                event.result_detail = detail
                event.hmac_signature = self._compute_hmac(event)
                self._persist_all()
                return event
        return None

    def verify_chain(self) -> dict:
        """Verify the entire chain is intact. Returns verification report."""
        if not self.events:
            return {"valid": True, "events_checked": 0, "errors": []}

        errors = []

        for i, event in enumerate(self.events):
            expected_hmac = self._compute_hmac(event)
            if event.hmac_signature != expected_hmac:
                errors.append(
                    f"Event {event.event_id}: signature mismatch (tampering detected)"
                )

            if i == 0:
                if event.previous_hash != "GENESIS":
                    errors.append(
                        f"Event {event.event_id}: first event should link to GENESIS"
                    )
            else:
                if event.previous_hash != self.events[i - 1].hmac_signature:
                    errors.append(
                        f"Event {event.event_id}: chain broken (previous hash mismatch)"
                    )

        return {
            "valid": len(errors) == 0,
            "events_checked": len(self.events),
            "errors": errors,
        }

    def get_events(
        self,
        agent_id: Optional[str] = None,
        action_type: Optional[str] = None,
        result: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> list[GateEvent]:
        """Query events with optional filters."""
        filtered = self.events

        if agent_id:
            filtered = [e for e in filtered if e.agent_id == agent_id]
        if action_type:
            filtered = [e for e in filtered if e.action_type == action_type]
        if result:
            filtered = [e for e in filtered if e.result == result]
        if since:
            filtered = [e for e in filtered if e.timestamp >= since]
        if until:
            filtered = [e for e in filtered if e.timestamp <= until]

        return filtered

    def get_stats(self) -> dict:
        """Get summary statistics for reporting."""
        total = len(self.events)
        if total == 0:
            return {"total": 0}

        results = {}
        action_types = {}
        agents = set()

        for e in self.events:
            results[e.result] = results.get(e.result, 0) + 1
            action_types[e.action_type] = action_types.get(e.action_type, 0) + 1
            agents.add(e.agent_id)

        return {
            "total": total,
            "by_result": results,
            "by_action_type": action_types,
            "unique_agents": len(agents),
            "chain_valid": self.verify_chain()["valid"],
        }

    # ── SQLite Backend ──────────────────────────────────────────────

    def _init_sqlite(self):
        """Initialize SQLite database with the events table."""
        conn = sqlite3.connect(self.storage_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                authorized_by TEXT DEFAULT 'pending',
                action_type TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                input_context TEXT DEFAULT '',
                payload TEXT DEFAULT '{}',
                result TEXT DEFAULT 'pending',
                result_detail TEXT DEFAULT '',
                previous_hash TEXT DEFAULT '',
                hmac_signature TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_result ON events(result)")
        conn.commit()
        conn.close()

    def _sqlite_persist(self, event: GateEvent):
        """Insert a single event into SQLite."""
        conn = sqlite3.connect(self.storage_path)
        conn.execute(
            """INSERT OR REPLACE INTO events
               (event_id, timestamp, agent_id, authorized_by, action_type,
                tool_name, input_context, payload, result, result_detail,
                previous_hash, hmac_signature)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id, event.timestamp, event.agent_id,
                event.authorized_by, event.action_type, event.tool_name,
                event.input_context, json.dumps(event.payload),
                event.result, event.result_detail,
                event.previous_hash, event.hmac_signature,
            ),
        )
        conn.commit()
        conn.close()

    def _sqlite_persist_all(self):
        """Rewrite all events to SQLite (used after updates that re-sign)."""
        conn = sqlite3.connect(self.storage_path)
        conn.execute("DELETE FROM events")
        for event in self.events:
            conn.execute(
                """INSERT INTO events
                   (event_id, timestamp, agent_id, authorized_by, action_type,
                    tool_name, input_context, payload, result, result_detail,
                    previous_hash, hmac_signature)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id, event.timestamp, event.agent_id,
                    event.authorized_by, event.action_type, event.tool_name,
                    event.input_context, json.dumps(event.payload),
                    event.result, event.result_detail,
                    event.previous_hash, event.hmac_signature,
                ),
            )
        conn.commit()
        conn.close()

    def _sqlite_load(self):
        """Load all events from SQLite, ordered by sequence."""
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.execute("SELECT * FROM events ORDER BY seq")
        columns = [desc[0] for desc in cursor.description]
        for row in cursor:
            row_dict = dict(zip(columns, row))
            row_dict["payload"] = json.loads(row_dict.get("payload", "{}"))
            row_dict.pop("seq", None)
            self.events.append(GateEvent(**row_dict))
        conn.close()

    # ── JSONL Backend ───────────────────────────────────────────────

    def _jsonl_persist(self, event: GateEvent):
        """Append a single event to the JSONL file."""
        with open(self.storage_path, "a") as f:
            f.write(event.model_dump_json() + "\n")

    def _jsonl_persist_all(self):
        """Rewrite the entire JSONL file (used after updates)."""
        with open(self.storage_path, "w") as f:
            for event in self.events:
                f.write(event.model_dump_json() + "\n")

    def _jsonl_load(self):
        """Load events from JSONL file on startup."""
        try:
            with open(self.storage_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.events.append(GateEvent.model_validate_json(line))
        except FileNotFoundError:
            pass

    # ── Backend Dispatch ────────────────────────────────────────────

    def _persist(self, event: GateEvent):
        if self._backend == "sqlite":
            self._sqlite_persist(event)
        else:
            self._jsonl_persist(event)

    def _persist_all(self):
        if self._backend == "sqlite":
            self._sqlite_persist_all()
        else:
            self._jsonl_persist_all()

    def _load_existing(self):
        if self._backend == "sqlite":
            self._sqlite_load()
        else:
            self._jsonl_load()
