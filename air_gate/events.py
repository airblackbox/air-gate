"""
Tamper-evident signed event store using HMAC-SHA256 chains.

Every agent action produces a signed event. Events are cryptographically
chained so that any tampering (editing, deleting, reordering) is detectable.
This is not a log file - it's legal evidence.

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

    # Kind of entry: "action" (an agent action) or "decision" (a human/policy
    # resolution of an earlier action). Decision entries are appended, never
    # mutated in place, so the chain stays append-only.
    entry_type: str = "action"
    related_event_id: str = ""  # for decisions: the action event being resolved

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
    signature_algorithm: str = "HMAC-SHA256"  # "HMAC-SHA256" or "Ed25519"
    previous_hash: str = ""  # signature of previous event (empty for first)
    hmac_signature: str = ""  # signature of this event (name kept for compat)


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

    def __init__(
        self,
        signing_key: str = None,
        storage_path: str = "gate_events.jsonl",
        backend: str = None,
        signer=None,
    ):
        """
        Parameters
        ----------
        signing_key : str, optional
            HMAC-SHA256 secret. Used when no explicit ``signer`` is given.
        signer : Signer, optional
            A signer from ``air_gate.signing`` (e.g. an ``Ed25519Signer`` for
            asymmetric, publicly-verifiable signatures). Takes precedence over
            ``signing_key``. Pass a verify-only signer to check an existing
            chain without the power to forge it.
        """
        from .signing import HMACSigner
        self._signer = signer or HMACSigner(signing_key or "change-me-in-production")
        # Kept for backward compatibility (HMAC deployments referenced this).
        self.signing_key = (signing_key or "change-me-in-production").encode("utf-8")
        self.storage_path = storage_path
        self.events: list[GateEvent] = []
        # In-memory callback fallback (JSONL backend only; SQLite persists them).
        self._callbacks: dict[str, str] = {}

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

    # ── Signing ─────────────────────────────────────────────────────

    @property
    def algorithm(self) -> str:
        """Signature algorithm this store signs/verifies with."""
        return self._signer.algorithm

    @property
    def public_key_hex(self):
        """
        Public key (Ed25519) that a third party can use to verify this chain
        without being able to forge it. None for HMAC (no public key exists).
        """
        return getattr(self._signer, "public_key_hex", None)

    def _signed_content(self, event: GateEvent) -> bytes:
        """
        Canonical bytes that get signed. Note: ``signature_algorithm`` is
        intentionally NOT included so that HMAC signatures remain byte-for-byte
        compatible with chains created before signer support was added.
        """
        return json.dumps(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "entry_type": event.entry_type,
                "related_event_id": event.related_event_id,
                "agent_id": event.agent_id,
                "action_type": event.action_type,
                "tool_name": event.tool_name,
                "input_context": event.input_context,
                "payload": event.payload,
                "result": event.result,
                "result_detail": event.result_detail,
                "authorized_by": event.authorized_by,
                "previous_hash": event.previous_hash,
            },
            sort_keys=True,
        ).encode("utf-8")

    def _compute_hmac(self, event: GateEvent) -> str:
        """Sign an event with the configured signer (name kept for compat)."""
        return self._signer.sign(self._signed_content(event))

    # ── Core Operations ─────────────────────────────────────────────

    def record(self, event: GateEvent) -> GateEvent:
        """Record an event, sign it, and chain it to the previous event."""
        if self.events:
            event.previous_hash = self.events[-1].hmac_signature
        else:
            event.previous_hash = "GENESIS"

        event.signature_algorithm = self._signer.algorithm
        event.hmac_signature = self._compute_hmac(event)

        self.events.append(event)
        self._persist(event)

        return event

    def resolve(
        self, event_id: str, result: str, authorized_by: str, detail: str = ""
    ) -> Optional[GateEvent]:
        """
        Resolve a pending action by *appending* a new signed decision event.

        The original action event is never mutated - this keeps the chain
        strictly append-only, so an approval or rejection can never break the
        HMAC linkage of events recorded after it. The decision event records
        who resolved it, the outcome, and any reason (all of which are signed).

        Returns the newly appended decision event, or None if no action with
        ``event_id`` exists.
        """
        action = next((e for e in self.events if e.event_id == event_id), None)
        if action is None:
            return None

        decision = GateEvent(
            entry_type="decision",
            related_event_id=event_id,
            agent_id=action.agent_id,
            action_type=action.action_type,
            tool_name=action.tool_name,
            input_context=action.input_context,
            result=result,
            result_detail=detail,
            authorized_by=authorized_by,
        )
        return self.record(decision)

    # Back-compat alias. Older callers expect ``update_result``; it now appends
    # a decision event instead of mutating in place (returns that new event).
    update_result = resolve

    def current_result(self, event_id: str) -> Optional[str]:
        """
        Effective result of an action: the outcome of the latest decision
        event that references it, or the action's own result if unresolved.
        """
        action = next((e for e in self.events if e.event_id == event_id), None)
        if action is None:
            return None
        latest = action.result
        for e in self.events:
            if e.entry_type == "decision" and e.related_event_id == event_id:
                latest = e.result
        return latest

    def _resolved_results(self) -> dict:
        """Map action event_id -> effective result (latest decision wins)."""
        resolved = {
            e.event_id: e.result for e in self.events if e.entry_type != "decision"
        }
        for e in self.events:
            if e.entry_type == "decision" and e.related_event_id in resolved:
                resolved[e.related_event_id] = e.result
        return resolved

    def pending_actions(self) -> list[GateEvent]:
        """
        Action events still awaiting a human decision. Derived from the chain,
        so it survives restarts and is consistent across workers sharing the DB
        (no in-memory pending list to lose).
        """
        resolved = self._resolved_results()
        return [
            e for e in self.events
            if e.entry_type != "decision" and resolved.get(e.event_id) == "pending"
        ]

    def count_recent_actions(
        self, agent_id: str, action_type: str, tool_name: str, since_iso: str
    ) -> int:
        """
        Count action events matching (agent, action_type, tool) at or after
        ``since_iso``. Used for durable, cross-worker rate limiting (decisions
        are excluded so approvals don't inflate the count).
        """
        return sum(
            1 for e in self.events
            if e.entry_type != "decision"
            and e.agent_id == agent_id
            and e.action_type == action_type
            and e.tool_name == tool_name
            and e.timestamp >= since_iso
        )

    def verify_chain(self) -> dict:
        """Verify the entire chain is intact. Returns verification report."""
        if not self.events:
            return {"valid": True, "events_checked": 0, "errors": []}

        errors = []

        for i, event in enumerate(self.events):
            # Reject algorithm downgrade/mismatch: every event must be signed
            # with the algorithm this store verifies under. Prevents swapping a
            # strong signature for one the verifier cannot actually check.
            if event.signature_algorithm != self._signer.algorithm:
                errors.append(
                    f"Event {event.event_id}: algorithm mismatch "
                    f"({event.signature_algorithm} != {self._signer.algorithm})"
                )
            elif not self._signer.verify(self._signed_content(event), event.hmac_signature):
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
        """
        Get summary statistics for reporting.

        Counts one row per agent *action*; the human/policy decisions that
        resolve those actions are folded into each action's effective result
        rather than counted as separate events.
        """
        actions = [e for e in self.events if e.entry_type != "decision"]
        total = len(actions)
        if total == 0:
            return {"total": 0}

        resolved = self._resolved_results()
        results = {}
        action_types = {}
        agents = set()

        for e in actions:
            effective = resolved.get(e.event_id, e.result)
            results[effective] = results.get(effective, 0) + 1
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
                entry_type TEXT DEFAULT 'action',
                related_event_id TEXT DEFAULT '',
                agent_id TEXT NOT NULL,
                authorized_by TEXT DEFAULT 'pending',
                action_type TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                input_context TEXT DEFAULT '',
                payload TEXT DEFAULT '{}',
                result TEXT DEFAULT 'pending',
                result_detail TEXT DEFAULT '',
                signature_algorithm TEXT DEFAULT 'HMAC-SHA256',
                previous_hash TEXT DEFAULT '',
                hmac_signature TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_result ON events(result)")
        # Durable callback URLs for pending actions (survive restart / shared
        # across workers), so a decision can still reach the waiting agent.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_callbacks (
                event_id TEXT PRIMARY KEY,
                callback_url TEXT NOT NULL
            )
        """)
        # Migration: add signature_algorithm to DBs created before signer support.
        cols = [r[1] for r in conn.execute("PRAGMA table_info(events)")]
        if "signature_algorithm" not in cols:
            conn.execute(
                "ALTER TABLE events ADD COLUMN signature_algorithm TEXT DEFAULT 'HMAC-SHA256'"
            )
        conn.commit()
        conn.close()

    # ── Pending callback URLs ───────────────────────────────────────

    def set_callback(self, event_id: str, callback_url: str):
        """Persist the agent's callback URL for a pending action."""
        if not callback_url:
            return
        if self._backend == "sqlite":
            conn = sqlite3.connect(self.storage_path)
            conn.execute(
                "INSERT OR REPLACE INTO pending_callbacks (event_id, callback_url) VALUES (?, ?)",
                (event_id, callback_url),
            )
            conn.commit()
            conn.close()
        else:
            self._callbacks[event_id] = callback_url

    def get_callback(self, event_id: str) -> str:
        """Fetch the stored callback URL for an action (empty if none)."""
        if self._backend == "sqlite":
            conn = sqlite3.connect(self.storage_path)
            row = conn.execute(
                "SELECT callback_url FROM pending_callbacks WHERE event_id = ?", (event_id,)
            ).fetchone()
            conn.close()
            return row[0] if row else ""
        return self._callbacks.get(event_id, "")

    def clear_callback(self, event_id: str):
        """Remove a callback once its action is resolved."""
        if self._backend == "sqlite":
            conn = sqlite3.connect(self.storage_path)
            conn.execute("DELETE FROM pending_callbacks WHERE event_id = ?", (event_id,))
            conn.commit()
            conn.close()
        else:
            self._callbacks.pop(event_id, None)

    def _sqlite_persist(self, event: GateEvent):
        """Insert a single event into SQLite."""
        conn = sqlite3.connect(self.storage_path)
        conn.execute(
            """INSERT OR REPLACE INTO events
               (event_id, timestamp, entry_type, related_event_id, agent_id,
                authorized_by, action_type, tool_name, input_context, payload,
                result, result_detail, signature_algorithm, previous_hash, hmac_signature)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id, event.timestamp, event.entry_type,
                event.related_event_id, event.agent_id,
                event.authorized_by, event.action_type, event.tool_name,
                event.input_context, json.dumps(event.payload),
                event.result, event.result_detail,
                event.signature_algorithm, event.previous_hash, event.hmac_signature,
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
                   (event_id, timestamp, entry_type, related_event_id, agent_id,
                    authorized_by, action_type, tool_name, input_context, payload,
                    result, result_detail, signature_algorithm, previous_hash, hmac_signature)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id, event.timestamp, event.entry_type,
                    event.related_event_id, event.agent_id,
                    event.authorized_by, event.action_type, event.tool_name,
                    event.input_context, json.dumps(event.payload),
                    event.result, event.result_detail,
                    event.signature_algorithm, event.previous_hash, event.hmac_signature,
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
