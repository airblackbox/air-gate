"""
Gate Proxy - the FastAPI server that intercepts every agent action.

This is the central nervous system. Every agent action flows through here:

  Agent → Gate Proxy → Policy Check → Approve/Block → Execute → Sign Event

Endpoints:
  POST /actions          - Submit an agent action for processing
  POST /actions/{id}/approve  - Human approves a pending action
  POST /actions/{id}/reject   - Human rejects a pending action
  GET  /events           - Query the signed event store
  GET  /events/{id}      - Get a specific event
  GET  /verify           - Verify audit chain integrity
  GET  /stats            - Get summary statistics
  GET  /report           - Generate compliance PDF report
  POST /slack/interact   - Handle Slack button clicks
  GET  /health           - Health check
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Optional

import httpx

from dotenv import load_dotenv
load_dotenv()

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .events import EventStore, GateEvent
from .policy import PolicyEngine, PolicyRule
from .pii import PIIRedactor, RedactionMethod
from .slack_bot import SlackBot
from .tracing import setup_tracing

# ── Setup ────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("gate")

app = FastAPI(
    title="AIR Blackbox Gate",
    description="The AI Action Firewall - Every agent action recorded, attributable, and provable.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize tracing (no-op if OTEL not installed)
setup_tracing(app)

# ── Config ───────────────────────────────────────────────────────────

SIGNING_KEY = os.getenv("GATE_SIGNING_KEY", "change-me-in-production")
STORAGE_PATH = os.getenv("GATE_STORAGE_PATH", "gate_events.jsonl")
CONFIG_PATH = os.getenv("GATE_CONFIG_PATH", "gate_config.yaml")
PII_REDACTION = os.getenv("GATE_PII_REDACTION", "true").lower() in ("true", "1", "yes")
PII_METHOD = os.getenv("GATE_PII_METHOD", "hash_sha256")
CALLBACK_TIMEOUT = int(os.getenv("GATE_CALLBACK_TIMEOUT", "300"))

# Shared secret required to approve/reject actions over the HTTP API. If unset,
# the approval endpoints are UNAUTHENTICATED - anyone who can reach the server
# can approve or reject on any human's behalf, which defeats the Article 14
# human-oversight guarantee. We enforce the token when configured and warn
# loudly when it is not.
APPROVAL_TOKEN = os.getenv("GATE_APPROVAL_TOKEN", "")
# Slack app signing secret, used to verify that interactive requests to
# /slack/interact genuinely came from Slack (not a forged POST).
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")

if not APPROVAL_TOKEN:
    logger.warning(
        "GATE_APPROVAL_TOKEN is not set - /actions/*/approve and /reject are "
        "UNAUTHENTICATED. Set GATE_APPROVAL_TOKEN to require an approver token."
    )
if not SLACK_SIGNING_SECRET:
    logger.warning(
        "SLACK_SIGNING_SECRET is not set - /slack/interact will reject all "
        "requests (it cannot verify they came from Slack). Set "
        "SLACK_SIGNING_SECRET to enable Slack button approvals."
    )


def require_approver(authorization: Optional[str] = Header(default=None)):
    """
    FastAPI dependency that guards the approve/reject endpoints.

    Requires ``Authorization: Bearer <GATE_APPROVAL_TOKEN>`` when an approval
    token is configured. Comparison is constant-time. When no token is
    configured the guard is a no-op (with a startup warning already emitted).
    """
    if not APPROVAL_TOKEN:
        return
    expected = f"Bearer {APPROVAL_TOKEN}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing approver token")

# Initialize components
event_store = EventStore(signing_key=SIGNING_KEY, storage_path=STORAGE_PATH)
slack_bot = SlackBot()
pii_redactor = PIIRedactor(method=RedactionMethod(PII_METHOD)) if PII_REDACTION else None

# Load policy from config file or use defaults
def load_policy() -> PolicyEngine:
    try:
        with open(CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)
            return PolicyEngine.from_config(config.get("policy", {}))
    except FileNotFoundError:
        logger.info(f"No config file at {CONFIG_PATH} - using default policy (require_approval)")
        return PolicyEngine()

policy_engine = load_policy()

# Track pending approvals (event_id → callback)
pending_actions: dict[str, dict] = {}


# ── Request/Response Models ──────────────────────────────────────────

class ActionRequest(BaseModel):
    """What an agent sends when it wants to take an action."""
    agent_id: str
    action_type: str  # email, api_call, db_write, file_access, tool_call
    tool_name: str
    payload: dict = Field(default_factory=dict)
    input_context: str = ""  # what prompt led to this
    callback_url: str = ""  # optional: Gate will POST the decision here when resolved


class ActionResponse(BaseModel):
    """What Gate returns after processing an action."""
    event_id: str
    decision: str  # auto_allowed, pending_approval, blocked
    rule_name: str
    reason: str
    message: str
    pii_redacted: int = 0  # number of PII fields redacted from payload


class ApprovalRequest(BaseModel):
    """Human approving or rejecting a pending action."""
    authorized_by: str  # who approved (email, Slack user ID, etc.)
    comment: str = ""


# ── Endpoints ────────────────────────────────────────────────────────

@app.post("/actions", response_model=ActionResponse)
async def submit_action(action: ActionRequest, background_tasks: BackgroundTasks):
    """
    Submit an agent action for processing.

    Gate will:
    1. Create a signed event
    2. Check the policy
    3. Auto-allow, send to Slack for approval, or block
    """
    # Redact PII from payload before it enters the audit chain
    pii_count = 0
    safe_payload = action.payload
    if pii_redactor:
        safe_payload, detections = pii_redactor.redact(action.payload)
        pii_count = len(detections)
        if pii_count > 0:
            logger.info(f"PII REDACTED: {pii_count} field(s) in {action.agent_id} → {action.tool_name}")

    # Create the event
    event = GateEvent(
        agent_id=action.agent_id,
        action_type=action.action_type,
        tool_name=action.tool_name,
        payload=safe_payload,
        input_context=action.input_context,
    )

    # Check policy
    decision = policy_engine.evaluate(
        agent_id=action.agent_id,
        action_type=action.action_type,
        tool_name=action.tool_name,
        payload=action.payload,
    )

    if decision["decision"] == "auto_allow":
        event.result = "auto_allowed"
        event.authorized_by = "auto-policy"
        event_store.record(event)
        logger.info(f"AUTO-ALLOWED: {action.agent_id} → {action.tool_name} ({decision['rule_name']})")

        return ActionResponse(
            event_id=event.event_id,
            decision="auto_allowed",
            rule_name=decision["rule_name"],
            reason=decision["reason"],
            message="Action auto-approved by policy. Proceed.",
            pii_redacted=pii_count,
        )

    elif decision["decision"] == "block":
        event.result = "blocked"
        event.authorized_by = "auto-policy"
        event.result_detail = decision["reason"]
        event_store.record(event)
        logger.warning(f"BLOCKED: {action.agent_id} → {action.tool_name} ({decision['reason']})")

        return ActionResponse(
            event_id=event.event_id,
            decision="blocked",
            rule_name=decision["rule_name"],
            reason=decision["reason"],
            message="Action blocked by policy. Cannot proceed.",
            pii_redacted=pii_count,
        )

    else:  # require_approval
        event.result = "pending"
        event_store.record(event)
        pending_actions[event.event_id] = {
            "event": event,
            "action": action,
            "callback_url": action.callback_url,
        }
        logger.info(f"PENDING APPROVAL: {action.agent_id} → {action.tool_name}")

        # Send to Slack in the background
        background_tasks.add_task(
            slack_bot.send_approval_request,
            event_id=event.event_id,
            agent_id=action.agent_id,
            action_type=action.action_type,
            tool_name=action.tool_name,
            payload=safe_payload,
            input_context=action.input_context,
        )

        return ActionResponse(
            event_id=event.event_id,
            decision="pending_approval",
            rule_name=decision["rule_name"],
            reason=decision["reason"],
            message="Action requires human approval. Sent to Slack.",
            pii_redacted=pii_count,
        )


async def _fire_callback(event_id: str, result: str, authorized_by: str):
    """Send decision to the agent's callback URL if one was provided."""
    pending = pending_actions.get(event_id, {})
    callback_url = pending.get("callback_url", "")
    if not callback_url:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(callback_url, json={
                "event_id": event_id,
                "result": result,
                "authorized_by": authorized_by,
            })
        logger.info(f"CALLBACK SENT: {event_id} → {callback_url}")
    except Exception as e:
        logger.warning(f"CALLBACK FAILED: {event_id} → {callback_url}: {e}")


@app.post("/actions/{event_id}/approve", dependencies=[Depends(require_approver)])
async def approve_action(event_id: str, approval: ApprovalRequest, background_tasks: BackgroundTasks):
    """Human approves a pending action."""
    event = event_store.resolve(
        event_id=event_id,
        result="approved",
        authorized_by=approval.authorized_by,
        detail=approval.comment,
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Fire callback to waiting agent
    background_tasks.add_task(_fire_callback, event_id, "approved", approval.authorized_by)

    # Clean up pending
    pending_actions.pop(event_id, None)

    logger.info(f"APPROVED: {event.agent_id} → {event.tool_name} by {approval.authorized_by}")
    return {"status": "approved", "event_id": event_id, "authorized_by": approval.authorized_by}


@app.post("/actions/{event_id}/reject", dependencies=[Depends(require_approver)])
async def reject_action(event_id: str, approval: ApprovalRequest, background_tasks: BackgroundTasks):
    """Human rejects a pending action."""
    event = event_store.resolve(
        event_id=event_id,
        result="rejected",
        authorized_by=approval.authorized_by,
        detail=approval.comment,
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Fire callback to waiting agent
    background_tasks.add_task(_fire_callback, event_id, "rejected", approval.authorized_by)

    pending_actions.pop(event_id, None)

    logger.info(f"REJECTED: {event.agent_id} → {event.tool_name} by {approval.authorized_by}")
    return {"status": "rejected", "event_id": event_id, "authorized_by": approval.authorized_by}


@app.get("/events")
async def list_events(
    agent_id: Optional[str] = None,
    action_type: Optional[str] = None,
    result: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
):
    """Query the signed event store with optional filters."""
    events = event_store.get_events(
        agent_id=agent_id,
        action_type=action_type,
        result=result,
        since=since,
        until=until,
    )
    return {"events": [e.model_dump() for e in events[-limit:]], "total": len(events)}


@app.get("/events/{event_id}")
async def get_event(event_id: str):
    """Get a specific event by ID."""
    for event in event_store.events:
        if event.event_id == event_id:
            return event.model_dump()
    raise HTTPException(status_code=404, detail="Event not found")


@app.get("/actions/{event_id}/status")
async def action_status(event_id: str):
    """
    Effective status of an action, resolving any appended approve/reject
    decision. Agents poll this to wait for a human decision on a pending action.
    """
    result = event_store.current_result(event_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"event_id": event_id, "result": result, "resolved": result != "pending"}


@app.get("/verify")
async def verify_chain():
    """Verify the entire audit chain is intact (no tampering)."""
    return event_store.verify_chain()


@app.get("/stats")
async def get_stats():
    """Get summary statistics for the event store."""
    return event_store.get_stats()


def _verify_slack_signature(raw_body: bytes, timestamp: str, signature: str) -> bool:
    """
    Verify a Slack request signature per Slack's signing spec.

    basestring = "v0:{timestamp}:{raw_body}"; expected = "v0=" + HMAC_SHA256.
    Rejects requests older than 5 minutes to prevent replay. Returns True only
    when SLACK_SIGNING_SECRET is configured and the signature matches.
    """
    if not SLACK_SIGNING_SECRET:
        return False
    if not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > 60 * 5:
            return False
    except ValueError:
        return False
    basestring = b"v0:" + timestamp.encode() + b":" + raw_body
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), basestring, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post("/slack/interact")
async def slack_interact(request: Request):
    """
    Handle Slack interactive button clicks (Approve/Reject).

    Slack sends a POST with a payload containing the action_id and value. We
    verify the request signature over the raw body before trusting anything in
    it, so a forged POST cannot approve or reject actions.
    """
    raw_body = await request.body()

    if not SLACK_SIGNING_SECRET:
        # Fail closed: without a signing secret we cannot tell a real Slack
        # request from a forgery, so we refuse to act on it.
        logger.error("Rejected /slack/interact: SLACK_SIGNING_SECRET not configured")
        raise HTTPException(status_code=503, detail="Slack signature verification not configured")

    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    if not _verify_slack_signature(raw_body, timestamp, signature):
        logger.warning("Rejected /slack/interact: invalid Slack signature")
        raise HTTPException(status_code=401, detail="Invalid Slack signature")

    from urllib.parse import parse_qs
    parsed = parse_qs(raw_body.decode("utf-8"))
    payload = json.loads(parsed.get("payload", ["{}"])[0])

    actions = payload.get("actions", [])
    user = payload.get("user", {})
    user_name = user.get("real_name", user.get("name", "unknown"))

    for action in actions:
        action_id = action.get("action_id")
        event_id = action.get("value")

        if action_id == "gate_approve":
            resolved = event_store.resolve(event_id, "approved", user_name)
            if not resolved:
                logger.warning(f"SLACK APPROVE for unknown event: {event_id}")
                return {"response_type": "ephemeral", "text": "Unknown or already-resolved action."}
            await _fire_callback(event_id, "approved", user_name)
            pending_actions.pop(event_id, None)
            logger.info(f"SLACK APPROVED: {event_id} by {user_name}")
            return {"response_type": "in_channel", "text": f"✅ Approved by {user_name}"}

        elif action_id == "gate_reject":
            resolved = event_store.resolve(event_id, "rejected", user_name)
            if not resolved:
                logger.warning(f"SLACK REJECT for unknown event: {event_id}")
                return {"response_type": "ephemeral", "text": "Unknown or already-resolved action."}
            await _fire_callback(event_id, "rejected", user_name)
            pending_actions.pop(event_id, None)
            logger.info(f"SLACK REJECTED: {event_id} by {user_name}")
            return {"response_type": "in_channel", "text": f"❌ Rejected by {user_name}"}

    return {"text": "Action processed"}


# ── Report Router ─────────────────────────────────────────────────

from .report_endpoint import create_report_router
report_router = create_report_router(event_store)
app.include_router(report_router)


@app.get("/health")
async def health():
    """Health check."""
    chain = event_store.verify_chain()
    return {
        "status": "healthy",
        "version": "0.1.0",
        "events_count": len(event_store.events),
        "chain_valid": chain["valid"],
        "pending_approvals": len(pending_actions),
    }
