"""
Gate Proxy — the FastAPI server that intercepts every agent action.

This is the central nervous system. Every agent action flows through here:

  Agent → Gate Proxy → Policy Check → Approve/Block → Execute → Sign Event

Endpoints:
  POST /actions          — Submit an agent action for processing
  POST /actions/{id}/approve  — Human approves a pending action
  POST /actions/{id}/reject   — Human rejects a pending action
  GET  /events           — Query the signed event store
  GET  /events/{id}      — Get a specific event
  GET  /verify           — Verify audit chain integrity
  GET  /stats            — Get summary statistics
  GET  /report           — Generate compliance PDF report
  POST /slack/interact   — Handle Slack button clicks
  GET  /health           — Health check
"""

import asyncio
import json
import logging
import os
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

import yaml
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .events import EventStore, GateEvent
from .policy import PolicyEngine, PolicyRule
from .slack_bot import SlackBot
from .tracing import setup_tracing

# ── Setup ────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("gate")

app = FastAPI(
    title="AIR Blackbox Gate",
    description="The AI Action Firewall — Every agent action recorded, attributable, and provable.",
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

# Initialize components
event_store = EventStore(signing_key=SIGNING_KEY, storage_path=STORAGE_PATH)
slack_bot = SlackBot()

# Load policy from config file or use defaults
def load_policy() -> PolicyEngine:
    try:
        with open(CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)
            return PolicyEngine.from_config(config.get("policy", {}))
    except FileNotFoundError:
        logger.info(f"No config file at {CONFIG_PATH} — using default policy (require_approval)")
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


class ActionResponse(BaseModel):
    """What Gate returns after processing an action."""
    event_id: str
    decision: str  # auto_allowed, pending_approval, blocked
    rule_name: str
    reason: str
    message: str


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
    # Create the event
    event = GateEvent(
        agent_id=action.agent_id,
        action_type=action.action_type,
        tool_name=action.tool_name,
        payload=action.payload,
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
        )

    else:  # require_approval
        event.result = "pending"
        event_store.record(event)
        pending_actions[event.event_id] = {
            "event": event,
            "action": action,
        }
        logger.info(f"PENDING APPROVAL: {action.agent_id} → {action.tool_name}")

        # Send to Slack in the background
        background_tasks.add_task(
            slack_bot.send_approval_request,
            event_id=event.event_id,
            agent_id=action.agent_id,
            action_type=action.action_type,
            tool_name=action.tool_name,
            payload=action.payload,
            input_context=action.input_context,
        )

        return ActionResponse(
            event_id=event.event_id,
            decision="pending_approval",
            rule_name=decision["rule_name"],
            reason=decision["reason"],
            message="Action requires human approval. Sent to Slack.",
        )


@app.post("/actions/{event_id}/approve")
async def approve_action(event_id: str, approval: ApprovalRequest):
    """Human approves a pending action."""
    event = event_store.update_result(
        event_id=event_id,
        result="approved",
        authorized_by=approval.authorized_by,
        detail=approval.comment,
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Clean up pending
    pending_actions.pop(event_id, None)

    logger.info(f"APPROVED: {event.agent_id} → {event.tool_name} by {approval.authorized_by}")
    return {"status": "approved", "event_id": event_id, "authorized_by": approval.authorized_by}


@app.post("/actions/{event_id}/reject")
async def reject_action(event_id: str, approval: ApprovalRequest):
    """Human rejects a pending action."""
    event = event_store.update_result(
        event_id=event_id,
        result="rejected",
        authorized_by=approval.authorized_by,
        detail=approval.comment,
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

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


@app.get("/verify")
async def verify_chain():
    """Verify the entire audit chain is intact (no tampering)."""
    return event_store.verify_chain()


@app.get("/stats")
async def get_stats():
    """Get summary statistics for the event store."""
    return event_store.get_stats()


@app.post("/slack/interact")
async def slack_interact(request: Request):
    """
    Handle Slack interactive button clicks (Approve/Reject).

    Slack sends a POST with a payload containing the action_id and value.
    """
    form_data = await request.form()
    payload = json.loads(form_data.get("payload", "{}"))

    actions = payload.get("actions", [])
    user = payload.get("user", {})
    user_name = user.get("real_name", user.get("name", "unknown"))

    for action in actions:
        action_id = action.get("action_id")
        event_id = action.get("value")

        if action_id == "gate_approve":
            event_store.update_result(
                event_id=event_id,
                result="approved",
                authorized_by=user_name,
            )
            pending_actions.pop(event_id, None)
            logger.info(f"SLACK APPROVED: {event_id} by {user_name}")
            return {"response_type": "in_channel", "text": f"✅ Approved by {user_name}"}

        elif action_id == "gate_reject":
            event_store.update_result(
                event_id=event_id,
                result="rejected",
                authorized_by=user_name,
            )
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
