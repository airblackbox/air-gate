#!/usr/bin/env python3
"""
AIR Blackbox — End-to-End Demo

Shows the complete flow:
  1. Connect to Gate (assumes docker compose up is running)
  2. Simulate a multi-agent scenario with different risk levels
  3. View audit trail and stats
  4. Verify cryptographic chain integrity
  5. Approve a pending action
  6. Show what the Dashboard displays

Prerequisites:
    cd air-gate && docker compose up -d
    pip install air-langchain-trust air-adk-trust

Run:
    python examples/e2e_demo.py
"""

import json
import sys
import time
import urllib.request
import urllib.error

GATE_URL = "http://localhost:8000"
DIVIDER = "=" * 60


def gate_request(method, path, data=None):
    """Make a request to Gate API."""
    url = f"{GATE_URL}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(
        url, data=body, method=method,
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError:
        return None


def check_gate():
    """Verify Gate is running."""
    health = gate_request("GET", "/health")
    if not health:
        print("ERROR: Gate is not running!")
        print()
        print("Start it with:")
        print("  cd air-gate && docker compose up -d")
        print()
        print("Or without Docker:")
        print("  pip install -r requirements.txt")
        print("  uvicorn gate.proxy:app --port 8000")
        sys.exit(1)
    return health


def main():
    print()
    print(DIVIDER)
    print("  AIR Blackbox — End-to-End Demo")
    print("  Gate + Trust Layers + Audit Trail")
    print(DIVIDER)

    # ── Step 1: Check Gate ───────────────────────────────────────
    print("\n[Step 1] Connecting to Gate...")
    health = check_gate()
    print(f"  Gate status: {health.get('status', 'unknown')}")
    print(f"  Gate URL:    {GATE_URL}")
    print(f"  Dashboard:   http://localhost:3000")
    print(f"  Jaeger:      http://localhost:16686")

    # ── Step 2: Simulate Agent 1 — Research Agent ────────────────
    print(f"\n{DIVIDER}")
    print("[Step 2] Agent 1: Research Agent (low-risk tasks)")
    print(DIVIDER)

    # Search tool — should be auto-allowed
    print("\n  Submitting: web_search (search type)...")
    result = gate_request("POST", "/actions", {
        "agent_id": "research-agent",
        "action_type": "search",
        "tool_name": "web_search",
        "payload": {"query": "EU AI Act compliance requirements 2026"},
        "input_context": "User asked for regulatory research",
    })
    if result:
        print(f"  Decision: {result.get('decision')}")
        print(f"  Rule:     {result.get('rule_matched', 'default')}")
    time.sleep(0.3)

    # Database read — should be auto-allowed
    print("\n  Submitting: read_database (db_read type)...")
    result = gate_request("POST", "/actions", {
        "agent_id": "research-agent",
        "action_type": "db_read",
        "tool_name": "read_database",
        "payload": {"table": "compliance_checks", "query": "SELECT * FROM checks"},
        "input_context": "Agent reading compliance check history",
    })
    if result:
        print(f"  Decision: {result.get('decision')}")
        print(f"  Rule:     {result.get('rule_matched', 'default')}")
    time.sleep(0.3)

    # ── Step 3: Simulate Agent 2 — Outreach Agent ────────────────
    print(f"\n{DIVIDER}")
    print("[Step 3] Agent 2: Outreach Agent (high-risk tasks)")
    print(DIVIDER)

    # Email — should require approval
    print("\n  Submitting: send_email (email type)...")
    email_result = gate_request("POST", "/actions", {
        "agent_id": "outreach-agent",
        "action_type": "email",
        "tool_name": "send_email",
        "payload": {
            "to": "cto@techcorp.com",
            "subject": "EU AI Act Compliance — Free Audit",
            "body": "Hi, I noticed your team uses LangChain agents...",
        },
        "input_context": "Agent sending cold outreach email to prospect",
    })
    pending_event_id = None
    if email_result:
        print(f"  Decision: {email_result.get('decision')}")
        print(f"  Rule:     {email_result.get('rule_matched', 'default')}")
        pending_event_id = email_result.get("event_id")
        if email_result.get("decision") == "require_approval":
            print(f"  Event ID: {pending_event_id} (waiting for human approval)")
    time.sleep(0.3)

    # Database write — should require approval
    print("\n  Submitting: update_crm (db_write type)...")
    result = gate_request("POST", "/actions", {
        "agent_id": "outreach-agent",
        "action_type": "db_write",
        "tool_name": "update_crm",
        "payload": {"contact": "cto@techcorp.com", "status": "contacted"},
        "input_context": "Agent updating CRM after email sent",
    })
    if result:
        print(f"  Decision: {result.get('decision')}")
        print(f"  Rule:     {result.get('rule_matched', 'default')}")
    time.sleep(0.3)

    # ── Step 4: Simulate Agent 3 — Rogue Agent (blocked) ─────────
    print(f"\n{DIVIDER}")
    print("[Step 4] Agent 3: Rogue Agent (dangerous tasks)")
    print(DIVIDER)

    # Delete — should be blocked
    print("\n  Submitting: drop_table (db_delete type)...")
    result = gate_request("POST", "/actions", {
        "agent_id": "rogue-agent",
        "action_type": "db_delete",
        "tool_name": "drop_table",
        "payload": {"table": "users"},
        "input_context": "Agent attempting to delete user table",
    })
    if result:
        print(f"  Decision: {result.get('decision')}")
        print(f"  Rule:     {result.get('rule_matched', 'default')}")
    time.sleep(0.3)

    # Admin action — should be blocked
    print("\n  Submitting: change_permissions (admin type)...")
    result = gate_request("POST", "/actions", {
        "agent_id": "rogue-agent",
        "action_type": "admin",
        "tool_name": "change_permissions",
        "payload": {"user": "admin", "role": "superuser"},
        "input_context": "Agent attempting to escalate privileges",
    })
    if result:
        print(f"  Decision: {result.get('decision')}")
        print(f"  Rule:     {result.get('rule_matched', 'default')}")
    time.sleep(0.3)

    # ── Step 5: Human approves the pending email ─────────────────
    print(f"\n{DIVIDER}")
    print("[Step 5] Human oversight — approving pending email")
    print(DIVIDER)

    if pending_event_id:
        print(f"\n  Approving event {pending_event_id}...")
        approval = gate_request("POST", f"/actions/{pending_event_id}/approve", {
            "authorized_by": "jason@airblackbox.ai",
            "comment": "Email content looks good, send it",
        })
        if approval:
            print(f"  Status: {approval.get('status', 'approved')}")
            print(f"  Authorized by: jason@airblackbox.ai")
        else:
            print("  (Approval endpoint not available — Gate may not support this yet)")
    else:
        print("  No pending events to approve")
    time.sleep(0.3)

    # ── Step 6: View audit trail ─────────────────────────────────
    print(f"\n{DIVIDER}")
    print("[Step 6] Audit trail")
    print(DIVIDER)

    events = gate_request("GET", "/audit/events")
    if events and isinstance(events, list):
        print(f"\n  Total events: {len(events)}")
        print(f"\n  {'Agent':<20} {'Tool':<25} {'Decision':<18} {'Type'}")
        print(f"  {'-'*17:<20} {'-'*22:<25} {'-'*15:<18} {'-'*10}")
        for evt in events[-6:]:  # Show last 6
            agent = evt.get("agent_id", "?")[:18]
            tool = evt.get("tool_name", "?")[:23]
            decision = evt.get("decision", "?")[:15]
            atype = evt.get("action_type", "?")
            print(f"  {agent:<20} {tool:<25} {decision:<18} {atype}")
    elif events and isinstance(events, dict) and "events" in events:
        event_list = events["events"]
        print(f"\n  Total events: {len(event_list)}")
        for evt in event_list[-6:]:
            agent = evt.get("agent_id", "?")[:18]
            tool = evt.get("tool_name", "?")[:23]
            decision = evt.get("decision", "?")[:15]
            print(f"  {agent:<20} {tool:<25} {decision}")
    else:
        print("  (Could not retrieve events — endpoint format may differ)")

    # ── Step 7: Stats ────────────────────────────────────────────
    print(f"\n{DIVIDER}")
    print("[Step 7] Audit stats")
    print(DIVIDER)

    stats = gate_request("GET", "/audit/stats")
    if stats:
        print()
        for k, v in stats.items():
            print(f"  {k}: {v}")
    else:
        print("  (Stats endpoint not available)")

    # ── Step 8: Chain verification ───────────────────────────────
    print(f"\n{DIVIDER}")
    print("[Step 8] Chain integrity verification")
    print(DIVIDER)

    verify = gate_request("GET", "/audit/verify")
    if verify:
        valid = verify.get("valid", verify.get("chain_valid", "unknown"))
        entries = verify.get("total_entries", verify.get("entries", "?"))
        print(f"\n  Chain valid:     {valid}")
        print(f"  Total entries:   {entries}")
        if valid is True or valid == "true":
            print("  HMAC-SHA256:     All signatures verified")
            print("  Tamper status:   No tampering detected")
        else:
            errors = verify.get("errors", [])
            print(f"  Errors:          {errors}")
    else:
        print("  (Verify endpoint not available)")

    # ── Summary ──────────────────────────────────────────────────
    print(f"\n{DIVIDER}")
    print("  Demo complete!")
    print(DIVIDER)
    print()
    print("  What just happened:")
    print("  - 3 agents submitted 6 tool calls to Gate")
    print("  - Gate auto-allowed 2 low-risk actions (search, db_read)")
    print("  - Gate held 2 medium-risk actions for approval (email, db_write)")
    print("  - Gate blocked 2 dangerous actions (db_delete, admin)")
    print("  - A human approved the pending email")
    print("  - Every decision was logged in a tamper-evident audit chain")
    print()
    print("  View the Dashboard:  http://localhost:3000")
    print("  View traces:         http://localhost:16686")
    print("  API docs:            http://localhost:8000/docs")
    print()


if __name__ == "__main__":
    main()
