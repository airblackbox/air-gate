#!/usr/bin/env python3
"""
AIR Blackbox Gate — Demo Script

Simulates a recruiting AI agent sending outreach emails through Gate.
Shows the full flow: intercept → policy check → approve/reject → signed event.

Run the server first:
  uvicorn gate.proxy:app --reload

Then run this demo:
  python3 demo.py
"""

import httpx
import json
import time
import sys

GATE_URL = "http://localhost:8000"

def banner(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")

def step(num, text):
    print(f"\n  [{num}] {text}")
    print(f"  {'-'*50}")

def main():
    banner("AIR Blackbox Gate — Demo")
    print("  Simulating a recruiting AI agent sending outreach emails.")
    print("  The agent's actions flow through Gate for approval.\n")

    client = httpx.Client(base_url=GATE_URL)

    # Check health
    try:
        health = client.get("/health").json()
        print(f"  Gate is running. Events: {health['events_count']}, Chain valid: {health['chain_valid']}")
    except httpx.ConnectError:
        print("  ERROR: Gate server is not running!")
        print("  Start it with: uvicorn gate.proxy:app --reload")
        sys.exit(1)

    # ── Step 1: Auto-allowed action (search) ──────────────────────
    step(1, "Agent searches for candidates (auto-allowed by policy)")

    response = client.post("/actions", json={
        "agent_id": "recruiting-agent-001",
        "action_type": "search",
        "tool_name": "linkedin_search",
        "payload": {
            "query": "senior data engineer",
            "location": "San Francisco Bay Area",
            "experience_years": "5+",
        },
        "input_context": "User asked: find senior data engineers in SF Bay Area",
    })
    result = response.json()
    print(f"  Decision: {result['decision']}")
    print(f"  Rule: {result['rule_name']}")
    print(f"  Message: {result['message']}")

    time.sleep(0.5)

    # ── Step 2: Action requiring approval (email) ─────────────────
    step(2, "Agent wants to send outreach email (requires approval)")

    response = client.post("/actions", json={
        "agent_id": "recruiting-agent-001",
        "action_type": "email",
        "tool_name": "send_email",
        "payload": {
            "to": "jane.doe@example.com",
            "subject": "Exciting Senior Data Engineer opportunity",
            "body": "Hi Jane,\n\nI came across your profile and was impressed by your work at Stripe on their real-time data pipeline...",
            "candidate_name": "Jane Doe",
            "role": "Senior Data Engineer",
            "company": "Acme Corp (confidential)",
        },
        "input_context": "Agent matched Jane Doe as 92% fit for the Acme Corp search based on Stripe experience + Kafka expertise",
    })
    result = response.json()
    event_id = result["event_id"]
    print(f"  Decision: {result['decision']}")
    print(f"  Event ID: {event_id}")
    print(f"  Message: {result['message']}")

    time.sleep(0.5)

    # ── Step 3: Human approves the email ──────────────────────────
    step(3, "Human approves the email via API (normally via Slack)")

    response = client.post(f"/actions/{event_id}/approve", json={
        "authorized_by": "jason@airblackbox.ai",
        "comment": "Email looks good. Send it.",
    })
    print(f"  Status: {response.json()['status']}")
    print(f"  Approved by: {response.json()['authorized_by']}")

    time.sleep(0.5)

    # ── Step 4: Blocked action (delete) ───────────────────────────
    step(4, "Agent tries to delete candidate records (blocked by policy)")

    response = client.post("/actions", json={
        "agent_id": "recruiting-agent-001",
        "action_type": "db_delete",
        "tool_name": "delete_records",
        "payload": {
            "table": "candidates",
            "filter": "status = 'rejected'",
            "count": 150,
        },
        "input_context": "Agent wants to clean up rejected candidates from the database",
    })
    result = response.json()
    print(f"  Decision: {result['decision']}")
    print(f"  Reason: {result['reason']}")

    time.sleep(0.5)

    # ── Step 5: More approved actions for a richer report ─────────
    step(5, "Simulating 5 more approved outreach emails...")

    for i in range(5):
        resp = client.post("/actions", json={
            "agent_id": "recruiting-agent-001",
            "action_type": "email",
            "tool_name": "send_email",
            "payload": {
                "to": f"candidate{i+1}@example.com",
                "subject": "Data Engineering opportunity",
                "body": f"Personalized outreach email #{i+1}...",
            },
        })
        eid = resp.json()["event_id"]
        # Auto-approve these for demo purposes
        client.post(f"/actions/{eid}/approve", json={
            "authorized_by": "jason@airblackbox.ai",
        })
        print(f"  Email #{i+1}: approved ✓")

    time.sleep(0.5)

    # ── Step 6: Verify the audit chain ────────────────────────────
    step(6, "Verifying audit chain integrity")

    verification = client.get("/verify").json()
    print(f"  Chain valid: {verification['valid']}")
    print(f"  Events verified: {verification['events_checked']}")
    if verification['errors']:
        for err in verification['errors']:
            print(f"  ERROR: {err}")

    # ── Step 7: Get stats ─────────────────────────────────────────
    step(7, "Event store statistics")

    stats = client.get("/stats").json()
    print(f"  Total events: {stats['total']}")
    print(f"  By result: {json.dumps(stats['by_result'], indent=4)}")
    print(f"  By action type: {json.dumps(stats['by_action_type'], indent=4)}")

    # ── Step 8: Generate compliance report ────────────────────────
    step(8, "Generating compliance report")

    print(f"\n  View the report at:")
    print(f"  HTML:     {GATE_URL}/report")
    print(f"  JSON:     {GATE_URL}/report?format=json")
    print(f"  Markdown: {GATE_URL}/report?format=markdown")
    print(f"\n  To save as PDF: open the HTML report in your browser and print to PDF.\n")

    banner("Demo Complete!")
    print("  Your recruiting AI agent just:")
    print("  ✓ Searched for candidates (auto-approved)")
    print("  ✓ Sent outreach emails (human-approved via Gate)")
    print("  ✓ Got blocked from deleting data (policy enforcement)")
    print("  ✓ Every action signed with HMAC-SHA256 chains")
    print("  ✓ Compliance report ready for legal/compliance team")
    print(f"\n  Events stored in: gate_events.jsonl")
    print(f"  Report URL: {GATE_URL}/report\n")


if __name__ == "__main__":
    main()
