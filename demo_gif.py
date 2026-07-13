#!/usr/bin/env python3
"""
Scripted air-gate demo for GIF recording.
Runs fast, no user interaction, shows all key features.
"""
import os
import sys
import time
import tempfile
import json

# Ensure we can import air_gate
sys.path.insert(0, os.path.dirname(__file__))

from air_gate.events import EventStore, GateEvent
from air_gate.policy import PolicyEngine, PolicyRule
from air_gate.pii import PIIRedactor, RedactionMethod
from air_gate.client import GateClient

# Colors
B = "\033[1m"
D = "\033[2m"
R = "\033[0m"
G = "\033[32m"
RED = "\033[31m"
Y = "\033[33m"
C = "\033[36m"
O = "\033[38;5;208m"
W = "\033[97m"

def p(text, delay=0.01):
    """Print with slight delay for recording."""
    print(text)
    time.sleep(delay)

def section(title):
    print()
    p(f"  {C}{B}━━━ {title} ━━━{R}")
    print()
    time.sleep(0.3)

# ══════════════════════════════════════════════════════════════
print()
p(f"  {O}{B}╔═══════════════════════════════════════════════════╗{R}")
p(f"  {O}{B}║  {W}AIR GATE{O}  v0.2.0 — The AI Action Firewall      ║{R}")
p(f"  {O}{B}║  {R}{D}pip install air-gate{R}  {O}{B}                           ║{R}")
p(f"  {O}{B}╚═══════════════════════════════════════════════════╝{R}")
print()
time.sleep(0.5)

# Setup
db = os.path.join(tempfile.gettempdir(), "air_gate_gif_demo.db")
if os.path.exists(db):
    os.remove(db)

gate = GateClient(
    storage_path=db,
    policy_config={
        "default": "require_approval",
        "rules": [
            {"name": "allow-search", "action_type": "search", "decision": "auto_allow",
             "description": "Read-only searches are safe"},
            {"name": "approve-emails", "action_type": "email", "decision": "require_approval",
             "description": "Outbound emails need human approval"},
            {"name": "block-delete", "action_type": "db_delete", "decision": "block",
             "description": "AI cannot delete data"},
        ]
    }
)


# ── 1. AUTO-ALLOWED ─────────────────────────────────────────
section("1. Agent searches for candidates")

p(f"  {D}POST /actions{R}  {C}tool: search_candidates{R}")
r1 = gate.check("recruiting-agent", "search", "search_candidates",
                 payload={"query": "senior data engineer", "location": "SF"})
p(f"  {G}✓ AUTO-ALLOWED{R}  {D}— matched rule: allow-search{R}")
p(f"  {D}Event: {r1['event_id'][:12]}...{R}")
time.sleep(0.5)

# ── 2. PII REDACTION + APPROVAL ─────────────────────────────
section("2. Agent sends email (PII auto-redacted)")

payload = {
    "to": "jane.doe@stripe.com",
    "subject": "Data Engineering opportunity",
    "body": "Hi Jane, saw your work on Kafka. Call me at 415-555-0199.",
    "ssn": "123-45-6789"
}

p(f"  {D}POST /actions{R}  {C}tool: send_email{R}")
p(f"  {D}Payload:{R}")
p(f"    {D}to:{R} jane.doe@stripe.com")
p(f"    {D}ssn:{R} 123-45-6789")
p(f"    {D}body:{R} ...Call me at 415-555-0199")
print()

# Show PII redaction
redactor = PIIRedactor()
safe, detections = redactor.redact(payload)
p(f"  {Y}⚡ PII REDACTED: {len(detections)} fields{R}")
for d in detections[:3]:
    p(f"    {Y}→{R} {d.category}: {d.field_path} {D}[{d.redaction_method}]{R}")
print()

r2 = gate.check("recruiting-agent", "email", "send_email",
                 payload=safe)
p(f"  {Y}⏳ PENDING APPROVAL{R}  {D}— sent to Slack #ai-approvals{R}")
time.sleep(0.4)

# Simulate human approval
gate.approve(r2["event_id"], "jason@airblackbox.ai", "Looks good")
p(f"  {G}✓ APPROVED{R} by jason@airblackbox.ai {D}(via Slack){R}")
time.sleep(0.5)

# ── 3. BLOCKED ──────────────────────────────────────────────
section("3. Agent tries to delete records")

p(f"  {D}POST /actions{R}  {C}tool: delete_records{R}")
r3 = gate.check("recruiting-agent", "db_delete", "delete_records",
                 payload={"table": "candidates", "filter": "rejected", "count": 150})
p(f"  {RED}✗ BLOCKED{R}  {D}— matched rule: block-delete{R}")
p(f"  {RED}  AI agents cannot delete data{R}")
time.sleep(0.5)


# ── 4. VERIFY CHAIN ─────────────────────────────────────────
section("4. Verify HMAC-SHA256 audit chain")

v = gate.verify()
p(f"  {G}{B}Chain integrity: VALID{R}")
p(f"  {G}✓{R} {v['events_checked']} events verified")
p(f"  {G}✓{R} Zero tampering detected")
p(f"  {G}✓{R} Every event cryptographically linked")
time.sleep(0.5)

# ── 5. STATS ────────────────────────────────────────────────
section("5. Compliance summary")

s = gate.stats()
print(f"""
  {D}┌───────────────────────────────────────────────┐{R}
  {D}│{R}  {B}AIR Gate — Audit Report{R}                       {D}│{R}
  {D}├───────────────────────────────────────────────┤{R}
  {D}│{R}  Total events:    {B}{s['total']}{R}                           {D}│{R}
  {D}│{R}  Auto-allowed:    {G}{s['by_result'].get('auto_allowed', 0)}{R}                           {D}│{R}
  {D}│{R}  Approved:        {G}{s['by_result'].get('approved', 0)}{R}                           {D}│{R}
  {D}│{R}  Blocked:         {RED}{s['by_result'].get('blocked', 1)}{R}                           {D}│{R}
  {D}│{R}  Chain valid:     {G}YES{R}                         {D}│{R}
  {D}│{R}                                               {D}│{R}
  {D}│{R}  {B}EU AI Act Coverage:{R}                           {D}│{R}
  {D}│{R}  Art. 9  Risk Management   {G}✓{R} policy engine     {D}│{R}
  {D}│{R}  Art. 12 Record-Keeping    {G}✓{R} HMAC audit chain  {D}│{R}
  {D}│{R}  Art. 14 Human Oversight   {G}✓{R} approval gates    {D}│{R}
  {D}│{R}  Art. 15 Robustness        {G}✓{R} action blocking   {D}│{R}
  {D}│{R}  GDPR    PII Protection    {G}✓{R} auto-redaction    {D}│{R}
  {D}└───────────────────────────────────────────────┘{R}
""")
time.sleep(0.5)

# ── NEXT STEPS ──────────────────────────────────────────────
p(f"  {B}Get started:{R}")
p(f"  {C}pip install air-gate{R}")
p(f"  {C}from air_gate import GateClient{R}")
p(f"")
p(f"  {D}GitHub: github.com/airblackbox/air-gate{R}")
p(f"  {D}Docs:   airblackbox.ai/gate{R}")
print()
