#!/usr/bin/env python3
"""
AIR Gate CLI — the single entry point for the AI Action Firewall.

Usage:
    air-gate demo          Run the interactive demo (no server needed)
    air-gate demo --sqlite Use SQLite storage (default)
    air-gate demo --jsonl  Use JSONL file storage
    air-gate verify <path> Verify an audit chain file
    air-gate version       Show version info
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .events import EventStore, GateEvent
from .policy import PolicyEngine, PolicyRule

__version__ = "0.3.0"

# Back-compat: CLI was originally named air-blackbox in the gate repo

# ─── Terminal Colors ───────────────────────────────────────────────
# Works on macOS, Linux, and Windows Terminal / PowerShell 7+

BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
ORANGE = "\033[38;5;208m"
WHITE = "\033[97m"
BG_GREEN = "\033[42m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"


def _supports_color():
    """Check if the terminal supports color output."""
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


if not _supports_color():
    BOLD = DIM = RESET = GREEN = RED = YELLOW = BLUE = CYAN = ORANGE = WHITE = ""
    BG_GREEN = BG_RED = BG_YELLOW = BG_BLUE = ""


# ─── Display Helpers ──────────────────────────────────────────────

def banner():
    print(f"""
{ORANGE}{BOLD}    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   {WHITE}AIR GATE{ORANGE}  —  The AI Action Firewall                   ║
    ║                                                          ║
    ║   {RESET}{DIM}Tamper-evident audit trails for AI agents{RESET}{ORANGE}{BOLD}             ║
    ║   {RESET}{DIM}EU AI Act compliance infrastructure{RESET}{ORANGE}{BOLD}                   ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝{RESET}
""")


def step_header(num, total, title):
    bar = "█" * num + "░" * (total - num)
    print(f"\n  {CYAN}{BOLD}[{num}/{total}]{RESET} {BOLD}{title}{RESET}")
    print(f"  {DIM}{bar}{RESET}")


def event_box(event, decision_color, decision_label):
    """Pretty-print a single event as a compact box."""
    print(f"""
    {DIM}┌─────────────────────────────────────────────────────┐{RESET}
    {DIM}│{RESET} {BOLD}Agent:{RESET}    {event.agent_id:<40}{DIM}│{RESET}
    {DIM}│{RESET} {BOLD}Action:{RESET}   {event.action_type} → {event.tool_name:<29}{DIM}│{RESET}
    {DIM}│{RESET} {BOLD}Decision:{RESET} {decision_color}{decision_label:<39}{RESET}{DIM}│{RESET}
    {DIM}│{RESET} {BOLD}Event ID:{RESET} {DIM}{event.event_id[:28]}...{RESET}  {DIM}│{RESET}
    {DIM}│{RESET} {BOLD}HMAC:{RESET}     {DIM}{event.hmac_signature[:32]}...{RESET}{DIM}│{RESET}
    {DIM}└─────────────────────────────────────────────────────┘{RESET}""")


def success(text):
    print(f"    {GREEN}✓{RESET} {text}")


def fail(text):
    print(f"    {RED}✗{RESET} {text}")


def info(text):
    print(f"    {BLUE}ℹ{RESET} {text}")


def warn(text):
    print(f"    {YELLOW}⚠{RESET} {text}")


def typing_effect(text, delay=0.02):
    """Simulate typing for dramatic effect on key messages."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


# ─── Demo Command ─────────────────────────────────────────────────

def run_demo(storage="sqlite"):
    """
    Run the self-contained AIR Blackbox demo.

    No server required. Everything runs in-process:
    - EventStore records and signs events
    - PolicyEngine evaluates actions
    - Audit chain is verified cryptographically
    """
    import tempfile

    banner()

    # Setup storage
    if storage == "sqlite":
        db_path = os.path.join(tempfile.gettempdir(), "air_blackbox_demo.db")
        storage_path = db_path
        info(f"Storage: SQLite → {DIM}{db_path}{RESET}")
    else:
        storage_path = os.path.join(tempfile.gettempdir(), "air_blackbox_demo.jsonl")
        info(f"Storage: JSONL → {DIM}{storage_path}{RESET}")

    # Clean previous demo data
    if os.path.exists(storage_path):
        os.remove(storage_path)

    # Initialize components
    signing_key = "demo-signing-key-change-in-production"
    store = EventStore(signing_key=signing_key, storage_path=storage_path)

    policy = PolicyEngine(rules=[
        PolicyRule(
            name="allow-search",
            action_type="search",
            decision="auto_allow",
            description="Search actions are low-risk — auto-approved",
        ),
        PolicyRule(
            name="approve-emails",
            action_type="email",
            decision="require_approval",
            description="Outbound emails require human approval",
            max_per_hour=50,
        ),
        PolicyRule(
            name="block-delete",
            action_type="db_delete",
            decision="block",
            description="AI agents cannot delete data — ever",
        ),
    ])

    total_steps = 7
    print(f"\n  {DIM}Simulating a recruiting AI agent sending outreach emails.{RESET}")
    print(f"  {DIM}Every action flows through AIR Blackbox for audit + policy.{RESET}\n")
    time.sleep(0.5)

    # ── Step 1: Auto-allowed search ──
    step_header(1, total_steps, "Agent searches for candidates")

    decision = policy.evaluate(
        agent_id="recruiting-agent-001",
        action_type="search",
        tool_name="linkedin_search",
    )

    event1 = GateEvent(
        agent_id="recruiting-agent-001",
        action_type="search",
        tool_name="linkedin_search",
        payload={"query": "senior data engineer", "location": "San Francisco"},
        input_context="User asked: find senior data engineers in SF",
        result="auto_allowed",
        authorized_by="auto-policy",
    )
    store.record(event1)
    event_box(event1, GREEN, "AUTO-ALLOWED ✓")
    success(f"Policy: {decision['rule_name']} — {decision['reason']}")
    time.sleep(0.8)

    # ── Step 2: Email requires approval ──
    step_header(2, total_steps, "Agent wants to send outreach email")

    decision = policy.evaluate(
        agent_id="recruiting-agent-001",
        action_type="email",
        tool_name="send_email",
    )

    event2 = GateEvent(
        agent_id="recruiting-agent-001",
        action_type="email",
        tool_name="send_email",
        payload={
            "to": "jane.doe@example.com",
            "subject": "Senior Data Engineer opportunity",
            "body": "Hi Jane, I came across your work at Stripe on real-time pipelines...",
        },
        input_context="Agent matched Jane Doe as 92% fit based on Kafka expertise",
        result="pending",
    )
    store.record(event2)
    event_box(event2, YELLOW, "PENDING APPROVAL ⏳")
    warn(f"Policy: {decision['rule_name']} — {decision['reason']}")
    time.sleep(0.8)

    # ── Step 3: Human approves ──
    step_header(3, total_steps, "Human approves the email")

    print(f"\n    {DIM}(In production, this happens via Slack, API, or dashboard){RESET}")
    time.sleep(0.3)

    store.update_result(
        event_id=event2.event_id,
        result="approved",
        authorized_by="jason@airblackbox.ai",
        detail="Email looks good. Send it.",
    )
    event_box(event2, GREEN, "APPROVED by jason@airblackbox.ai ✓")
    success("Human-in-the-loop oversight: Article 14 ✓")
    time.sleep(0.8)

    # ── Step 4: Blocked action ──
    step_header(4, total_steps, "Agent tries to delete records")

    decision = policy.evaluate(
        agent_id="recruiting-agent-001",
        action_type="db_delete",
        tool_name="delete_records",
    )

    event3 = GateEvent(
        agent_id="recruiting-agent-001",
        action_type="db_delete",
        tool_name="delete_records",
        payload={"table": "candidates", "filter": "status = 'rejected'", "count": 150},
        input_context="Agent wants to clean up rejected candidates",
        result="blocked",
        authorized_by="auto-policy",
        result_detail=decision["reason"],
    )
    store.record(event3)
    event_box(event3, RED, "BLOCKED ✗")
    fail(f"Policy: {decision['rule_name']} — {decision['reason']}")
    time.sleep(0.8)

    # ── Step 5: Batch approved emails ──
    step_header(5, total_steps, "Simulating 5 more approved outreach emails")

    candidates = [
        ("alex.chen@example.com", "Alex Chen", "Netflix"),
        ("maria.garcia@example.com", "Maria Garcia", "Airbnb"),
        ("james.wilson@example.com", "James Wilson", "Databricks"),
        ("sarah.kim@example.com", "Sarah Kim", "Snowflake"),
        ("david.patel@example.com", "David Patel", "Uber"),
    ]

    for i, (email, name, company) in enumerate(candidates):
        event = GateEvent(
            agent_id="recruiting-agent-001",
            action_type="email",
            tool_name="send_email",
            payload={"to": email, "subject": f"Data Engineering opportunity at {company}"},
            result="approved",
            authorized_by="jason@airblackbox.ai",
        )
        store.record(event)
        success(f"Email #{i+1}: {name} ({company}) — approved + signed")
        time.sleep(0.15)

    time.sleep(0.5)

    # ── Step 6: Verify chain ──
    step_header(6, total_steps, "Verifying HMAC-SHA256 audit chain")

    verification = store.verify_chain()
    print()
    if verification["valid"]:
        typing_effect(f"    {GREEN}{BOLD}Chain integrity: VALID{RESET}")
        success(f"Events verified: {verification['events_checked']}")
        success("Zero tampering detected")
        success("Every event cryptographically linked to previous")
    else:
        fail(f"Chain integrity: BROKEN")
        for err in verification["errors"]:
            fail(err)
    time.sleep(0.8)

    # ── Step 7: Summary ──
    step_header(7, total_steps, "Audit summary")

    stats = store.get_stats()
    print(f"""
    {DIM}┌─────────────────────────────────────────────────────┐{RESET}
    {DIM}│{RESET}  {BOLD}AIR Gate Audit Report{RESET}                               {DIM}│{RESET}
    {DIM}├─────────────────────────────────────────────────────┤{RESET}
    {DIM}│{RESET}                                                     {DIM}│{RESET}
    {DIM}│{RESET}  Total events:    {BOLD}{stats['total']}{RESET}                                {DIM}│{RESET}
    {DIM}│{RESET}  Auto-allowed:    {GREEN}{stats['by_result'].get('auto_allowed', 0)}{RESET}                                {DIM}│{RESET}
    {DIM}│{RESET}  Human-approved:  {GREEN}{stats['by_result'].get('approved', 0)}{RESET}                                {DIM}│{RESET}
    {DIM}│{RESET}  Blocked:         {RED}{stats['by_result'].get('blocked', 0)}{RESET}                                {DIM}│{RESET}
    {DIM}│{RESET}  Chain valid:     {GREEN if stats['chain_valid'] else RED}{'YES' if stats['chain_valid'] else 'NO'}{RESET}                              {DIM}│{RESET}
    {DIM}│{RESET}                                                     {DIM}│{RESET}
    {DIM}│{RESET}  {BOLD}EU AI Act Coverage:{RESET}                                 {DIM}│{RESET}
    {DIM}│{RESET}  Art. 9  Risk Management     {GREEN}✓{RESET} policy engine         {DIM}│{RESET}
    {DIM}│{RESET}  Art. 12 Record-Keeping       {GREEN}✓{RESET} HMAC audit chain      {DIM}│{RESET}
    {DIM}│{RESET}  Art. 14 Human Oversight      {GREEN}✓{RESET} approval gates        {DIM}│{RESET}
    {DIM}│{RESET}  Art. 15 Robustness           {GREEN}✓{RESET} action blocking       {DIM}│{RESET}
    {DIM}│{RESET}                                                     {DIM}│{RESET}
    {DIM}│{RESET}  Audit file: {DIM}{storage_path}{RESET}
    {DIM}│{RESET}                                                     {DIM}│{RESET}
    {DIM}└─────────────────────────────────────────────────────┘{RESET}
""")

    # ── What's Next ──
    print(f"  {BOLD}What just happened:{RESET}")
    print(f"  Your AI agent ran 8 actions through AIR Gate.")
    print(f"  Every action was {BOLD}policy-checked{RESET}, {BOLD}signed with HMAC-SHA256{RESET},")
    print(f"  and {BOLD}chained{RESET} into a tamper-evident audit trail.")
    print()
    print(f"  {BOLD}Next steps:{RESET}")
    print(f"  1. Add to your own agent:  {CYAN}from air_gate import GateClient{RESET}")
    print(f"  2. Start the full server:  {CYAN}pip install air-gate[server]{RESET}")
    print(f"     Then:                   {CYAN}uvicorn gate.proxy:app --reload{RESET}")
    print(f"  3. View docs:              {CYAN}https://airblackbox.ai/gate{RESET}")
    print()
    print(f"  {DIM}Audit trail saved to: {storage_path}{RESET}")
    print(f"  {DIM}Run 'air-gate verify {storage_path}' to re-verify anytime.{RESET}")
    print()


# ─── Verify Command ───────────────────────────────────────────────

def run_verify(path, public_key=None):
    """Verify an existing audit chain file."""
    if not os.path.exists(path):
        print(f"  {RED}Error:{RESET} File not found: {path}")
        sys.exit(1)

    public_key = public_key or os.getenv("GATE_ED25519_PUBLIC_HEX")
    if public_key:
        # Ed25519: verify with only the public key (no forging power needed).
        from .signing import Ed25519Signer
        try:
            signer = Ed25519Signer.from_public_hex(public_key)
        except (ValueError, ImportError) as e:
            print(f"  {RED}Error:{RESET} invalid Ed25519 public key: {e}")
            sys.exit(1)
        store = EventStore(signer=signer, storage_path=path)
        print(f"\n  {DIM}Algorithm: Ed25519 (public-key verification){RESET}")
    else:
        signing_key = os.getenv("GATE_SIGNING_KEY", "demo-signing-key-change-in-production")
        store = EventStore(signing_key=signing_key, storage_path=path)

    print(f"\n  {BOLD}Verifying audit chain:{RESET} {path}")
    print(f"  {DIM}Events loaded: {len(store.events)}{RESET}\n")

    verification = store.verify_chain()

    if verification["valid"]:
        print(f"  {GREEN}{BOLD}✓ Chain integrity: VALID{RESET}")
        print(f"  {GREEN}  {verification['events_checked']} events verified{RESET}")
        print(f"  {GREEN}  Zero tampering detected{RESET}")
    else:
        print(f"  {RED}{BOLD}✗ Chain integrity: BROKEN{RESET}")
        for err in verification["errors"]:
            print(f"  {RED}  {err}{RESET}")
        sys.exit(1)

    print()


# ─── Keygen Command ───────────────────────────────────────────────

def run_keygen():
    """Generate an Ed25519 keypair for asymmetric audit-chain signing."""
    try:
        from .signing import Ed25519Signer
        signer = Ed25519Signer.generate()
    except ImportError:
        print(f"  {RED}Error:{RESET} Ed25519 needs the 'cryptography' package.")
        print(f"  Install it with: {CYAN}pip install air-gate[crypto]{RESET}")
        sys.exit(1)

    print(f"\n  {BOLD}Ed25519 keypair generated.{RESET}\n")
    print(f"  {DIM}Private key (keep secret — signs the chain):{RESET}")
    print(f"  {YELLOW}GATE_ED25519_PRIVATE_HEX={signer.private_key_hex}{RESET}\n")
    print(f"  {DIM}Public key (share freely — verifies the chain):{RESET}")
    print(f"  {GREEN}GATE_ED25519_PUBLIC_HEX={signer.public_key_hex}{RESET}\n")
    print(f"  {DIM}Set GATE_SIGNATURE_ALGORITHM=Ed25519 and the private key on the")
    print(f"  server; hand auditors only the public key to verify:{RESET}")
    print(f"  {CYAN}air-gate verify chain.db --public-key {signer.public_key_hex}{RESET}\n")


# ─── Main Entry Point ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="air-gate",
        description="AIR Gate — The AI Action Firewall. Tamper-evident audit trails for AI agents.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # demo command
    demo_parser = subparsers.add_parser("demo", help="Run the interactive demo (no server needed)")
    demo_parser.add_argument("--jsonl", action="store_true", help="Use JSONL file storage instead of SQLite")
    demo_parser.add_argument("--sqlite", action="store_true", default=True, help="Use SQLite storage (default)")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify an audit chain file")
    verify_parser.add_argument("path", help="Path to the audit chain file (.jsonl or .db)")
    verify_parser.add_argument(
        "--public-key",
        help="Ed25519 public key (hex) to verify an asymmetrically-signed chain",
    )

    # keygen command
    subparsers.add_parser("keygen", help="Generate an Ed25519 keypair for asymmetric signing")

    # version command
    subparsers.add_parser("version", help="Show version info")

    args = parser.parse_args()

    if args.command == "demo":
        storage = "jsonl" if args.jsonl else "sqlite"
        run_demo(storage=storage)
    elif args.command == "verify":
        run_verify(args.path, public_key=args.public_key)
    elif args.command == "keygen":
        run_keygen()
    elif args.command == "version":
        print(f"air-gate {__version__}")
    else:
        banner()
        parser.print_help()


if __name__ == "__main__":
    main()
