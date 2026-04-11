# air-gate

HMAC-SHA256 audit chain engine with human-in-the-loop tool gating for AI agents. Implements EU AI Act Article 14 (Human Oversight).

## Overview

`air-gate` sits between your AI agent and its tools. Before calling a dangerous operation (send email, delete files, execute SQL), it pauses execution and requires explicit human approval. Every approval or denial is logged to a tamper-evident HMAC-SHA256 audit chain.

## Quick Start

```bash
pip install air-gate
```

### Basic Usage

```python
from air_gate import GateKeeper, RiskTier
from air_trust import AuditChain

# Initialize with audit chain
audit_chain = AuditChain(secret_key="your-secret")
gatekeeper = GateKeeper(audit_chain=audit_chain)

# Configure risk tiers
gatekeeper.set_risk_tier("send_email", RiskTier.HIGH)
gatekeeper.set_risk_tier("read_file", RiskTier.LOW)
gatekeeper.set_risk_tier("execute_sql", RiskTier.HIGH)

# Gate a tool call
def send_email(to, subject, body):
    # Returns True if approved, False if denied
    if not gatekeeper.request_approval("send_email", {"to": to}):
        raise PermissionError("Tool call denied by human")
    # ... actual email logic
    
# Automatic approval for low-risk tools, human review for HIGH
result = send_email("user@example.com", "Hello", "Test message")

# Access audit trail
for entry in audit_chain.entries():
    print(f"{entry['timestamp']} | {entry['action']} | HMAC: {entry['signature']}")
```

## Risk Tier Configuration

Configure tools by risk level. Use a dict or YAML config:

```python
risk_config = {
    "LOW": ["read_file", "list_directory", "get_current_time"],
    "MEDIUM": ["write_file", "send_slack_message"],
    "HIGH": ["send_email", "execute_sql", "delete_file", "deploy_service"]
}

gatekeeper.load_config(risk_config)
```

**AUTO_APPROVE** (LOW): Tools execute without human intervention.  
**REQUIRE_APPROVAL** (MEDIUM/HIGH): Execution pauses; human must approve/deny.

## Audit Chain & Tamper-Evidence

Every gate decision is cryptographically signed using HMAC-SHA256. The chain prevents tampering:

```python
# Each entry includes timestamp, action, decision, and HMAC signature
entry = {
    "timestamp": "2026-04-10T14:32:05Z",
    "tool": "send_email",
    "decision": "APPROVED",
    "approver": "alice@company.com",
    "signature": "abc123def456..."  # HMAC-SHA256
}

# Verify chain integrity
is_valid = audit_chain.verify()  # True if unmodified, False if tampered
```

All entries are chained: each signature depends on the previous entry, making it impossible to insert, delete, or reorder decisions without detection.

## Integration with air-trust

`air-gate` uses `air-trust`'s `AuditChain` class under the hood for cryptographic signing and verification. This ensures your approval log is tamper-evident and compliant with Article 14 record-keeping requirements.

```python
from air_trust import AuditChain

# air-gate automatically uses this for HMAC signing
audit_chain = AuditChain(secret_key="your-secret-key")
gatekeeper = GateKeeper(audit_chain=audit_chain)
```

## Part of AIR Blackbox

`air-gate` is one component of the **AIR Blackbox** ecosystem for EU AI Act compliance:

- **[air-gate](https://github.com/airblackbox/air-gate)** — Human-in-the-loop tool gating (Article 14)
- **[air-trust](https://github.com/airblackbox/air-trust)** — HMAC audit chains + Ed25519 signed handoffs
- **[air-blackbox](https://github.com/airblackbox/gateway)** — EU AI Act compliance scanner (39 checks)
- **[air-blackbox-mcp](https://github.com/airblackbox/air-blackbox-mcp)** — Claude Desktop / Cursor integration

## License

Apache License 2.0. See LICENSE file.

## Installation from PyPI

```bash
pip install air-gate
```

---

**Questions?** Open an issue on [GitHub](https://github.com/airblackbox/air-gate).
# AIR Gate

**The AI Action Firewall** — Every agent action gated, signed, and auditable.

<p align="center">
  <img src="demo.gif" alt="AIR Gate demo" width="800">
</p>

Gate sits between your AI agents and the real world. Every action flows through Gate, gets checked against policy, PII is automatically redacted, and everything produces a tamper-evident signed record.

## What's New in v0.2.0

- **PII Redaction** — Automatic detection and redaction of emails, SSNs, credit cards, medical records, and 25+ PII categories before they enter the audit chain. GDPR, HIPAA, PCI-DSS compliant.
- **GateClient SDK** — Use Gate as a library without running a server. `from air_gate import GateClient`
- **Callback URLs** — Gate POSTs the decision back to your agent when a human approves/rejects in Slack.
- **Framework Integrations** — Drop-in wrappers for LangChain tools and OpenAI function tools.
- **Rebranded CLI** — `air-gate demo` and `air-gate verify` (was air-blackbox).
## How It Works

```
Agent wants to send email
       ↓
   Gate intercepts
       ↓
   PII redacted from payload
       ↓
   Policy check
       ↓
  ┌────┴────┐────────┐
  ↓         ↓        ↓
Auto-Allow  Slack   Block
            Approval
  ↓         ↓        ↓
  Signed event recorded
  (HMAC-SHA256 chain)
       ↓
  Callback to agent
```

## Quick Start

### Option 1: Library Mode (no server)

```python
from air_gate import GateClient

gate = GateClient()  # local mode, zero config
result = gate.check("my-agent", "email", "send_email",
                    payload={"to": "jane@example.com"})

if result["decision"] == "auto_allowed":
    send_the_email()
elif result["decision"] == "blocked":
    print("Blocked:", result["reason"])

# Verify the audit chain anytime
print(gate.verify())
```

### Option 2: Server Mode (Slack approvals)

```bash
pip install air-gate[server]
uvicorn gate.proxy:app --reload
```

```python
gate = GateClient(server_url="http://localhost:8000")
result = gate.check("my-agent", "email", "send_email",
                    payload={"to": "jane@example.com"},
                    callback_url="http://my-agent/callback")
```

### Option 3: Framework Integrations

**LangChain:**
```python
from air_gate.integrations.langchain import GatedTool
gated_search = GatedTool(tool=my_search_tool, agent_id="research-agent")
# Use gated_search in your agent chain — every call goes through Gate
```

**OpenAI Function Tools:**
```python
from air_gate.integrations.openai_agents import gated_tool
from air_gate import GateClient

gate = GateClient()

@gated_tool(gate=gate, agent_id="assistant-v1")
def send_email(to: str, subject: str, body: str) -> str:
    return f"Email sent to {to}"
```

## Run the Demo

```bash
pip install air-gate
air-gate demo
```

## Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Key environment variables:- `GATE_SIGNING_KEY` — HMAC signing key (required for production)
- `GATE_STORAGE_PATH` — Event storage file (default: `gate_events.jsonl`)
- `GATE_PII_REDACTION` — Enable PII auto-redaction (default: `true`)
- `GATE_PII_METHOD` — Redaction method: `hash_sha256`, `mask`, `remove`, `tokenise`
- `SLACK_WEBHOOK_URL` — Slack incoming webhook for approvals
- `SLACK_BOT_TOKEN` — Slack bot token (for full interactivity)

Edit `gate_config.yaml` for policy rules:

```yaml
policy:
  default: require_approval
  rules:
    - name: allow-search
      action_type: search
      decision: auto_allow
    - name: block-delete
      action_type: db_delete
      decision: block
    - name: approve-emails
      action_type: email
      decision: require_approval
      max_per_hour: 50
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/actions` | POST | Submit an agent action |
| `/actions/{id}/approve` | POST | Approve a pending action || `/actions/{id}/reject` | POST | Reject a pending action |
| `/events` | GET | Query the event store |
| `/events/{id}` | GET | Get a specific event |
| `/verify` | GET | Verify audit chain integrity |
| `/stats` | GET | Summary statistics |
| `/report` | GET | Generate compliance report (HTML/JSON/Markdown) |
| `/health` | GET | Health check |

## PII Redaction

Gate automatically detects and redacts 25+ categories of PII before data enters the audit chain:

- **Universal:** Email, phone, IP, date of birth, passport, national ID
- **Recruiting:** LinkedIn URLs, resume text, protected characteristics (EEOC)
- **Finance:** Credit cards, bank accounts, routing numbers, SSN, tax ID (PCI-DSS)
- **Healthcare:** Medical record numbers, health plan IDs, NPI (HIPAA)
- **Legal:** Case numbers, bar numbers, client matter IDs

Every redaction is logged with SHA-256 hash of the original value, enabling GDPR Article 17 erasure lookups.

## Architecture

```
gate/
├── client.py           — GateClient SDK (library mode)
├── proxy.py            — FastAPI server (server mode)
├── events.py           — HMAC-SHA256 signed event store (SQLite + JSONL)
├── policy.py           — Policy engine (YAML rules)
├── pii.py              — PII detection + redaction (multi-vertical)
├── slack_bot.py        — Slack approval bot (Block Kit)
├── report.py           — Compliance report generator├── report_endpoint.py  — /report API endpoint
├── tracing.py          — OpenTelemetry integration
├── cli.py              — air-gate CLI
└── integrations/
    ├── langchain.py    — LangChain tool wrapper
    └── openai_agents.py — OpenAI function tool decorator
```

## Part of AIR Blackbox

- **AIR Blackbox** scans your AI system for compliance issues (build-time)
- **AIR Gate** controls what your AI agents can do at runtime

Together: full AI governance lifecycle. [airblackbox.ai](https://airblackbox.ai)
