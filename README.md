# air-gate

Policy engine + human-in-the-loop tool gating + tamper-evident HMAC-SHA256 audit
chain for AI agents. Helps satisfy EU AI Act Article 14 (Human Oversight) and
Article 12 (Record-Keeping).

**▶ [Try the live demo](https://airblackbox.ai/demo/gate)** — run agent actions, approve one, then tamper with the log and watch verification fail. Runs entirely in your browser. The version in [`demo/`](demo/) is a standalone, package-accurate build you can open or host yourself.

## Overview

`air-gate` sits between your AI agent and its tools. Every tool call is checked
against a policy and recorded to an append-only, cryptographically signed audit
chain. Low-risk actions run automatically; risky ones (send email, delete data,
execute SQL) **pause and wait for a human decision** before the tool runs.

Two ways to use it:

- **Local mode** — everything runs in-process. Zero servers. Great for a single
  agent, tests, or embedding the audit chain directly in your app.
- **Server mode** — run the Gate proxy; approvals happen in Slack (or via the
  HTTP API). Use this for multi-agent setups and real human-in-the-loop review.

## Install

```bash
pip install air-gate              # core: GateClient + policy + audit chain
pip install "air-gate[server]"    # adds the FastAPI proxy + Slack approvals
pip install "air-gate[langchain]" # adds the LangChain tool wrapper
```

## Quick Start (local mode)

```python
from air_gate import GateClient

# Local mode: no server. Events are policy-checked, signed, and chained on disk.
gate = GateClient(
    signing_key="use-a-real-secret",
    storage_path="gate_events.db",
    policy_config={
        "default": "require_approval",
        "rules": [
            {"name": "search",  "action_type": "search", "decision": "auto_allow"},
            {"name": "emails",  "action_type": "email",  "decision": "require_approval"},
            {"name": "deletes", "action_type": "db_delete", "decision": "block"},
        ],
    },
)

result = gate.check(
    agent_id="recruiting-agent",
    action_type="email",
    tool_name="send_email",
    payload={"to": "jane@example.com", "subject": "Hello"},
    input_context="Agent matched Jane as a 92% fit",
)

# check() returns one of: "auto_allowed", "pending_approval", "blocked"
if result["decision"] == "auto_allowed":
    send_the_email()
elif result["decision"] == "blocked":
    print("Blocked by policy:", result["reason"])
else:  # pending_approval
    # A human approves out-of-band (Slack, API, another process), then:
    gate.approve(result["event_id"], authorized_by="alice@company.com")

# Verify the audit chain at any time
print(gate.verify())   # {"valid": True, "events_checked": N, "errors": []}
```

## Policy configuration

Rules are evaluated in order — **first match wins**. If nothing matches, the
`default` decision applies. A rule's `decision` is one of `auto_allow`,
`require_approval`, or `block`. Match on any combination of `agent_id`,
`action_type`, and `tool_name`; a field left unset matches anything.

```yaml
# gate_config.yaml
policy:
  default: require_approval          # safest default: humans approve everything

  rules:
    - name: allow-read-only
      action_type: db_read
      decision: auto_allow

    - name: block-delete
      action_type: db_delete
      decision: block

    - name: approve-emails
      action_type: email
      decision: require_approval
      max_per_hour: 50               # optional rate limit (blocks over the cap)
      max_payload_size: 100000       # optional payload byte cap
```

```python
gate = GateClient(config_path="gate_config.yaml")
```

## Human-in-the-loop (blocking)

When you wrap tools with an integration, a `require_approval` action **blocks
the tool call until a human decides**, then runs the tool only if approved. If
it is rejected — or no decision arrives before the timeout — the wrapper fails
closed and the tool never runs.

### LangChain

```python
from langchain_community.tools import DuckDuckGoSearchRun
from air_gate.integrations.langchain import GatedTool

gated_search = GatedTool(
    tool=DuckDuckGoSearchRun(),
    agent_id="research-agent",
    gate_url="http://localhost:8000",  # server mode; omit for local mode
    action_type="search",
    wait=True,        # block on pending approval (default)
    timeout=300,      # seconds to wait before failing closed
)

# Use gated_search anywhere a LangChain tool is expected.
```

### OpenAI Agents / plain function tools

```python
from air_gate import GateClient
from air_gate.integrations.openai_agents import gated_tool

gate = GateClient(server_url="http://localhost:8000")

@gated_tool(gate=gate, agent_id="assistant-v1", action_type="email", wait=True)
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    ...  # runs only after a human approves
```

You can also wait manually without a wrapper:

```python
r = gate.check("agent", "email", "send_email", payload={"to": "x@y.com"})
if r["decision"] == "pending_approval":
    outcome = gate.wait_for_decision(r["event_id"], timeout=300)  # blocks
    if outcome == "approved":
        send_the_email()
```

## Server mode + Slack approvals

```bash
uvicorn air_gate.proxy:app --host 0.0.0.0 --port 8000
# or: docker compose up
```

When an action needs approval, Gate posts a message to Slack with **Approve /
Reject** buttons; the click is recorded to the signed chain. Key endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /actions` | Submit an action for policy check + audit |
| `POST /actions/{id}/approve` · `/reject` | Human decision (**requires approver token**) |
| `GET /actions/{id}/status` | Poll a pending action's effective result |
| `GET /verify` | Verify audit chain integrity |
| `GET /report?format=html` | Compliance report (HTML/JSON/Markdown) |
| `POST /slack/interact` | Slack button handler (**Slack-signature verified**) |

### Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `GATE_SIGNING_KEY` | **Required.** HMAC key for signing the audit chain. |
| `GATE_APPROVAL_TOKEN` | Bearer token required to call approve/reject. If unset, those endpoints are unauthenticated (logged as a warning). |
| `SLACK_SIGNING_SECRET` | Slack app signing secret. Required for `/slack/interact`; without it, Slack approvals are rejected. |
| `SLACK_WEBHOOK_URL` / `SLACK_BOT_TOKEN` | Where approval requests are sent. |
| `GATE_STORAGE_PATH` | `.db` → SQLite, `.jsonl` → JSONL file. |
| `GATE_CONFIG_PATH` | Path to `gate_config.yaml`. |

Approve/reject over HTTP with the token:

```bash
curl -X POST http://localhost:8000/actions/$ID/approve \
  -H "Authorization: Bearer $GATE_APPROVAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"authorized_by": "alice@company.com"}'
```

## Audit chain & tamper-evidence

Every action and every human decision is a signed entry, chained to the one
before it (`previous_hash`). The chain is **append-only**: approvals and
rejections are recorded as *new* signed decision entries, never edits, so a
resolution can never rewrite or break earlier history. Editing, deleting, or
reordering any entry fails verification.

```python
gate.verify()   # {"valid": True/False, "events_checked": N, "errors": [...]}
```

Note: HMAC uses a shared secret, so anyone holding `GATE_SIGNING_KEY` can both
sign and verify. It protects against tampering by parties without the key; it is
not a substitute for asymmetric signatures or an external anchor if you need to
prove integrity to a party who must not hold the signing key.

## CLI

```bash
air-gate demo               # self-contained demo (no server needed)
air-gate verify PATH        # re-verify an existing .db or .jsonl chain
air-gate version
```

## PII redaction (optional)

The server can redact PII from payloads before they enter the audit chain and
attach a GDPR Article 30 processing manifest. Enable with `GATE_PII_REDACTION=true`
(default) and choose a method via `GATE_PII_METHOD` (`hash_sha256`, `mask`,
`remove`, `tokenise`). See `air_gate/pii.py` for the multi-vertical detectors
(recruiting, finance/PCI, healthcare/HIPAA, legal) and Article 17 erasure lookup.

## Part of AIR Blackbox

`air-gate` is one component of the **AIR Blackbox** ecosystem for EU AI Act
compliance:

- **[air-gate](https://github.com/airblackbox/air-gate)** — tool gating + audit chain (Articles 12, 14)
- **[air-trust](https://github.com/airblackbox/air-trust)** — trust layers and compliance tooling
- **[air-compliance](https://github.com/airblackbox/air-compliance)** — automated Article 9–15 scanning
- **[air-docs](https://github.com/airblackbox/air-docs)** — model cards, consent logs, audit trails

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

**Questions?** Open an issue on [GitHub](https://github.com/airblackbox/air-gate/issues).
