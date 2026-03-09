# AIR Blackbox Gate — Setup Guide

**Last updated**: March 2026

Gate is the centralized policy server for the AIR Blackbox ecosystem. It enforces organization-wide rules on what AI agents can and cannot do, and maintains a unified audit trail across all agents.

---

## Quick Start (Docker Compose)

The fastest way to run Gate with full observability:

```bash
git clone https://github.com/airblackbox/air-gate.git
cd air-gate
docker compose up -d
```

This starts three services:

| Service | URL | Purpose |
|---------|-----|---------|
| Gate API | http://localhost:8000 | Policy enforcement + audit trail |
| Dashboard | http://localhost:3000 | Real-time audit viewer |
| Jaeger | http://localhost:16686 | Distributed tracing |

Verify it's running:
```bash
curl http://localhost:8000/health
# {"status": "healthy", "version": "0.1.0"}
```

## Quick Start (Without Docker)

If you prefer running Gate directly:

```bash
git clone https://github.com/airblackbox/air-gate.git
cd air-gate
pip install -r requirements.txt
cp .env.example .env

# Start the server
uvicorn gate.proxy:app --host 0.0.0.0 --port 8000 --reload
```

## How Gate Works

Gate sits between your AI agents and the tools they call. When an agent wants to execute a tool:

```
Agent → Trust Layer → Gate → Policy Decision → Tool Execution
                                    ↓
                              Audit Trail
```

1. The trust layer (LangChain or ADK) sends the tool call details to Gate
2. Gate evaluates the action against its policy rules
3. Gate returns one of three decisions:
   - **auto_allow** — tool executes immediately
   - **require_approval** — tool is paused until a human approves
   - **block** — tool is denied, agent gets an error
4. Every decision is logged in Gate's tamper-evident audit chain

## Policy Configuration

Gate's policies are defined in `gate_config.yaml`. Rules are evaluated in order — first match wins.

```yaml
policy:
  default: require_approval  # if no rule matches

  rules:
    # Safe actions: let them through
    - name: allow-read-only
      action_type: db_read
      decision: auto_allow

    - name: allow-search
      action_type: search
      decision: auto_allow

    # Dangerous actions: always block
    - name: block-delete
      action_type: db_delete
      decision: block

    # Everything else: humans decide
    - name: approve-emails
      action_type: email
      decision: require_approval
      max_per_hour: 50
```

### Decision Types

| Decision | What Happens | Use When |
|----------|-------------|----------|
| `auto_allow` | Tool executes immediately | Read-only, search, low-risk operations |
| `require_approval` | Paused until human approves via API or Dashboard | Emails, writes, API calls |
| `block` | Denied permanently | Deletes, admin actions, shell execution |

### Matching Rules

Rules match on `action_type`, which is set by the trust layer based on the tool name and classification. Common action types:

- `search`, `db_read` — read-only operations
- `db_write`, `api_call`, `email` — operations that change state
- `db_delete`, `admin`, `shell` — dangerous operations

## API Endpoints

### Submit an Action
```bash
POST /actions
{
  "agent_id": "my-agent",
  "action_type": "email",
  "tool_name": "send_email",
  "payload": {"to": "user@example.com", "subject": "Hello"},
  "input_context": "User asked to send a follow-up email"
}
```

Response:
```json
{
  "event_id": "evt_abc123",
  "decision": "require_approval",
  "rule_matched": "approve-emails"
}
```

### Approve/Reject a Pending Action
```bash
POST /actions/{event_id}/approve
{
  "authorized_by": "jason@example.com",
  "comment": "Looks good, send it"
}

POST /actions/{event_id}/reject
{
  "authorized_by": "jason@example.com",
  "comment": "Wrong recipient"
}
```

### View Audit Trail
```bash
GET /audit/events              # All events
GET /audit/events?agent_id=X   # Filter by agent
GET /audit/stats               # Summary statistics
GET /audit/verify               # Chain integrity check
```

### Health Check
```bash
GET /health
```

## Connecting Trust Layers to Gate

### LangChain
```python
from air_langchain_trust import AirTrustCallbackHandler, AirTrustConfig

config = AirTrustConfig(gateway_url="http://localhost:8000")
handler = AirTrustCallbackHandler(config=config)
# Use handler with any LangChain LLM or agent
```

### Google ADK
```python
from air_adk_trust import AIRBlackboxPlugin, AIRConfig, AuditConfig

config = AIRConfig(audit=AuditConfig(gateway_url="http://localhost:8000"))
plugin = AIRBlackboxPlugin(config=config)
# Add plugin to any ADK agent
```

Both trust layers:
- Check Gate before every tool execution
- Fall back to local policy if Gate is unreachable
- Log Gate's decision in the local audit chain

## Dashboard

The Dashboard (http://localhost:3000) provides a real-time view of:

- **Stats** — total events, approved, blocked, pending, active agents
- **Chain Status** — HMAC-SHA256 integrity verification
- **Event Log** — every action with timestamp, agent, tool, decision, and approver
- Auto-refreshes every 10 seconds

## Observability with Jaeger

Gate integrates with OpenTelemetry for distributed tracing. When running via Docker Compose, every API call is traced end-to-end in Jaeger (http://localhost:16686).

Traces show:
- Request timing per endpoint
- Policy evaluation duration
- Audit chain write performance
- Error details and stack traces

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATE_HOST` | `0.0.0.0` | Server bind address |
| `GATE_PORT` | `8000` | Server port |
| `GATE_CONFIG` | `gate_config.yaml` | Policy config file path |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | Jaeger/OTEL endpoint |
| `OTEL_SERVICE_NAME` | `air-gate` | Service name in traces |

## FAQ

**Q: Is Gate required?**
No. The trust layers work standalone with local policy enforcement. Gate adds centralized control and a unified audit trail across multiple agents.

**Q: Where is data stored?**
SQLite by default (`/data/gate.db` in Docker, local directory otherwise). No external database required.

**Q: Can I run Gate in production?**
Gate is designed for self-hosting. For production, consider adding authentication (API keys via `GATE_API_KEY` env var), running behind a reverse proxy, and mounting the data volume for persistence.

**Q: What happens if Gate goes down?**
All trust layers gracefully degrade to local policy enforcement. Agents keep running, keep logging locally. When Gate comes back, new events flow to it automatically.

---

*Document version: 1.0 — Applies to air-gate with Docker Compose stack*
