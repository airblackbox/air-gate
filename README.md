# AIR Blackbox Gate

**The AI Action Firewall** — Every agent action recorded, attributable, and provable.

Gate sits between your AI agents and the real world. Every action flows through Gate, gets checked against policy, and produces a tamper-evident signed record. Think of it like a firewall — but for AI agent actions instead of network traffic.

## What It Does

```
Agent wants to send email
       ↓
   Gate intercepts
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
```

- **Intercept** — Every agent action hits Gate before reaching the real world
- **Policy** — Rules decide: auto-allow, require human approval, or block
- **Approve** — Humans approve/reject actions in Slack (no dashboard needed)
- **Sign** — Every action produces a cryptographically chained event
- **Report** — Generate compliance PDFs for legal/audit teams

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Start Gate
uvicorn gate.proxy:app --reload

# Run the demo
python3 demo.py
```

The demo simulates a recruiting AI agent sending outreach emails through Gate. You'll see actions get auto-allowed, held for approval, and blocked — with every action signed and chained.

## Configuration

Copy `.env.example` to `.env` and set your signing key:

```bash
cp .env.example .env
# Edit .env with your GATE_SIGNING_KEY and optional SLACK_WEBHOOK_URL
```

Edit `gate_config.yaml` to define your policy rules:

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
| `/actions/{id}/approve` | POST | Approve a pending action |
| `/actions/{id}/reject` | POST | Reject a pending action |
| `/events` | GET | Query the event store |
| `/events/{id}` | GET | Get a specific event |
| `/verify` | GET | Verify audit chain integrity |
| `/stats` | GET | Summary statistics |
| `/report` | GET | Generate compliance report |
| `/health` | GET | Health check |

## Slack Integration

Gate sends approval requests to Slack with Approve/Reject buttons:

1. Create a Slack app at https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Set `SLACK_WEBHOOK_URL` in your `.env`
4. Point the Slack interactivity URL to `https://your-gate-url/slack/interact`

## Compliance Reports

Generate reports at `/report`:

- `/report` — HTML (print to PDF from browser)
- `/report?format=json` — Raw data
- `/report?format=markdown` — Markdown
- `/report?start=2026-01-01&end=2026-02-01` — Date range

Reports include: action counts, approval rates, human oversight summary, anomaly detection, and cryptographic chain verification.

## Architecture

```
gate/
├── proxy.py          — FastAPI server (the main entry point)
├── events.py         — HMAC-SHA256 signed event store
├── policy.py         — Policy engine (auto-allow, require-approval, block)
├── slack_bot.py      — Slack approval bot
├── report.py         — Compliance report data + markdown rendering
└── report_endpoint.py — /report API endpoint with HTML output
```

## Part of AIR Blackbox

- **AIR Blackbox Scan** tells you if your AI system is built right (build-time compliance)
- **AIR Blackbox Gate** makes sure it behaves right (runtime control)

Together: full AI governance lifecycle.

[airblackbox.ai](https://airblackbox.ai)
