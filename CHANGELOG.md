# Changelog

All notable changes to `air-gate` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-13

This release fixes issues affecting the core guarantee of air-gate: that the
audit chain is trustworthy and that approvals are real. Existing HMAC audit
chains continue to verify unchanged.

### ⚠️ Action required (server deployments)

Two new environment variables gate the approval paths. Both fail safe — when
unset, approvals are refused rather than silently allowed.

- `GATE_APPROVAL_TOKEN` — required to call `/actions/{id}/approve` and
  `/reject`. Send it as `Authorization: Bearer <token>`.
- `SLACK_SIGNING_SECRET` — required for Slack button approvals. Without it,
  `/slack/interact` refuses all requests.

### Fixed

- **Audit chain no longer breaks on approval.** Approvals/rejections previously
  rewrote a signed record in place, silently corrupting the chain once any
  later event had been recorded (`verify()` returned `false` in normal use).
  Decisions are now appended as new signed events; original records are
  immutable and the chain stays strictly append-only.
- **Approval endpoints are authenticated.** `/approve` and `/reject` now
  require a bearer token; previously anyone who could reach the server could
  approve any action as any identity.
- **Slack approvals verify Slack's request signature** (with replay
  protection), closing a hole where a forged POST could approve any action.
- **Evidence fields are now signed.** `input_context` (the reasoning behind an
  action) and `result_detail` (the rejection reason) are covered by the
  signature — editing them now breaks verification.
- **Framework integrations block on approval.** The LangChain and OpenAI tool
  wrappers previously returned a "pending" string and let the agent continue;
  they now block until a decision is reached.
- **README quickstart matches the shipped API.** The documented `GateKeeper` /
  `air_trust.AuditChain` API did not exist; rewritten against `GateClient`.
- **Docker image builds again.** The `gate/` → `air_gate/` rename had missed
  the Dockerfile (`COPY gate/`, `uvicorn gate.proxy:app`).
- **Version strings unified.** `proxy.py` reported `0.1.0` and the `version`
  command printed `air-blackbox`; both corrected.

### Added

- **Ed25519 asymmetric signing (optional).** Sign the chain with a private key
  that auditors verify using only the public key — so a third party can prove
  the chain was not tampered with **without holding a key that could forge it.**
  HMAC-SHA256 remains the zero-dependency default. Install with
  `pip install air-gate[crypto]` and configure via `air_gate.signing`.
- **Durable pending state.** Pending approvals and rate-limit counters are no
  longer memory-only, so a restart or a second worker process no longer loses
  them.

## [0.2.1] - 2026-04-06

- Renamed the module from `gate` to `air_gate` so `import air_gate` matches the
  `air-gate` package name.

## [0.2.0]

- `GateClient` SDK, PII redaction, framework integrations, decision callbacks.

## [0.1.0]

- Initial release: policy engine, HMAC-SHA256 audit chain, Slack approvals.

[0.3.0]: https://github.com/airblackbox/air-gate/releases/tag/v0.3.0
[0.2.1]: https://github.com/airblackbox/air-gate/releases/tag/v0.2.1
[0.2.0]: https://github.com/airblackbox/air-gate/releases/tag/v0.2.0
[0.1.0]: https://github.com/airblackbox/air-gate/releases/tag/v0.1.0
