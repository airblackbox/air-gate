"""
Compliance Report Generator — produces PDF reports from Gate events.

This is the monetization lever. Companies pay serious money for
defensible documentation that proves AI actions were governed.

The report includes:
  - Executive summary
  - Action counts (approved, blocked, auto-allowed)
  - Human oversight summary (who approved what)
  - Anomaly flags (unusual volume, off-hours, policy violations)
  - Audit chain integrity verification (cryptographic proof)
"""

import io
import json
from datetime import datetime, timezone
from typing import Optional

from .events import EventStore, GateEvent


def generate_report_data(
    event_store: EventStore,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    title: str = "AI Activity Compliance Report",
) -> dict:
    """
    Generate structured report data from the event store.

    This returns a dict that can be rendered as PDF, HTML, or JSON.
    Keeping data and presentation separate.
    """
    # Filter events by date range
    events = event_store.get_events(since=start_date, until=end_date)

    if not events:
        return {
            "title": title,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {"start": start_date or "all time", "end": end_date or "now"},
            "summary": {"total_actions": 0},
            "sections": [],
        }

    # ── Summary Stats ────────────────────────────────────────────────
    total = len(events)
    by_result = {}
    by_action_type = {}
    by_agent = {}
    by_authorizer = {}
    hourly_distribution = [0] * 24

    for e in events:
        by_result[e.result] = by_result.get(e.result, 0) + 1
        by_action_type[e.action_type] = by_action_type.get(e.action_type, 0) + 1

        if e.agent_id not in by_agent:
            by_agent[e.agent_id] = {"total": 0, "approved": 0, "blocked": 0, "auto_allowed": 0}
        by_agent[e.agent_id]["total"] += 1
        if e.result in by_agent[e.agent_id]:
            by_agent[e.agent_id][e.result] += 1

        if e.authorized_by and e.authorized_by not in ("pending", "auto-policy"):
            by_authorizer[e.authorized_by] = by_authorizer.get(e.authorized_by, 0) + 1

        # Hour distribution for anomaly detection
        try:
            hour = datetime.fromisoformat(e.timestamp).hour
            hourly_distribution[hour] += 1
        except (ValueError, IndexError):
            pass

    # ── Anomaly Detection ────────────────────────────────────────────
    anomalies = []

    # Off-hours activity (before 6am or after 10pm)
    off_hours = sum(hourly_distribution[0:6]) + sum(hourly_distribution[22:24])
    if off_hours > 0:
        anomalies.append({
            "type": "off_hours_activity",
            "severity": "medium",
            "detail": f"{off_hours} actions occurred outside business hours (10pm-6am)",
            "count": off_hours,
        })

    # High block rate
    blocked = by_result.get("blocked", 0)
    if total > 0 and (blocked / total) > 0.2:
        anomalies.append({
            "type": "high_block_rate",
            "severity": "high",
            "detail": f"{blocked}/{total} actions were blocked ({blocked/total*100:.0f}%)",
            "count": blocked,
        })

    # Rejection rate
    rejected = by_result.get("rejected", 0)
    if total > 0 and (rejected / total) > 0.15:
        anomalies.append({
            "type": "high_rejection_rate",
            "severity": "medium",
            "detail": f"{rejected}/{total} actions were rejected by humans ({rejected/total*100:.0f}%)",
            "count": rejected,
        })

    # Volume spike (more than 100 actions per hour in any hour)
    max_hourly = max(hourly_distribution)
    if max_hourly > 100:
        peak_hour = hourly_distribution.index(max_hourly)
        anomalies.append({
            "type": "volume_spike",
            "severity": "medium",
            "detail": f"Peak of {max_hourly} actions at {peak_hour:02d}:00 UTC",
            "count": max_hourly,
        })

    # ── Chain Verification ───────────────────────────────────────────
    chain_status = event_store.verify_chain()

    # ── Build Report ─────────────────────────────────────────────────
    report = {
        "title": title,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": {
            "start": start_date or events[0].timestamp,
            "end": end_date or events[-1].timestamp,
        },
        "summary": {
            "total_actions": total,
            "by_result": by_result,
            "by_action_type": by_action_type,
            "unique_agents": len(by_agent),
            "human_approvals": sum(by_authorizer.values()),
            "approval_rate": (
                by_result.get("approved", 0) + by_result.get("auto_allowed", 0)
            ) / total * 100 if total > 0 else 0,
        },
        "human_oversight": {
            "authorizers": by_authorizer,
            "total_human_decisions": by_result.get("approved", 0) + by_result.get("rejected", 0),
            "auto_allowed": by_result.get("auto_allowed", 0),
        },
        "agent_breakdown": by_agent,
        "anomalies": anomalies,
        "audit_chain": {
            "valid": chain_status["valid"],
            "events_verified": chain_status["events_checked"],
            "errors": chain_status["errors"],
            "integrity_statement": (
                "All events have been cryptographically verified. The audit chain is intact "
                "with no evidence of tampering, deletion, or reordering."
                if chain_status["valid"]
                else "WARNING: Audit chain integrity check FAILED. " + "; ".join(chain_status["errors"])
            ),
        },
        "hourly_distribution": hourly_distribution,
    }

    return report


def render_report_markdown(report: dict) -> str:
    """Render report data as Markdown (for PDF conversion)."""
    md = []
    md.append(f"# {report['title']}")
    md.append(f"\n**Generated:** {report['generated_at']}")
    md.append(f"**Period:** {report['period']['start']} to {report['period']['end']}")
    md.append(f"\n---\n")

    # Executive Summary
    s = report["summary"]
    md.append("## Executive Summary\n")
    md.append(f"During the reporting period, **{s['total_actions']}** AI agent actions were "
              f"processed through AIR Blackbox Gate across **{s['unique_agents']}** agent(s).\n")

    if s["total_actions"] > 0:
        md.append(f"- **Approved:** {s['by_result'].get('approved', 0)}")
        md.append(f"- **Auto-Allowed:** {s['by_result'].get('auto_allowed', 0)}")
        md.append(f"- **Rejected:** {s['by_result'].get('rejected', 0)}")
        md.append(f"- **Blocked:** {s['by_result'].get('blocked', 0)}")
        md.append(f"- **Overall Approval Rate:** {s['approval_rate']:.1f}%\n")

    # Action Types
    md.append("## Actions by Type\n")
    for action_type, count in s.get("by_action_type", {}).items():
        md.append(f"- **{action_type}:** {count}")
    md.append("")

    # Human Oversight
    ho = report["human_oversight"]
    md.append("## Human Oversight Summary\n")
    md.append(f"**{ho['total_human_decisions']}** actions required human decision. "
              f"**{ho['auto_allowed']}** were auto-allowed by policy.\n")

    if ho["authorizers"]:
        md.append("### Approvals by Person\n")
        for person, count in ho["authorizers"].items():
            md.append(f"- **{person}:** {count} approvals")
    md.append("")

    # Agent Breakdown
    md.append("## Agent Activity Breakdown\n")
    for agent_id, data in report.get("agent_breakdown", {}).items():
        md.append(f"### {agent_id}\n")
        md.append(f"- Total actions: {data['total']}")
        md.append(f"- Approved: {data.get('approved', 0)}")
        md.append(f"- Blocked: {data.get('blocked', 0)}")
        md.append(f"- Auto-allowed: {data.get('auto_allowed', 0)}")
    md.append("")

    # Anomalies
    md.append("## Anomaly Detection\n")
    if report["anomalies"]:
        for a in report["anomalies"]:
            severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(a["severity"], "⚪")
            md.append(f"- {severity_icon} **{a['type']}** ({a['severity']}): {a['detail']}")
    else:
        md.append("No anomalies detected during the reporting period.")
    md.append("")

    # Audit Chain Integrity
    ac = report["audit_chain"]
    md.append("## Audit Chain Integrity\n")
    md.append(f"**Events Verified:** {ac['events_verified']}")
    md.append(f"**Chain Status:** {'✅ INTACT' if ac['valid'] else '❌ COMPROMISED'}\n")
    md.append(f"> {ac['integrity_statement']}")
    md.append("")

    # Footer
    md.append("---\n")
    md.append("*This report was generated by AIR Blackbox Gate — The AI Action Firewall.*")
    md.append("*For more information, visit [airblackbox.ai](https://airblackbox.ai)*")

    return "\n".join(md)
