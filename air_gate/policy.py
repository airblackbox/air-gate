"""
Policy engine — decides what happens when an agent wants to take an action.

Three possible outcomes:
  - auto_allow: Action proceeds immediately (low-risk, pre-approved)
  - require_approval: Action held for human review via Slack
  - block: Action denied outright (forbidden actions)

Policies are simple rules defined in YAML config. No ML, no complexity.
"""

from typing import Optional

from pydantic import BaseModel, Field


class PolicyRule(BaseModel):
    """A single policy rule."""

    name: str
    description: str = ""

    # Match conditions (all must match for rule to apply)
    agent_id: Optional[str] = None  # specific agent, or None = any
    action_type: Optional[str] = None  # email, api_call, etc., or None = any
    tool_name: Optional[str] = None  # specific tool, or None = any

    # What to do when matched
    decision: str = "require_approval"  # auto_allow, require_approval, block

    # Optional limits
    max_per_hour: Optional[int] = None  # rate limit
    max_payload_size: Optional[int] = None  # payload size limit in bytes


class PolicyEngine:
    """
    Evaluates agent actions against policy rules.

    Rules are evaluated in order — first match wins.
    If no rule matches, the default policy applies (require_approval).
    """

    def __init__(self, rules: list[PolicyRule] = None, default: str = "require_approval"):
        self.rules = rules or []
        self.default_decision = default
        self._action_counts: dict[str, list[float]] = {}  # in-memory fallback
        # Optional durable counter: (agent_id, action_type, tool_name, since_iso)
        # -> int. When set (wired to the EventStore), rate limits survive
        # restarts and are consistent across workers. See set_action_counter().
        self._recent_action_counter = None

    def set_action_counter(self, counter):
        """Provide a durable recent-action counter (e.g. EventStore-backed)."""
        self._recent_action_counter = counter

    def evaluate(self, agent_id: str, action_type: str, tool_name: str, payload: dict = None) -> dict:
        """
        Evaluate an action against policy rules.

        Returns:
            {
                "decision": "auto_allow" | "require_approval" | "block",
                "rule_name": "which rule matched" | "default",
                "reason": "human-readable explanation"
            }
        """
        import time

        for rule in self.rules:
            if self._matches(rule, agent_id, action_type, tool_name):
                # Check rate limit if configured
                if rule.max_per_hour is not None:
                    if self._recent_action_counter is not None:
                        # Durable path: count prior matching actions from the
                        # store (survives restart, shared across workers). The
                        # current attempt is recorded by the caller afterwards.
                        from datetime import datetime, timedelta, timezone
                        since_iso = (
                            datetime.now(timezone.utc) - timedelta(hours=1)
                        ).isoformat()
                        count = self._recent_action_counter(
                            agent_id, action_type, tool_name, since_iso
                        )
                        if count >= rule.max_per_hour:
                            return {
                                "decision": "block",
                                "rule_name": rule.name,
                                "reason": f"Rate limit exceeded: {rule.max_per_hour}/hour",
                            }
                    else:
                        # In-memory fallback (single process only).
                        key = f"{agent_id}:{action_type}:{tool_name}"
                        now = time.time()
                        hour_ago = now - 3600

                        if key not in self._action_counts:
                            self._action_counts[key] = []

                        self._action_counts[key] = [
                            t for t in self._action_counts[key] if t > hour_ago
                        ]

                        if len(self._action_counts[key]) >= rule.max_per_hour:
                            return {
                                "decision": "block",
                                "rule_name": rule.name,
                                "reason": f"Rate limit exceeded: {rule.max_per_hour}/hour",
                            }

                        self._action_counts[key].append(now)

                # Check payload size if configured
                if rule.max_payload_size is not None and payload:
                    import json
                    payload_size = len(json.dumps(payload).encode("utf-8"))
                    if payload_size > rule.max_payload_size:
                        return {
                            "decision": "block",
                            "rule_name": rule.name,
                            "reason": f"Payload too large: {payload_size} bytes (max {rule.max_payload_size})",
                        }

                return {
                    "decision": rule.decision,
                    "rule_name": rule.name,
                    "reason": rule.description or f"Matched rule: {rule.name}",
                }

        # No rule matched — use default
        return {
            "decision": self.default_decision,
            "rule_name": "default",
            "reason": "No specific policy matched — using default policy",
        }

    def _matches(self, rule: PolicyRule, agent_id: str, action_type: str, tool_name: str) -> bool:
        """Check if a rule matches the given action."""
        if rule.agent_id and rule.agent_id != agent_id:
            return False
        if rule.action_type and rule.action_type != action_type:
            return False
        if rule.tool_name and rule.tool_name != tool_name:
            return False
        return True

    @classmethod
    def from_config(cls, config: dict) -> "PolicyEngine":
        """
        Create a PolicyEngine from a config dict (loaded from YAML).

        Example config:
        {
            "default": "require_approval",
            "rules": [
                {
                    "name": "allow-read-only",
                    "action_type": "db_read",
                    "decision": "auto_allow",
                    "description": "Read-only database queries are safe"
                },
                {
                    "name": "block-delete",
                    "action_type": "db_delete",
                    "decision": "block",
                    "description": "Never allow AI to delete data"
                },
                {
                    "name": "approve-emails",
                    "action_type": "email",
                    "decision": "require_approval",
                    "max_per_hour": 50,
                    "description": "All emails need human approval"
                }
            ]
        }
        """
        rules = [PolicyRule(**r) for r in config.get("rules", [])]
        default = config.get("default", "require_approval")
        return cls(rules=rules, default=default)
