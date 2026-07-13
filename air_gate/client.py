"""
gate/client.py

GateClient - the simplest way to add Gate to any AI agent.

Two modes:
  1. Local mode (no server): Events are signed and stored locally.
     Perfect for single-agent setups or development.

  2. Server mode: Events are sent to a running Gate proxy.
     Use this when you need Slack approvals or multi-agent setups.

Usage (local mode - zero config):

    from gate import GateClient

    gate = GateClient()

    # Check if an action is allowed
    result = gate.check("my-agent", "email", "send_email",
                        payload={"to": "jane@example.com"})

    if result["decision"] == "auto_allowed":
        send_the_email()
    elif result["decision"] == "blocked":
        print("Blocked:", result["reason"])

    # Verify the audit chain anytime
    print(gate.verify())

Usage (server mode - Slack approvals):

    gate = GateClient(server_url="http://localhost:8000")

    result = gate.check("my-agent", "email", "send_email",
                        payload={"to": "jane@example.com"})
    # If pending_approval, the agent can poll or use callback_url
"""

import json
import os
from typing import Optional

from .events import EventStore, GateEvent
from .policy import PolicyEngine, PolicyRule


class GateClient:
    """
    Drop-in Gate client for any Python AI agent.

    Parameters
    ----------
    server_url : str, optional
        If provided, all actions are sent to a remote Gate proxy.
        If None, Gate runs locally (no server needed).
    signing_key : str, optional
        HMAC signing key. Defaults to env var GATE_SIGNING_KEY.
    storage_path : str, optional
        Where to store events locally. Defaults to "gate_events.db".
    policy_config : dict, optional
        Policy rules for local mode. If None, uses default (require_approval).
    config_path : str, optional
        Path to YAML config file for local mode.
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        signing_key: Optional[str] = None,
        storage_path: str = "gate_events.db",
        policy_config: Optional[dict] = None,
        config_path: Optional[str] = None,
    ):
        self.server_url = server_url

        if server_url:
            # Server mode - we just need httpx
            self._mode = "server"
        else:
            # Local mode - initialize everything in-process
            self._mode = "local"
            key = signing_key or os.getenv("GATE_SIGNING_KEY", "change-me-in-production")
            self._store = EventStore(signing_key=key, storage_path=storage_path)
            self._policy = self._load_policy(policy_config, config_path)

    def _load_policy(self, config: Optional[dict], config_path: Optional[str]) -> PolicyEngine:
        """Load policy from config dict, YAML file, or defaults."""
        if config:
            return PolicyEngine.from_config(config)
        if config_path:
            import yaml
            with open(config_path) as f:
                data = yaml.safe_load(f)
                return PolicyEngine.from_config(data.get("policy", {}))
        # Try default config file
        default_path = os.getenv("GATE_CONFIG_PATH", "gate_config.yaml")
        if os.path.exists(default_path):
            import yaml
            with open(default_path) as f:
                data = yaml.safe_load(f)
                return PolicyEngine.from_config(data.get("policy", {}))
        return PolicyEngine()

    def check(
        self,
        agent_id: str,
        action_type: str,
        tool_name: str,
        payload: Optional[dict] = None,
        input_context: str = "",
        callback_url: str = "",
    ) -> dict:
        """
        Submit an action for policy check + audit recording.

        Returns a dict with:
            decision: "auto_allowed" | "pending_approval" | "blocked"
            event_id: unique ID for this event
            reason: why this decision was made
            rule_name: which policy rule matched
        """
        payload = payload or {}

        if self._mode == "server":
            return self._check_remote(agent_id, action_type, tool_name, payload, input_context, callback_url)
        else:
            return self._check_local(agent_id, action_type, tool_name, payload, input_context)

    def _check_local(self, agent_id, action_type, tool_name, payload, input_context) -> dict:
        """Evaluate locally - no server needed."""
        decision = self._policy.evaluate(
            agent_id=agent_id,
            action_type=action_type,
            tool_name=tool_name,
            payload=payload,
        )

        event = GateEvent(
            agent_id=agent_id,
            action_type=action_type,
            tool_name=tool_name,
            payload=payload,
            input_context=input_context,
        )

        if decision["decision"] == "auto_allow":
            event.result = "auto_allowed"
            event.authorized_by = "auto-policy"
        elif decision["decision"] == "block":
            event.result = "blocked"
            event.authorized_by = "auto-policy"
            event.result_detail = decision["reason"]
        else:
            event.result = "pending"

        self._store.record(event)

        # Normalize to the same vocabulary the server returns so callers (and
        # the framework wrappers) can treat both modes identically. Internally
        # the event's result stays "pending"; the response says "pending_approval".
        decision_out = "pending_approval" if event.result == "pending" else event.result

        return {
            "decision": decision_out,
            "event_id": event.event_id,
            "rule_name": decision["rule_name"],
            "reason": decision["reason"],
        }

    def _check_remote(self, agent_id, action_type, tool_name, payload, input_context, callback_url) -> dict:
        """Send to Gate proxy server."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required for server mode: pip install air-gate[server]")

        response = httpx.post(
            f"{self.server_url}/actions",
            json={
                "agent_id": agent_id,
                "action_type": action_type,
                "tool_name": tool_name,
                "payload": payload,
                "input_context": input_context,
                "callback_url": callback_url,
            },
        )
        response.raise_for_status()
        return response.json()

    def approve(self, event_id: str, authorized_by: str, comment: str = "") -> dict:
        """Approve a pending action (local mode only - server mode uses Slack)."""
        if self._mode == "server":
            import httpx
            r = httpx.post(f"{self.server_url}/actions/{event_id}/approve",
                           json={"authorized_by": authorized_by, "comment": comment})
            r.raise_for_status()
            return r.json()
        else:
            event = self._store.update_result(event_id, "approved", authorized_by, comment)
            return {"status": "approved", "event_id": event_id} if event else {"error": "not found"}

    def reject(self, event_id: str, authorized_by: str, comment: str = "") -> dict:
        """Reject a pending action."""
        if self._mode == "server":
            import httpx
            r = httpx.post(f"{self.server_url}/actions/{event_id}/reject",
                           json={"authorized_by": authorized_by, "comment": comment})
            r.raise_for_status()
            return r.json()
        else:
            event = self._store.update_result(event_id, "rejected", authorized_by, comment)
            return {"status": "rejected", "event_id": event_id} if event else {"error": "not found"}

    # Terminal outcomes: once an action reaches one of these it will not change.
    _TERMINAL = frozenset({"approved", "rejected", "blocked", "auto_allowed"})

    def status(self, event_id: str) -> Optional[str]:
        """
        Current effective result of an action ("pending" until resolved), or
        None if the event is unknown. Reflects the latest approval/rejection.
        """
        if self._mode == "server":
            import httpx
            r = httpx.get(f"{self.server_url}/actions/{event_id}/status")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json().get("result")
        return self._store.current_result(event_id)

    def wait_for_decision(
        self,
        event_id: str,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> str:
        """
        Block until a pending action is resolved, then return its final result.

        Polls until the action reaches a terminal state (approved, rejected,
        blocked, auto_allowed) or ``timeout`` seconds elapse. On timeout returns
        "pending" so callers can fail closed (do not execute the tool).
        """
        import time as _time
        deadline = _time.monotonic() + timeout
        while True:
            result = self.status(event_id)
            if result in self._TERMINAL:
                return result
            if _time.monotonic() >= deadline:
                return result or "pending"
            _time.sleep(min(poll_interval, max(0.0, deadline - _time.monotonic())))

    async def await_decision(
        self,
        event_id: str,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> str:
        """Async variant of :meth:`wait_for_decision` (does not block the loop)."""
        import asyncio
        import time as _time
        deadline = _time.monotonic() + timeout
        while True:
            if self._mode == "server":
                import httpx
                async with httpx.AsyncClient() as client:
                    r = await client.get(f"{self.server_url}/actions/{event_id}/status")
                    result = None if r.status_code == 404 else r.json().get("result")
            else:
                result = self._store.current_result(event_id)
            if result in self._TERMINAL:
                return result
            if _time.monotonic() >= deadline:
                return result or "pending"
            await asyncio.sleep(min(poll_interval, max(0.0, deadline - _time.monotonic())))

    def verify(self) -> dict:
        """Verify the audit chain integrity."""
        if self._mode == "server":
            import httpx
            r = httpx.get(f"{self.server_url}/verify")
            r.raise_for_status()
            return r.json()
        return self._store.verify_chain()

    def stats(self) -> dict:
        """Get event store statistics."""
        if self._mode == "server":
            import httpx
            r = httpx.get(f"{self.server_url}/stats")
            r.raise_for_status()
            return r.json()
        return self._store.get_stats()

    def events(self, **filters) -> list:
        """Query events with optional filters."""
        if self._mode == "server":
            import httpx
            r = httpx.get(f"{self.server_url}/events", params=filters)
            r.raise_for_status()
            return r.json().get("events", [])
        return [e.model_dump() for e in self._store.get_events(**filters)]
