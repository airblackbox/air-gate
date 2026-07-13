"""Tests for AIR Blackbox Gate core components."""

import json
import pytest
from air_gate.events import EventStore, GateEvent
from air_gate.policy import PolicyEngine, PolicyRule


# ── Event Store Tests ─────────────────────────────────────────────────

class TestEventStore:

    def setup_method(self):
        """Fresh event store for each test."""
        self.store = EventStore(signing_key="test-secret", storage_path="/tmp/test_events.jsonl")
        self.store.events = []  # clear

    def test_record_event(self):
        event = GateEvent(
            agent_id="test-agent",
            action_type="email",
            tool_name="send_email",
            payload={"to": "test@example.com"},
        )
        recorded = self.store.record(event)
        assert recorded.hmac_signature != ""
        assert recorded.previous_hash == "GENESIS"
        assert len(self.store.events) == 1

    def test_chain_integrity(self):
        """Events should chain together via previous_hash."""
        for i in range(5):
            event = GateEvent(
                agent_id="agent",
                action_type="email",
                tool_name="send",
                payload={"num": i},
            )
            self.store.record(event)

        # Chain should be valid
        result = self.store.verify_chain()
        assert result["valid"] is True
        assert result["events_checked"] == 5

        # Second event should link to first
        assert self.store.events[1].previous_hash == self.store.events[0].hmac_signature

    def test_tamper_detection(self):
        """Modifying an event should break the chain."""
        for i in range(3):
            event = GateEvent(
                agent_id="agent",
                action_type="email",
                tool_name="send",
                payload={"num": i},
            )
            self.store.record(event)

        # Tamper with the middle event
        self.store.events[1].payload = {"num": 999}

        result = self.store.verify_chain()
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_filter_events(self):
        """Should filter events by agent, type, result."""
        self.store.record(GateEvent(agent_id="a1", action_type="email", tool_name="send", result="approved"))
        self.store.record(GateEvent(agent_id="a2", action_type="search", tool_name="find", result="auto_allowed"))
        self.store.record(GateEvent(agent_id="a1", action_type="email", tool_name="send", result="blocked"))

        assert len(self.store.get_events(agent_id="a1")) == 2
        assert len(self.store.get_events(action_type="search")) == 1
        assert len(self.store.get_events(result="blocked")) == 1

    def test_stats(self):
        self.store.record(GateEvent(agent_id="a1", action_type="email", tool_name="send", result="approved"))
        self.store.record(GateEvent(agent_id="a1", action_type="email", tool_name="send", result="blocked"))
        self.store.record(GateEvent(agent_id="a2", action_type="search", tool_name="find", result="auto_allowed"))

        stats = self.store.get_stats()
        assert stats["total"] == 3
        assert stats["unique_agents"] == 2
        assert stats["by_result"]["approved"] == 1

    def test_resolve_keeps_chain_valid(self):
        """Resolving a non-last event must not break the chain (regression)."""
        pending = GateEvent(agent_id="a", action_type="email", tool_name="send", result="pending")
        self.store.record(pending)
        # A later action arrives before the human decides.
        self.store.record(GateEvent(agent_id="a", action_type="search", tool_name="find", result="auto_allowed"))

        decision = self.store.resolve(pending.event_id, "approved", "human@co", "ok")

        assert decision is not None
        assert decision.entry_type == "decision"
        assert decision.related_event_id == pending.event_id
        # Original action event is never mutated.
        assert pending.result == "pending"
        # Chain stays intact and the effective result reflects the approval.
        assert self.store.verify_chain()["valid"] is True
        assert self.store.current_result(pending.event_id) == "approved"

    def test_resolve_unknown_event(self):
        assert self.store.resolve("does-not-exist", "approved", "human@co") is None

    def test_stats_folds_decisions(self):
        """A resolved action counts once, under its effective result."""
        pending = GateEvent(agent_id="a1", action_type="email", tool_name="send", result="pending")
        self.store.record(pending)
        self.store.resolve(pending.event_id, "approved", "human@co")

        stats = self.store.get_stats()
        assert stats["total"] == 1  # decision event is not a separate action
        assert stats["by_result"] == {"approved": 1}
        assert stats["chain_valid"] is True

    def test_input_context_is_signed(self):
        """input_context and result_detail are covered by the HMAC (regression)."""
        e = GateEvent(agent_id="a", action_type="email", tool_name="send",
                      input_context="92% fit", result_detail="reason")
        self.store.record(e)

        self.store.events[0].input_context = "TAMPERED"
        assert self.store.verify_chain()["valid"] is False


# ── Policy Engine Tests ───────────────────────────────────────────────

class TestPolicyEngine:

    def test_default_policy(self):
        """No rules = everything requires approval."""
        engine = PolicyEngine()
        result = engine.evaluate("agent", "email", "send")
        assert result["decision"] == "require_approval"
        assert result["rule_name"] == "default"

    def test_auto_allow(self):
        engine = PolicyEngine(rules=[
            PolicyRule(name="allow-search", action_type="search", decision="auto_allow"),
        ])
        result = engine.evaluate("agent", "search", "find")
        assert result["decision"] == "auto_allow"

    def test_block(self):
        engine = PolicyEngine(rules=[
            PolicyRule(name="block-delete", action_type="db_delete", decision="block"),
        ])
        result = engine.evaluate("agent", "db_delete", "drop_table")
        assert result["decision"] == "block"

    def test_first_match_wins(self):
        """Rules are evaluated in order - first match wins."""
        engine = PolicyEngine(rules=[
            PolicyRule(name="block-agent-x", agent_id="evil-agent", decision="block"),
            PolicyRule(name="allow-email", action_type="email", decision="auto_allow"),
        ])
        # evil-agent trying to email → blocked (first rule matches)
        result = engine.evaluate("evil-agent", "email", "send")
        assert result["decision"] == "block"

        # good-agent emailing → auto-allowed (second rule matches)
        result = engine.evaluate("good-agent", "email", "send")
        assert result["decision"] == "auto_allow"

    def test_from_config(self):
        config = {
            "default": "block",
            "rules": [
                {"name": "allow-read", "action_type": "db_read", "decision": "auto_allow"},
            ],
        }
        engine = PolicyEngine.from_config(config)
        assert engine.evaluate("a", "db_read", "select")["decision"] == "auto_allow"
        assert engine.evaluate("a", "email", "send")["decision"] == "block"

    def test_rate_limit(self):
        engine = PolicyEngine(rules=[
            PolicyRule(name="limit-email", action_type="email", decision="auto_allow", max_per_hour=2),
        ])
        # First two should pass
        assert engine.evaluate("a", "email", "send")["decision"] == "auto_allow"
        assert engine.evaluate("a", "email", "send")["decision"] == "auto_allow"
        # Third should be blocked
        assert engine.evaluate("a", "email", "send")["decision"] == "block"


# ── Client / HITL wait Tests ──────────────────────────────────────────

class TestClientWait:

    def _client(self, tmp_path):
        from gate.client import GateClient
        return GateClient(
            storage_path=str(tmp_path / "c.db"),
            policy_config={
                "default": "require_approval",
                "rules": [
                    {"name": "emails", "action_type": "email", "decision": "require_approval"},
                    {"name": "search", "action_type": "search", "decision": "auto_allow"},
                ],
            },
        )

    def test_local_pending_uses_server_vocabulary(self, tmp_path):
        """Local mode returns 'pending_approval' (not 'pending') like the server."""
        gate = self._client(tmp_path)
        r = gate.check("a", "email", "send", payload={"to": "x@y.com"})
        assert r["decision"] == "pending_approval"

    def test_wait_returns_approved_once_resolved(self, tmp_path):
        gate = self._client(tmp_path)
        r = gate.check("a", "email", "send", payload={"to": "x@y.com"})
        assert gate.status(r["event_id"]) == "pending"
        gate.approve(r["event_id"], "boss@co")
        assert gate.wait_for_decision(r["event_id"], timeout=2) == "approved"

    def test_wait_times_out_to_pending(self, tmp_path):
        gate = self._client(tmp_path)
        r = gate.check("a", "email", "send", payload={"to": "x@y.com"})
        # Nobody approves -> must fail closed (return non-approved) quickly.
        assert gate.wait_for_decision(r["event_id"], timeout=0.3, poll_interval=0.05) == "pending"

    def test_gated_tool_fails_closed_without_approval(self, tmp_path):
        from gate.integrations.langchain import GatedTool

        class FakeTool:
            name = "send"
            description = ""
            def __init__(self): self.ran = False
            def run(self, *a, **k):
                self.ran = True
                return "SENT"

        gate = self._client(tmp_path)
        tool = FakeTool()
        gt = GatedTool(tool=tool, agent_id="a", gate_client=gate,
                       action_type="email", timeout=0.3)
        out = gt.run("hi")
        assert tool.ran is False
        assert out == gt.block_message


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
