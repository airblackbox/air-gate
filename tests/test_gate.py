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
        """Rules are evaluated in order — first match wins."""
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
