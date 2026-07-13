"""
gate/integrations/langchain.py

Drop-in LangChain tool wrapper that routes every tool call through Gate.

Usage:

    from langchain.tools import DuckDuckGoSearchRun
    from air_gate.integrations.langchain import GatedTool

    search = DuckDuckGoSearchRun()
    gated_search = GatedTool(
        tool=search,
        agent_id="research-agent",
        gate_url="http://localhost:8000",  # or use local mode
    )

    # Use gated_search in your agent - it works like any LangChain tool
    # but every invocation goes through Gate for policy + audit
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("gate.langchain")


class GatedTool:
    """
    Wraps any LangChain BaseTool so every call flows through Gate.

    Works with both server mode (Gate proxy) and local mode (GateClient).

    Parameters
    ----------
    tool : BaseTool
        The LangChain tool to wrap.
    agent_id : str
        Identifier for the agent using this tool.
    gate_url : str, optional
        Gate proxy URL. If None, uses local GateClient.
    gate_client : GateClient, optional
        Pre-configured GateClient instance. Takes priority over gate_url.
    action_type : str
        How to classify this tool's actions. Default: "tool_call".
    block_message : str
        What to return when Gate blocks the action.
    """

    def __init__(
        self,
        tool: Any,
        agent_id: str,
        gate_url: Optional[str] = None,
        gate_client: Optional[Any] = None,
        action_type: str = "tool_call",
        block_message: str = "[BLOCKED BY POLICY] This action was blocked by AIR Gate.",
        wait: bool = True,
        timeout: float = 300.0,
    ):
        self.tool = tool
        self.agent_id = agent_id
        self.action_type = action_type
        self.block_message = block_message
        # When wait=True (default) a pending action BLOCKS until a human
        # approves or rejects it, then the tool runs only if approved. This is
        # what enforces human-in-the-loop; without it the agent would proceed
        # while the action is still unapproved.
        self.wait = wait
        self.timeout = timeout

        if gate_client:
            self._client = gate_client
        else:
            from air_gate.client import GateClient
            self._client = GateClient(server_url=gate_url)

        # Copy LangChain tool attributes so the wrapper looks like the original
        self.name = getattr(tool, "name", tool.__class__.__name__)
        self.description = getattr(tool, "description", "")

    def run(self, *args, **kwargs) -> str:
        """Synchronous run - checks Gate before executing the tool."""
        tool_input = args[0] if args else kwargs.get("tool_input", str(kwargs))
        payload = {"input": tool_input} if isinstance(tool_input, str) else tool_input

        result = self._client.check(
            agent_id=self.agent_id,
            action_type=self.action_type,
            tool_name=self.name,
            payload=payload if isinstance(payload, dict) else {"input": str(payload)},
        )

        decision = result.get("decision", "blocked")
        event_id = result.get("event_id", "")

        if decision == "blocked":
            logger.warning(f"BLOCKED: {self.agent_id} → {self.name}: {result.get('reason')}")
            return self.block_message

        if decision == "pending_approval":
            if not self.wait:
                logger.info(f"PENDING: {self.agent_id} → {self.name} - not waiting (wait=False)")
                return f"[PENDING APPROVAL] Action sent to human reviewer. Event ID: {event_id}"
            logger.info(f"PENDING: {self.agent_id} → {self.name} - waiting for human approval")
            final = self._client.wait_for_decision(event_id, timeout=self.timeout)
            if final != "approved":
                # rejected, blocked, or timed out -> fail closed, do NOT execute
                logger.warning(f"NOT APPROVED ({final}): {self.agent_id} → {self.name}")
                return self.block_message

        # auto_allowed or approved - execute the tool
        logger.info(f"ALLOWED: {self.agent_id} → {self.name}")
        return self.tool.run(*args, **kwargs)

    async def arun(self, *args, **kwargs) -> str:
        """Async run - same gating logic, async execution."""
        # Gate check is sync (fast, local or single HTTP call)
        tool_input = args[0] if args else kwargs.get("tool_input", str(kwargs))
        payload = {"input": tool_input} if isinstance(tool_input, str) else tool_input

        result = self._client.check(
            agent_id=self.agent_id,
            action_type=self.action_type,
            tool_name=self.name,
            payload=payload if isinstance(payload, dict) else {"input": str(payload)},
        )

        decision = result.get("decision", "blocked")
        event_id = result.get("event_id", "")

        if decision == "blocked":
            return self.block_message
        if decision == "pending_approval":
            if not self.wait:
                return f"[PENDING APPROVAL] Event ID: {event_id}"
            final = await self._client.await_decision(event_id, timeout=self.timeout)
            if final != "approved":
                return self.block_message

        if hasattr(self.tool, "arun"):
            return await self.tool.arun(*args, **kwargs)
        return self.tool.run(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.run(*args, **kwargs)
