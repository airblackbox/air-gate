"""
gate/integrations/openai_agents.py

Wrapper for OpenAI Agents SDK function tools that routes
every tool call through Gate for policy + audit.

Usage:

    from openai import OpenAI
    from air_gate.integrations.openai_agents import gated_tool
    from gate import GateClient

    gate = GateClient()  # local mode, or GateClient(server_url="...")

    @gated_tool(gate=gate, agent_id="assistant-v1")
    def send_email(to: str, subject: str, body: str) -> str:
        \"\"\"Send an email to a recipient.\"\"\"
        # your actual email logic here
        return f"Email sent to {to}"

    # Use send_email as a normal function tool in your OpenAI agent
    # Every call gets policy-checked and audit-signed by Gate
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("gate.openai")


def gated_tool(
    gate: Any,
    agent_id: str,
    action_type: str = "tool_call",
    block_return: str = "[BLOCKED BY POLICY]",
    wait: bool = True,
    timeout: float = 300.0,
):
    """
    Decorator that wraps any function tool with Gate policy checking.

    Parameters
    ----------
    gate : GateClient
        A configured GateClient instance.
    agent_id : str
        Identifier for the agent calling this tool.
    action_type : str
        Classification for this tool's actions.
    block_return : str
        What to return when Gate blocks (or does not approve) the action.
    wait : bool
        When True (default), a pending action BLOCKS until a human approves or
        rejects, and the function runs only if approved. This is what enforces
        human-in-the-loop. When False, a pending action returns immediately
        without executing.
    timeout : float
        Seconds to wait for a human decision before failing closed.

    Returns
    -------
    Decorator that wraps the function.
    """

    def decorator(func: Callable) -> Callable:
        tool_name = func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Build payload from function arguments
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            payload = dict(bound.arguments)

            # Check Gate
            result = gate.check(
                agent_id=agent_id,
                action_type=action_type,
                tool_name=tool_name,
                payload=payload,
            )

            decision = result.get("decision", "blocked")
            event_id = result.get("event_id", "")

            if decision == "blocked":
                logger.warning(f"BLOCKED: {agent_id} → {tool_name}: {result.get('reason')}")
                return block_return

            if decision == "pending_approval":
                if not wait:
                    logger.info(f"PENDING: {agent_id} → {tool_name} (wait=False)")
                    return f"[PENDING APPROVAL] Event ID: {event_id}"
                logger.info(f"PENDING: {agent_id} → {tool_name} - waiting for approval")
                final = gate.wait_for_decision(event_id, timeout=timeout)
                if final != "approved":
                    logger.warning(f"NOT APPROVED ({final}): {agent_id} → {tool_name}")
                    return block_return

            # Allowed - execute the function
            logger.info(f"ALLOWED: {agent_id} → {tool_name}")
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            payload = dict(bound.arguments)

            result = gate.check(
                agent_id=agent_id,
                action_type=action_type,
                tool_name=tool_name,
                payload=payload,
            )

            decision = result.get("decision", "blocked")
            event_id = result.get("event_id", "")

            if decision == "blocked":
                return block_return
            if decision == "pending_approval":
                if not wait:
                    return f"[PENDING APPROVAL] Event ID: {event_id}"
                final = await gate.await_decision(event_id, timeout=timeout)
                if final != "approved":
                    return block_return

            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
