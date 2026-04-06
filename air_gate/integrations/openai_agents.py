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
        What to return when Gate blocks the action.

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

            if decision == "blocked":
                logger.warning(f"BLOCKED: {agent_id} → {tool_name}: {result.get('reason')}")
                return block_return

            if decision == "pending_approval":
                logger.info(f"PENDING: {agent_id} → {tool_name}")
                return f"[PENDING APPROVAL] Event ID: {result.get('event_id')}"

            # Allowed — execute the function
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

            if decision == "blocked":
                return block_return
            if decision == "pending_approval":
                return f"[PENDING APPROVAL] Event ID: {result.get('event_id')}"

            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
