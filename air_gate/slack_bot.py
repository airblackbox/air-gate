"""
Slack approval bot — sends agent actions to Slack for human review.

When an agent action requires approval, Gate sends a rich Slack message
with the action details and Approve/Reject buttons. The human clicks a
button, and Gate records the decision in the signed event chain.

This is the killer feature: no dashboard to build, no login system.
Enterprises already live in Slack.
"""

import os
import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger("gate.slack")


class SlackBot:
    """Sends approval requests to Slack and handles button responses."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        bot_token: Optional[str] = None,
        channel: Optional[str] = None,
    ):
        """
        Two modes:
        1. Webhook mode (simpler): Just needs SLACK_WEBHOOK_URL. Can send messages
           but can't receive button clicks natively (use /approve endpoint instead).
        2. Bot token mode (full): Needs SLACK_BOT_TOKEN + channel. Full interactivity.

        For MVP, webhook mode + a /approve API endpoint is plenty.
        """
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
        self.bot_token = bot_token or os.getenv("SLACK_BOT_TOKEN", "")
        self.channel = channel or os.getenv("SLACK_CHANNEL", "#ai-approvals")
        self.gate_url = os.getenv("GATE_URL", "http://localhost:8000")

    def format_approval_message(self, event_id: str, agent_id: str, action_type: str,
                                 tool_name: str, payload: dict, input_context: str = "") -> dict:
        """
        Build a Slack Block Kit message for an approval request.

        Shows: which agent, what action, what data, approve/reject buttons.
        """
        # Truncate payload for display (full payload available via API)
        payload_preview = json.dumps(payload, indent=2)
        if len(payload_preview) > 1500:
            payload_preview = payload_preview[:1500] + "\n... (truncated)"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔒 Agent Action Requires Approval",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n`{agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Action:*\n`{action_type}`"},
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{tool_name}`"},
                    {"type": "mrkdwn", "text": f"*Event ID:*\n`{event_id[:8]}...`"},
                ],
            },
        ]

        # Add context if provided
        if input_context:
            context_preview = input_context[:500] + ("..." if len(input_context) > 500 else "")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Context:*\n>{context_preview}",
                },
            })

        # Add payload
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Payload:*\n```{payload_preview}```",
            },
        })

        # Approve / Reject buttons
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                    "style": "primary",
                    "value": event_id,
                    "action_id": "gate_approve",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ Reject", "emoji": True},
                    "style": "danger",
                    "value": event_id,
                    "action_id": "gate_reject",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "👁️ View Full Payload"},
                    "value": event_id,
                    "action_id": "gate_view",
                    "url": f"{self.gate_url}/events/{event_id}",
                },
            ],
        })

        return {"blocks": blocks, "text": f"Agent action requires approval: {agent_id} → {tool_name}"}

    async def send_approval_request(self, event_id: str, agent_id: str, action_type: str,
                                     tool_name: str, payload: dict, input_context: str = "") -> bool:
        """Send an approval request to Slack. Returns True if sent successfully."""
        message = self.format_approval_message(
            event_id=event_id,
            agent_id=agent_id,
            action_type=action_type,
            tool_name=tool_name,
            payload=payload,
            input_context=input_context,
        )

        try:
            if self.webhook_url:
                return await self._send_webhook(message)
            elif self.bot_token:
                return await self._send_bot(message)
            else:
                logger.warning("No Slack credentials configured — logging approval request instead")
                logger.info(f"APPROVAL NEEDED: {agent_id} → {tool_name} (event: {event_id})")
                return True  # Don't block if Slack isn't configured

        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return False

    async def _send_webhook(self, message: dict) -> bool:
        """Send via incoming webhook (simpler setup)."""
        async with httpx.AsyncClient() as client:
            response = await client.post(self.webhook_url, json=message)
            if response.status_code == 200:
                return True
            else:
                logger.error(f"Slack webhook error: {response.status_code} {response.text}")
                return False

    async def _send_bot(self, message: dict) -> bool:
        """Send via bot token (full interactivity)."""
        message["channel"] = self.channel
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://slack.com/api/chat.postMessage",
                json=message,
                headers={"Authorization": f"Bearer {self.bot_token}"},
            )
            data = response.json()
            if data.get("ok"):
                return True
            else:
                logger.error(f"Slack API error: {data.get('error')}")
                return False

    async def send_notification(self, text: str) -> bool:
        """Send a simple text notification to Slack."""
        message = {"text": text}
        if self.webhook_url:
            return await self._send_webhook(message)
        elif self.bot_token:
            message["channel"] = self.channel
            return await self._send_bot(message)
        return False
