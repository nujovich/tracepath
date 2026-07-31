"""Webhook notifiers for incident alerts.

Sends structured incident payloads to Slack, Discord, and PagerDuty.
Configured via environment variables. Each channel is optional —
unset the corresponding env var to disable it.
"""

import json
import logging
import os

import aiohttp

from .models import Incident

logger = logging.getLogger("tracepath.webhooks")

# ── Env config ──
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY", "")
INCIDENT_DASHBOARD_URL = os.environ.get("INCIDENT_DASHBOARD_URL", "http://localhost:3000/incidents")

SEVERITY_COLORS = {
    "critical": "#DC2626",  # red
    "warning": "#F59E0B",   # amber
    "info": "#3B82F6",      # blue
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "warning": "🟡",
    "info": "🔵",
}


async def notify_all(incident: Incident) -> None:
    """Fire all configured webhook channels concurrently."""
    results = await asyncio_gather_safe(
        _notify_slack(incident) if SLACK_WEBHOOK_URL else None,
        _notify_discord(incident) if DISCORD_WEBHOOK_URL else None,
        _notify_pagerduty(incident) if PAGERDUTY_ROUTING_KEY else None,
    )
    for r in results:
        if r and isinstance(r, Exception):
            logger.error("webhook delivery failed: %s", r)


async def _notify_slack(incident: Incident) -> None:
    """Post incident to Slack incoming webhook."""
    color = SEVERITY_COLORS.get(incident.severity, "#6B7280")
    emoji = SEVERITY_EMOJI.get(incident.severity, "⚪")

    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"{emoji} [{incident.severity.upper()}] {incident.incident_type}",
                "text": incident.message,
                "fields": [
                    {"title": "Session", "value": incident.session_id, "short": True},
                    {"title": "Agent", "value": incident.agent_id, "short": True},
                ],
                "footer": "Tracepath Incident Service",
                "ts": int(datetime_utc_timestamp()),
            }
        ]
    }

    if incident.context:
        ctx_block = "\n".join(
            f"• *{k}*: {v}" for k, v in incident.context.items()
        )
        payload["attachments"][0]["fields"].append(
            {"title": "Context", "value": ctx_block, "short": False}
        )

    async with aiohttp.ClientSession() as session:
        async with session.post(SLACK_WEBHOOK_URL, json=payload) as resp:
            if resp.status >= 400:
                body = await resp.text()
                raise RuntimeError(f"Slack webhook returned {resp.status}: {body}")
            logger.info(
                "slack notification sent: %s [%s]", incident.id, incident.severity
            )


async def _notify_discord(incident: Incident) -> None:
    """Post incident to Discord webhook."""
    color_dec = int(SEVERITY_COLORS.get(incident.severity, "#6B7280").lstrip("#"), 16)
    emoji = SEVERITY_EMOJI.get(incident.severity, "⚪")

    payload = {
        "embeds": [
            {
                "title": f"{emoji} [{incident.severity.upper()}] {incident.incident_type}",
                "description": incident.message,
                "color": color_dec,
                "fields": [
                    {"name": "Session", "value": incident.session_id, "inline": True},
                    {"name": "Agent", "value": incident.agent_id, "inline": True},
                    {
                        "name": "Dashboard",
                        "value": f"[View incident]({INCIDENT_DASHBOARD_URL})",
                        "inline": False,
                    },
                ],
                "timestamp": incident.detected_at,
            }
        ]
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(DISCORD_WEBHOOK_URL, json=payload) as resp:
            if resp.status >= 400:
                body = await resp.text()
                raise RuntimeError(f"Discord webhook returned {resp.status}: {body}")
            logger.info(
                "discord notification sent: %s [%s]", incident.id, incident.severity
            )


async def _notify_pagerduty(incident: Incident) -> None:
    """Trigger PagerDuty incident via Events API v2."""
    severity_map = {"critical": "critical", "warning": "warning", "info": "info"}
    pd_severity = severity_map.get(incident.severity, "info")

    payload = {
        "routing_key": PAGERDUTY_ROUTING_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": f"[{incident.severity.upper()}] {incident.incident_type}: {incident.message}",
            "source": "tracepath-incident-service",
            "severity": pd_severity,
            "custom_details": {
                "incident_id": incident.id,
                "session_id": incident.session_id,
                "agent_id": incident.agent_id,
                "incident_type": incident.incident_type,
                "context": incident.context,
                "dashboard_url": INCIDENT_DASHBOARD_URL,
            },
        },
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            headers={"Content-Type": "application/json"},
        ) as resp:
            if resp.status >= 400:
                body = await resp.text()
                raise RuntimeError(f"PagerDuty returned {resp.status}: {body}")
            logger.info(
                "pagerduty incident triggered: %s [%s]", incident.id, incident.severity
            )


# ── Helpers ──


async def asyncio_gather_safe(*coros):
    """Like asyncio.gather but returns exceptions instead of raising."""
    import asyncio

    async def _safe(coro):
        if coro is None:
            return None
        try:
            return await coro
        except Exception as e:
            return e

    return await asyncio.gather(*(_safe(c) for c in coros))


def datetime_utc_timestamp() -> float:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).timestamp()
