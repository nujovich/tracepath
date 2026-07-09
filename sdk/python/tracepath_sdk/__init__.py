"""
Tracepath Python SDK — client wrapper to audit AI agent tool calls.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any
from uuid import uuid4

import httpx


@dataclass
class AuditEvent:
    session_id: str
    agent_id: str
    step_number: int
    tool_name: str
    tool_input: dict[str, Any]
    tool_output: dict[str, Any]
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ"))


class AuditClient:
    """Wraps AI agent tool calls and sends audit events to Tracepath Gateway."""

    def __init__(
        self,
        gateway_url: str | None = None,
        session_id: str | None = None,
        agent_id: str = "agent",
    ):
        self.gateway_url = gateway_url or os.getenv(
            "TRACEPATH_GATEWAY_URL", "http://localhost:9001"
        )
        self.session_id = session_id or str(uuid4())
        self.agent_id = agent_id
        self.step_number = 0
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))

    async def record_step(
        self, tool_name: str, tool_input: dict[str, Any], tool_output: dict[str, Any]
    ) -> dict[str, Any]:
        """Record a tool call step and send to Gateway."""
        self.step_number += 1
        event = AuditEvent(
            session_id=self.session_id,
            agent_id=self.agent_id,
            step_number=self.step_number,
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output,
        )

        response = await self._client.post(
            f"{self.gateway_url}/audit/step", json=asdict(event)
        )
        response.raise_for_status()
        return response.json()

    async def health(self) -> dict[str, Any]:
        """Check Gateway health."""
        response = await self._client.get(f"{self.gateway_url}/health")
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
