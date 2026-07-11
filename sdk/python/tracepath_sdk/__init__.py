"""Tracepath Python SDK — auditable AI agent middleware client.

Usage::

    from tracepath_sdk import AsyncAuditClient

    client = AsyncAuditClient(agent_type="coder")
    async with client:
        result = await client.record_step("read_file", {"path": "/x"}, {"lines": 5})

        events = await client.query_events(limit=20)
        incidents = await client.get_incidents()
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional, Union
from uuid import uuid4

import httpx
from pydantic import BaseModel

from .decorators import audit


# ═══════════════════════════════════════════════════════════════════
# Errors
# ═══════════════════════════════════════════════════════════════════


class TracepathError(Exception):
    """Base error for Tracepath SDK."""


class PolicyDenied(TracepathError):
    """Raised when a tool call was denied by policy."""

    def __init__(self, denials: list[str], signature: str) -> None:
        self.denials = denials
        self.signature = signature
        super().__init__(f"Policy denied: {', '.join(denials)}")


class GatewayUnavailable(TracepathError):
    """Gateway did not respond."""


class QueryError(TracepathError):
    """Audit query failed."""


# ═══════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════


class PolicyDecision(BaseModel):
    allowed: bool
    denials: list[str] = []


class AuditResponse(BaseModel):
    status: str
    signature: str
    policy_decision: Optional[PolicyDecision] = None


class AuditEventRow(BaseModel):
    id: str
    session_id: str
    agent_id: str
    agent_type: Optional[str] = None
    step_number: int
    tool_name: str
    signature: str
    policy_decision: Optional[str] = None
    created_at: str


class AuditQueryResult(BaseModel):
    events: list[AuditEventRow]
    count: int
    limit: int
    offset: int


class Incident(BaseModel):
    id: str
    type: str
    severity: str
    session_id: str
    agent_id: str
    message: str
    context: dict[str, Any] = {}
    detected_at: str


class IncidentList(BaseModel):
    incidents: list[Incident]


@dataclass
class AuditEvent:
    """An audit step to send to the gateway."""

    session_id: str
    agent_id: str
    step_number: int
    tool_name: str
    tool_input: dict[str, Any]
    tool_output: dict[str, Any]
    agent_type: str = "default"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )


# ═══════════════════════════════════════════════════════════════════
# Async client
# ═══════════════════════════════════════════════════════════════════


class AsyncAuditClient:
    """Async client for the Tracepath Audit Gateway.

    Parameters
    ----------
    gateway_url:
        URL of the gateway (default ``TRACEPATH_GATEWAY_URL`` or
        ``http://localhost:9001``).
    session_id:
        Session identifier (auto-generated UUID if omitted).
    agent_id:
        Identifier for this agent instance.
    agent_type:
        ``coder``, ``researcher``, ``assistant``, etc.  Used by
        policy rules to apply per-type allowlists and budgets.
    raise_on_deny:
        When ``True`` (default), ``record_step`` raises
        :class:`PolicyDenied` for denied calls.
    """

    def __init__(
        self,
        gateway_url: str | None = None,
        session_id: str | None = None,
        agent_id: str = "agent",
        agent_type: str = "default",
        raise_on_deny: bool = True,
    ) -> None:
        self.gateway_url: str = (
            gateway_url
            or os.getenv("TRACEPATH_GATEWAY_URL", "http://localhost:9001")
        )
        self.session_id: str = session_id or str(uuid4())
        self.agent_id: str = agent_id
        self.agent_type: str = agent_type
        self.raise_on_deny: bool = raise_on_deny
        self.step_number: int = 0
        self._client: httpx.AsyncClient = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0)
        )

    # ── context manager ──────────────────────────────────────────

    async def __aenter__(self) -> "AsyncAuditClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # ── gateway endpoints ────────────────────────────────────────

    async def health(self) -> dict[str, Any]:
        r = await self._client.get(f"{self.gateway_url}/health")
        r.raise_for_status()
        return r.json()

    async def health_policy(self) -> dict[str, Any]:
        r = await self._client.get(f"{self.gateway_url}/health/policy")
        r.raise_for_status()
        return r.json()

    async def record_step(
        self, tool_name: str, tool_input: dict[str, Any], tool_output: dict[str, Any]
    ) -> AuditResponse:
        """Record a tool call and submit it to the gateway.

        Returns an :class:`AuditResponse`.  If *raise_on_deny* is set
        (the default) and the policy engine rejects the call, raises
        :class:`PolicyDenied` instead.
        """
        self.step_number += 1
        event = AuditEvent(
            session_id=self.session_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            step_number=self.step_number,
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output,
        )
        try:
            r = await self._client.post(
                f"{self.gateway_url}/audit/step", json=asdict(event)
            )
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                try:
                    body = exc.response.json()
                except Exception:
                    raise PolicyDenied(
                        ["unknown denial"], ""
                    ) from exc
                denials = (
                    body.get("policy_decision", {}).get("denials", [])
                    if isinstance(body.get("policy_decision"), dict)
                    else []
                )
                raise PolicyDenied(denials, body.get("signature", "")) from exc
            raise GatewayUnavailable(
                f"gateway returned {exc.response.status_code}"
            ) from exc
        data = r.json()
        return AuditResponse(**data)

    async def query_events(
        self,
        session_id: str | None = None,
        agent_id: str | None = None,
        tool_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AuditQueryResult:
        """Retrieve audit events from the gateway."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if session_id:
            params["session_id"] = session_id
        if agent_id:
            params["agent_id"] = agent_id
        if tool_name:
            params["tool_name"] = tool_name
        try:
            r = await self._client.get(
                f"{self.gateway_url}/audit/events", params=params
            )
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise QueryError(str(exc)) from exc
        return AuditQueryResult(**r.json())

    async def get_incidents(self, limit: int = 100) -> list[Incident]:
        """Fetch incidents detected by the incident service."""
        try:
            r = await self._client.get(
                f"{self.gateway_url}/incidents", params={"limit": limit}
            )
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise QueryError(str(exc)) from exc
        return [Incident(**i) for i in r.json().get("incidents", [])]


# ═══════════════════════════════════════════════════════════════════
# Sync client (convenience)
# ═══════════════════════════════════════════════════════════════════


class SyncAuditClient:
    """Synchronous wrapper around :class:`AsyncAuditClient`.

    All parameters are forwarded to the async client.  The sync client
    is a thin convenience for scripts and sync frameworks.
    """

    def __init__(self, **kwargs: Any) -> None:
        self._async = AsyncAuditClient(**kwargs)

    def __enter__(self) -> "SyncAuditClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is None:
            asyncio.run(self._async.close())
        else:
            # Already inside an event loop — schedule and hope.
            import threading
            import concurrent.futures

            f = concurrent.futures.Future()

            def _close() -> None:
                try:
                    asyncio.run(self._async.close())
                    f.set_result(None)
                except Exception as e:
                    f.set_exception(e)

            threading.Thread(target=_close, daemon=True).start()

    def _run(self, coro: Any) -> Any:
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        # We're inside an event loop — run in a new one on a thread.
        import concurrent.futures
        import threading

        f: concurrent.futures.Future[Any] = concurrent.futures.Future()

        def _runner() -> None:
            try:
                result = asyncio.run(coro)
                f.set_result(result)
            except Exception as e:
                f.set_exception(e)

        threading.Thread(target=_runner, daemon=True).start()
        return f.result()

    def health(self) -> dict[str, Any]:
        return self._run(self._async.health())

    def health_policy(self) -> dict[str, Any]:
        return self._run(self._async.health_policy())

    def record_step(
        self, tool_name: str, tool_input: dict[str, Any], tool_output: dict[str, Any]
    ) -> AuditResponse:
        return self._run(
            self._async.record_step(tool_name, tool_input, tool_output)
        )

    def query_events(
        self,
        session_id: str | None = None,
        agent_id: str | None = None,
        tool_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AuditQueryResult:
        return self._run(
            self._async.query_events(
                session_id=session_id,
                agent_id=agent_id,
                tool_name=tool_name,
                limit=limit,
                offset=offset,
            )
        )

    def get_incidents(self, limit: int = 100) -> list[Incident]:
        return self._run(self._async.get_incidents(limit=limit))
