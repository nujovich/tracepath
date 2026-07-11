"""Integration tests for the Tracepath Python SDK.

Run against a live gateway::

    pytest -v tests/
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tracepath_sdk import (
    AsyncAuditClient,
    AuditQueryResult,
    AuditResponse,
    Incident,
    PolicyDenied,
)


GATEWAY_URL = os.getenv("TRACEPATH_GATEWAY_URL", "http://localhost:9001")


@pytest.mark.asyncio
async def test_health():
    client = AsyncAuditClient(gateway_url=GATEWAY_URL)
    async with client:
        h = await client.health()
        assert h["status"] == "ok"
        assert h["service"] == "tracepath-gateway"


@pytest.mark.asyncio
async def test_record_step_allowed():
    client = AsyncAuditClient(
        gateway_url=GATEWAY_URL,
        agent_type="researcher",
        session_id="sdk-test-allowed",
    )
    async with client:
        resp = await client.record_step(
            "web_search", {"query": "test"}, {"results": 3}
        )
        assert resp.status == "recorded"
        assert resp.policy_decision is not None
        assert resp.policy_decision.allowed is True
        assert len(resp.signature) > 0


@pytest.mark.asyncio
async def test_record_step_denied():
    client = AsyncAuditClient(
        gateway_url=GATEWAY_URL,
        agent_type="coder",
        session_id="sdk-test-denied",
    )
    async with client:
        with pytest.raises(PolicyDenied) as exc:
            await client.record_step(
                "image_generate", {"prompt": "test"}, {"url": "..."}
            )
        assert len(exc.value.denials) > 0
        assert "not" in exc.value.denials[0].lower() or "denied" in exc.value.denials[0].lower()


@pytest.mark.asyncio
async def test_query_events():
    client = AsyncAuditClient(
        gateway_url=GATEWAY_URL,
        session_id="sdk-test-allowed",
        agent_type="researcher",
    )
    async with client:
        # Ensure at least one event exists
        await client.record_step("web_search", {"q": "x"}, {"ok": True})
        result = await client.query_events(
            session_id="sdk-test-allowed", limit=10
        )
        assert isinstance(result, AuditQueryResult)
        assert result.count >= 1
        assert result.events[0].session_id == "sdk-test-allowed"


@pytest.mark.asyncio
async def test_get_incidents():
    client = AsyncAuditClient(gateway_url=GATEWAY_URL)
    async with client:
        incidents = await client.get_incidents(limit=5)
        assert isinstance(incidents, list)
        for inc in incidents:
            assert isinstance(inc, Incident)
            assert inc.id
            assert inc.type
            assert inc.severity
