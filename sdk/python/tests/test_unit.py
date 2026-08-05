"""Unit tests (no gateway needed)."""

import json
import os
import sys
from dataclasses import asdict

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tracepath_sdk import (
    AsyncAuditClient,
    AuditEvent,
    AuditQueryResult,
    AuditResponse,
    Incident,
    PolicyDecision,
    PolicyDenied,
    SyncAuditClient,
)


def test_audit_event_model():
    e = AuditEvent(
        session_id="s1",
        agent_id="a1",
        step_number=1,
        tool_name="test",
        tool_input={"x": 1},
        tool_output={"y": 2},
        agent_type="coder",
    )
    assert e.session_id == "s1"
    assert e.agent_type == "coder"
    assert e.step_number == 1
    assert e.timestamp  # auto-generated


def test_audit_event_model_with_llm_metadata():
    e = AuditEvent(
        session_id="s1",
        agent_id="a1",
        step_number=1,
        tool_name="search",
        tool_input={"query": "otel"},
        tool_output={"count": 2},
        llm_model="gemini-2.5-flash",
        llm_provider="google",
        llm_prompt_tokens=120,
        llm_completion_tokens=30,
        llm_total_tokens=150,
        llm_latency_ms=245.5,
        llm_cost_cents=0.42,
    )

    payload = asdict(e)
    assert payload["llm_model"] == "gemini-2.5-flash"
    assert payload["llm_total_tokens"] == 150
    assert payload["llm_cost_cents"] == 0.42


def test_audit_response_parsing():
    data = {"status": "recorded", "signature": "abc", "policy_decision": {"allowed": True, "denials": []}}
    resp = AuditResponse(**data)
    assert resp.status == "recorded"
    assert resp.policy_decision.allowed is True


def test_policy_denied_exception():
    with pytest.raises(PolicyDenied, match="tool not in allowlist"):
        raise PolicyDenied(["tool not in allowlist"], "sig")


def test_incident_model():
    inc = Incident(
        id="inc1", type="rate_limit_breach", severity="warning",
        session_id="s1", agent_id="a1", message="Rate limit breach: 61 calls in 0.0s",
        detected_at="2026-07-11T12:00:00Z",
    )
    assert inc.type == "rate_limit_breach"
    assert inc.severity == "warning"


def test_audit_query_result_parsing():
    data = {
        "events": [{
            "id": "ev1", "session_id": "s1", "agent_id": "a1",
            "step_number": 1, "tool_name": "read_file", "signature": "sig",
            "created_at": "2026-07-11T12:00:00Z",
        }],
        "count": 1, "limit": 50, "offset": 0,
    }
    result = AuditQueryResult(**data)
    assert result.count == 1
    assert result.events[0].tool_name == "read_file"


def test_audit_query_result_parses_llm_metadata():
    data = {
        "events": [
            {
                "id": "ev1",
                "session_id": "s1",
                "agent_id": "a1",
                "step_number": 1,
                "tool_name": "search",
                "signature": "sig",
                "llm_model": "gemini-2.5-flash",
                "llm_provider": "google",
                "llm_prompt_tokens": 120,
                "llm_completion_tokens": 30,
                "llm_total_tokens": 150,
                "llm_latency_ms": 245.5,
                "llm_cost_cents": 0.42,
                "created_at": "2026-08-05T00:00:00Z",
            }
        ],
        "count": 1,
        "limit": 50,
        "offset": 0,
    }

    event = AuditQueryResult(**data).events[0]
    assert event.llm_model == "gemini-2.5-flash"
    assert event.llm_total_tokens == 150


@pytest.mark.asyncio
async def test_record_step_forwards_llm_metadata_and_omits_missing_values():
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={"status": "recorded", "signature": "sig"},
        )

    client = AsyncAuditClient(gateway_url="http://test", session_id="s1")
    await client._client.aclose()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async with client:
        await client.record_step("plain", {}, {})
        await client.record_step(
            "search",
            {"query": "otel"},
            {"count": 2},
            llm_model="gemini-2.5-flash",
            llm_provider="google",
            llm_prompt_tokens=120,
            llm_completion_tokens=30,
            llm_total_tokens=150,
            llm_latency_ms=245.5,
            llm_cost_cents=0.42,
        )

    assert "llm_model" not in requests[0]
    assert requests[1]["llm_model"] == "gemini-2.5-flash"
    assert requests[1]["llm_total_tokens"] == 150
    assert requests[1]["llm_cost_cents"] == 0.42


def test_client_instantiation():
    client = AsyncAuditClient(session_id="test", agent_type="coder")
    assert client.agent_type == "coder"
    assert client.session_id == "test"
    assert client.gateway_url == "http://localhost:9001"


def test_sync_client_instantiation():
    client = SyncAuditClient(session_id="test", agent_type="coder")
    assert client._async.agent_type == "coder"
    assert client._async.session_id == "test"
