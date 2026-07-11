"""Decorator tests."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tracepath_sdk import AsyncAuditClient, PolicyDenied, audit

GATEWAY_URL = os.getenv("TRACEPATH_GATEWAY_URL", "http://localhost:9001")


@pytest.mark.asyncio
async def test_decorator_async():
    client = AsyncAuditClient(
        gateway_url=GATEWAY_URL,
        agent_type="default",
        session_id="sdk-decorator-async",
    )

    @audit(client)
    async def web_search(query: str) -> int:
        return len(query)

    async with client:
        result = await web_search(query="hello world")
        assert result == 11
        assert client.step_number == 1


@pytest.mark.asyncio
async def test_decorator_exception_is_audited():
    client = AsyncAuditClient(
        gateway_url=GATEWAY_URL,
        agent_type="default",
        session_id="sdk-decorator-err",
    )

    @audit(client)
    async def web_extract(url: str) -> str:
        raise ValueError(url)

    async with client:
        with pytest.raises(ValueError, match="kaboom"):
            await web_extract(url="kaboom")
        # Step was still recorded (1 call)
        assert client.step_number == 1