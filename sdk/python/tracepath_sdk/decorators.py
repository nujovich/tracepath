"""Decorators for transparent step auditing.

``@audit`` wraps a function (sync or async) so every call is sent
to the Tracepath gateway as an audit step.  The return value is
serialized as ``tool_output``; exceptions become an ``{"error": ...}``
output so denied-but-exceptional calls are still recorded.

Usage::

    from tracepath_sdk import AsyncAuditClient, audit

    client = AsyncAuditClient(agent_type="coder")

    @audit(client)
    async def search_docs(query: str) -> str:
        ...

    result = await search_docs("rate limits")
    #  → POST /audit/step with tool_name="search_docs",
    #    tool_input={"query": "rate limits"},
    #    tool_output={"result": <return value>}
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from . import AsyncAuditClient, PolicyDenied


def audit(client: "AsyncAuditClient") -> Callable:
    """Return a decorator that audits every call of the wrapped function.

    Tool name = the function's ``__name__``.
    Tool input = the keyword arguments (as a dict).
    Tool output = ``{"result": <return value>}`` or, on exception,
    ``{"error": "<message>"}``.

    If the gateway denies the call (policy rejection) and the client
    has ``raise_on_deny=True``, :class:`PolicyDenied` is raised
    **after** the audit event has been recorded.
    """

    def decorator(fn: Callable) -> Callable:
        tool_name = fn.__name__

        if asyncio.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                from . import PolicyDenied  # lazy — avoids circular import

                try:
                    result = await fn(*args, **kwargs)
                    output: dict[str, Any] = {"result": result}
                except Exception as exc:
                    output = {"error": str(exc)}
                    try:
                        await client.record_step(tool_name, kwargs, output)
                    except PolicyDenied:
                        pass  # already recorded — re-raise original
                    raise
                await client.record_step(tool_name, kwargs, output)
                return result

            return async_wrapper
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                from . import PolicyDenied

                try:
                    result = fn(*args, **kwargs)
                    output = {"result": result}
                except Exception as exc:
                    output = {"error": str(exc)}
                    try:
                        try:
                            loop = asyncio.get_running_loop()
                        except RuntimeError:
                            asyncio.run(
                                client.record_step(tool_name, kwargs, output)
                            )
                        else:
                            import concurrent.futures
                            import threading

                            f: concurrent.futures.Future[None] = (
                                concurrent.futures.Future()
                            )

                            def _do() -> None:
                                asyncio.run(
                                    client.record_step(tool_name, kwargs, output)
                                )
                                f.set_result(None)

                            threading.Thread(target=_do, daemon=True).start()
                    except PolicyDenied:
                        pass
                    raise
                try:
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        asyncio.run(client.record_step(tool_name, kwargs, output))
                    else:
                        import concurrent.futures
                        import threading

                        f: concurrent.futures.Future[None] = (
                            concurrent.futures.Future()
                        )

                        def _do() -> None:
                            asyncio.run(
                                client.record_step(tool_name, kwargs, output)
                            )
                            f.set_result(None)

                        threading.Thread(target=_do, daemon=True).start()
                except PolicyDenied:
                    pass  # re-raise handled above
                return result

            return sync_wrapper

    return decorator
