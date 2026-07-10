"""Policy replay engine.

Replays historical audit events against a selected policy version
to answer: "What would have happened if this policy was active then?"

Produces a ReplayResult comparing original decisions vs. new policy decisions.
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .versioning import POLICY_FILES, PolicyVersioning

logger = logging.getLogger("tracepath.policies.replay")

OPA_BIN = os.environ.get("OPA_BIN", "opa")


@dataclass
class ReplayEvent:
    """A single event replayed against a policy version."""
    event_id: str
    session_id: str
    agent_id: str
    tool_name: str
    step_number: int
    original_allowed: bool
    original_denials: list[str] = field(default_factory=list)
    replay_allowed: bool = True
    replay_denials: list[str] = field(default_factory=list)
    changed: bool = False


@dataclass
class ReplayResult:
    """Summary of a policy replay."""
    policy_version: str
    policy_message: str
    generated_at: str
    total_events: int
    affected_events: int  # events where the decision would change
    newly_denied: int     # was allowed, now denied
    newly_allowed: int    # was denied, now allowed
    affected_sessions: int
    events: list[ReplayEvent] = field(default_factory=list)


class ReplayEngine:
    """Replays audit events against historical policy versions."""

    def __init__(
        self,
        versioning: PolicyVersioning | None = None,
        db_pool=None,
    ) -> None:
        self._versioning = versioning or PolicyVersioning()
        self._db_pool = db_pool
        self._policy_cache: dict[str, str] = {}  # commit_hash -> temp_dir

    async def replay(
        self,
        policy_version: str,
        period_start: str | None = None,
        period_end: str | None = None,
        limit: int = 1000,
    ) -> ReplayResult:
        """Replay historical events against a specific policy version."""
        # Get policy version info
        versions = self._versioning.list_versions()
        version_info = next((v for v in versions if v.commit_hash.startswith(policy_version)), None)
        if version_info is None:
            raise ValueError(f"Policy version not found: {policy_version}")

        # Get events from DB
        events = await self._fetch_events(period_start, period_end, limit)
        if not events:
            return ReplayResult(
                policy_version=policy_version,
                policy_message=version_info.message,
                generated_at=datetime.now(timezone.utc).isoformat(),
                total_events=0,
                affected_events=0,
                newly_denied=0,
                newly_allowed=0,
                affected_sessions=0,
            )

        # Export policy version to a temp directory for OPA
        policy_dir = self._export_policy_version(policy_version)

        # Replay each event
        replay_events = []
        for evt in events:
            replay_evt = await self._replay_event(evt, policy_dir)
            replay_events.append(replay_evt)

        # Compute summary
        newly_denied = sum(1 for e in replay_events if e.original_allowed and not e.replay_allowed)
        newly_allowed = sum(1 for e in replay_events if not e.original_allowed and e.replay_allowed)
        affected = newly_denied + newly_allowed
        affected_sessions = len(set(
            e.session_id for e in replay_events if e.changed
        ))

        return ReplayResult(
            policy_version=policy_version,
            policy_message=version_info.message,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_events=len(replay_events),
            affected_events=affected,
            newly_denied=newly_denied,
            newly_allowed=newly_allowed,
            affected_sessions=affected_sessions,
            events=replay_events,
        )

    # ── Private ──

    async def _fetch_events(
        self,
        period_start: str | None,
        period_end: str | None,
        limit: int,
    ) -> list[dict]:
        """Fetch audit events from PostgreSQL."""
        if self._db_pool is None:
            logger.warning("No DB pool configured — replay requires PostgreSQL connection")
            return []

        where = ""
        params: list[Any] = []
        n = 1
        if period_start:
            where += f" WHERE created_at >= ${n}"
            params.append(period_start)
            n += 1
        if period_end:
            prefix = " AND" if where else " WHERE"
            where += f"{prefix} created_at <= ${n}"
            params.append(period_end)
            n += 1

        query = f"""
            SELECT id, session_id, agent_id, agent_type, step_number,
                   tool_name, tool_input, tool_output, signature, policy_decision
            FROM audit_events
            {where}
            ORDER BY created_at ASC
            LIMIT ${n}
        """
        params.append(limit)

        rows = await self._db_pool.fetch(query, *params)
        return [
            {
                "id": str(r["id"]),
                "session_id": r["session_id"],
                "agent_id": r["agent_id"],
                "agent_type": r["agent_type"],
                "step_number": r["step_number"],
                "tool_name": r["tool_name"],
                "tool_input": json.loads(r["tool_input"]) if isinstance(r["tool_input"], str) else r["tool_input"],
                "tool_output": json.loads(r["tool_output"]) if isinstance(r["tool_output"], str) else r["tool_output"],
                "policy_decision": json.loads(r["policy_decision"]) if isinstance(r["policy_decision"], str) and r["policy_decision"] else (r["policy_decision"] or {}),
            }
            for r in rows
        ]

    async def _replay_event(self, event: dict, policy_dir: str) -> ReplayEvent:
        """Replay a single event against the given policy version."""
        original = event.get("policy_decision", {})
        original_allowed = original.get("allowed", True) if isinstance(original, dict) else True
        original_denials = original.get("denials", []) if isinstance(original, dict) else []

        # Build OPA input matching gateway format
        opa_input = json.dumps({
            "action": "audit_step",
            "agent_type": event.get("agent_type") or "default",
            "tool_name": event["tool_name"],
            "estimated_cost_cents": 0,
            "spent_so_far_cents": 0,
            "calls_last_minute": 0,
        })

        try:
            result = await asyncio.to_thread(
                lambda: subprocess.run(
                    [
                        OPA_BIN, "eval",
                        "--data", policy_dir,
                        "--input", "/dev/stdin",
                        "--format", "json",
                        "data.tracepath.main.decision",
                    ],
                    input=opa_input,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            )

            if result.returncode == 0 and result.stdout.strip():
                opa_output = json.loads(result.stdout)
                # OPA returns: {"result": [{"expressions": [{"value": {"allowed": bool, "denials": [...]}}]}]}
                decision = opa_output.get("result", [{}])[0].get("expressions", [{}])[0].get("value", {})
                replay_allowed = decision.get("allowed", True)
                replay_denials = decision.get("denials", [])
            else:
                logger.warning("OPA eval failed for event %s: rc=%d stderr=%s",
                              event["id"], result.returncode, result.stderr)
                replay_allowed = True
                replay_denials = []

        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            logger.warning("OPA eval error for event %s: %s", event["id"], e)
            replay_allowed = True
            replay_denials = []

        changed = (original_allowed != replay_allowed)

        return ReplayEvent(
            event_id=event["id"],
            session_id=event["session_id"],
            agent_id=event["agent_id"],
            tool_name=event["tool_name"],
            step_number=event["step_number"],
            original_allowed=original_allowed,
            original_denials=original_denials,
            replay_allowed=replay_allowed,
            replay_denials=replay_denials,
            changed=changed,
        )

    def _export_policy_version(self, commit_hash: str) -> str:
        """Export policy files at a given version to a temp directory."""
        if commit_hash in self._policy_cache:
            return self._policy_cache[commit_hash]

        tmpdir = tempfile.mkdtemp(prefix="tracepath-policy-")
        for filename in POLICY_FILES:
            content = self._versioning.get_policy_at(commit_hash, filename)
            if content is not None:
                filepath = os.path.join(tmpdir, filename)
                with open(filepath, "w") as f:
                    f.write(content)

        self._policy_cache[commit_hash] = tmpdir
        logger.info("Exported policy %s to %s", commit_hash[:8], tmpdir)
        return tmpdir

    def to_summary(self, result: ReplayResult) -> dict:
        """Serialize a replay result to a JSON-compatible summary dict."""
        return {
            "policy_version": result.policy_version,
            "policy_message": result.policy_message,
            "generated_at": result.generated_at,
            "total_events": result.total_events,
            "affected_events": result.affected_events,
            "newly_denied": result.newly_denied,
            "newly_allowed": result.newly_allowed,
            "affected_sessions": result.affected_sessions,
            "sample_affected": [
                {
                    "event_id": e.event_id,
                    "session_id": e.session_id,
                    "tool_name": e.tool_name,
                    "original": "allowed" if e.original_allowed else f"denied: {e.original_denials}",
                    "replay": "allowed" if e.replay_allowed else f"denied: {e.replay_denials}",
                }
                for e in result.events
                if e.changed
            ][:20],
        }
