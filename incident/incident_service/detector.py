"""Real-time incident detectors.

Evaluates incoming audit events against detection rules
and emits Incident objects when thresholds are breached.
Optionally refines severity with Gemini semantic classification.

Threshold rules are derived from the same policy intent as the Rego rules
in the gateway. Gemini adds a second pass: distinguishing true threats
from benign patterns (e.g., debugging loops vs. actual attacks).
"""

from datetime import datetime, timezone
from typing import Optional

from .gemini_classifier import GeminiClassifier
from .models import AuditEvent, Incident, IncidentType, SessionState, Severity


class Detector:
    """Evaluates audit events in real-time and yields incidents."""

    # ── Thresholds ──
    BUDGET_LIMIT_CENTS = 1000       # 10 € per session
    RATE_LIMIT_PER_MINUTE = 60      # matches gateway policy
    DENIAL_SPIKE_THRESHOLD = 5      # >5 denials in a session → incident
    SUSPICIOUS_CONSECUTIVE_SAME_TOOL = 10  # >10 same tool in a row → suspicious

    def __init__(self, gemini: Optional[GeminiClassifier] = None) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._gemini = gemini

    async def evaluate(self, event: AuditEvent) -> Optional[Incident]:
        """Evaluate a single audit event. Returns an Incident if triggered, else None.

        When Gemini is configured, threshold-triggered incidents get a second pass
        through semantic classification before being returned.
        """
        session = self._get_or_create_session(event)
        session.step_count += 1
        if session.step_count == 1:
            session.first_step_at = event.timestamp
        session.last_step_at = event.timestamp

        # Track tool usage
        tool = event.tool_name
        session.tool_counts[tool] = session.tool_counts.get(tool, 0) + 1

        # Track denials
        decision = event.policy_decision
        if not decision.get("allowed", True):
            session.denied_count += 1

        # Track estimated cost (from tool_input or policy metadata)
        cost = self._estimate_cost(event)
        session.cumulative_cost_cents += cost

        # ── Detection rules (threshold pass) ──
        incident = (
            self._check_budget(session)
            or self._check_denial_spike(session)
            or self._check_suspicious_pattern(session, event)
            or self._check_rate_limit(session, event)
        )

        # ── Gemini refinement pass ──
        if incident is not None and self._gemini is not None:
            summary = self._gemini.build_session_summary(
                event_count=session.step_count,
                tool_counts=session.tool_counts,
                denied_count=session.denied_count,
                cost_cents=session.cumulative_cost_cents,
            )
            incident = await self._gemini.refine(incident, summary)

        return incident

    # ── Private helpers ──

    def _get_or_create_session(self, event: AuditEvent) -> SessionState:
        if event.session_id not in self._sessions:
            self._sessions[event.session_id] = SessionState(
                session_id=event.session_id,
                agent_id=event.agent_id,
                agent_type=event.agent_type,
            )
        return self._sessions[event.session_id]

    @staticmethod
    def _estimate_cost(event: AuditEvent) -> int:
        """Estimate cost in cents from tool metadata. Conservative defaults."""
        tool_costs = {
            "terminal": 1,
            "read_file": 0,
            "write_file": 1,
            "web_search": 5,
            "web_extract": 3,
            "delegate_task": 10,
            "image_generate": 15,
            "browser_navigate": 8,
            "browser_click": 3,
            "browser_type": 2,
        }
        return tool_costs.get(event.tool_name, 1)

    def _check_budget(self, session: SessionState) -> Optional[Incident]:
        if session.cumulative_cost_cents >= self.BUDGET_LIMIT_CENTS:
            return Incident(
                id=f"budget-{session.session_id}",
                incident_type=IncidentType.BUDGET_EXCEEDED,
                severity=Severity.WARNING,
                session_id=session.session_id,
                agent_id=session.agent_id,
                message=(
                    f"Budget exceeded: {session.cumulative_cost_cents}c spent "
                    f"(limit: {self.BUDGET_LIMIT_CENTS}c) "
                    f"across {session.step_count} steps"
                ),
                context={
                    "cumulative_cost_cents": session.cumulative_cost_cents,
                    "budget_limit_cents": self.BUDGET_LIMIT_CENTS,
                    "step_count": session.step_count,
                },
            )
        return None

    def _check_denial_spike(self, session: SessionState) -> Optional[Incident]:
        if session.denied_count > self.DENIAL_SPIKE_THRESHOLD:
            return Incident(
                id=f"denial-{session.session_id}",
                incident_type=IncidentType.DENIAL_SPIKE,
                severity=Severity.CRITICAL,
                session_id=session.session_id,
                agent_id=session.agent_id,
                message=(
                    f"Denial spike: {session.denied_count} policy denials "
                    f"in session (threshold: {self.DENIAL_SPIKE_THRESHOLD})"
                ),
                context={
                    "denied_count": session.denied_count,
                    "total_steps": session.step_count,
                    "denial_rate": f"{session.denied_count}/{session.step_count}",
                },
            )
        return None

    def _check_suspicious_pattern(
        self, session: SessionState, event: AuditEvent
    ) -> Optional[Incident]:
        # Check if any single tool dominates suspiciously
        max_tool, max_count = max(
            session.tool_counts.items(), key=lambda x: x[1]
        )
        if (
            max_count >= self.SUSPICIOUS_CONSECUTIVE_SAME_TOOL
            and session.step_count <= max_count + 1  # almost all steps are this tool
        ):
            return Incident(
                id=f"suspicious-{session.session_id}-{max_tool}",
                incident_type=IncidentType.SUSPICIOUS_PATTERN,
                severity=Severity.WARNING,
                session_id=session.session_id,
                agent_id=session.agent_id,
                message=(
                    f"Suspicious pattern: tool '{max_tool}' used {max_count}/{session.step_count} "
                    f"times in session"
                ),
                context={
                    "dominant_tool": max_tool,
                    "dominant_count": max_count,
                    "other_tools": {
                        k: v for k, v in session.tool_counts.items() if k != max_tool
                    },
                },
            )
        return None

    def _check_rate_limit(
        self, session: SessionState, event: AuditEvent
    ) -> Optional[Incident]:
        if session.step_count >= self.RATE_LIMIT_PER_MINUTE and session.first_step_at:
            try:
                first_ts = datetime.fromisoformat(session.first_step_at)
                last_ts = datetime.fromisoformat(session.last_step_at)
                elapsed = (last_ts - first_ts).total_seconds()
                # elapsed=0 means all events in same second → instant breach
                if elapsed <= 0:
                    rate = float('inf')
                else:
                    rate = session.step_count / (elapsed / 60)
                if rate > self.RATE_LIMIT_PER_MINUTE:
                    return Incident(
                        id=f"ratelimit-{session.session_id}",
                        incident_type=IncidentType.RATE_LIMIT_BREACH,
                        severity=Severity.WARNING,
                        session_id=session.session_id,
                        agent_id=session.agent_id,
                        message=(
                            f"Rate limit approaching: {rate:.0f} calls/min "
                            f"(limit: {self.RATE_LIMIT_PER_MINUTE})"
                        ),
                        context={
                            "current_rate": round(rate, 1),
                            "rate_limit": self.RATE_LIMIT_PER_MINUTE,
                            "elapsed_seconds": elapsed,
                        },
                    )
            except ValueError:
                pass
        return None
