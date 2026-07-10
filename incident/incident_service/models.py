"""Data models for incident detection."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class IncidentType(str, Enum):
    BUDGET_EXCEEDED = "budget_exceeded"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    RATE_LIMIT_BREACH = "rate_limit_breach"
    DENIAL_SPIKE = "denial_spike"
    UNUSUAL_TOOL = "unusual_tool"
    COMPLIANCE_VIOLATION = "compliance_violation"


@dataclass
class AuditEvent:
    session_id: str
    agent_id: str
    agent_type: str | None
    step_number: int
    tool_name: str
    tool_input: dict[str, Any]
    tool_output: dict[str, Any]
    timestamp: str
    signature: str
    policy_decision: dict[str, Any]


@dataclass
class Incident:
    id: str
    incident_type: IncidentType
    severity: Severity
    session_id: str
    agent_id: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class SessionState:
    """Rolling state for a session — used by detectors."""
    session_id: str
    agent_id: str
    agent_type: str | None
    step_count: int = 0
    denied_count: int = 0
    tool_counts: dict[str, int] = field(default_factory=dict)
    cumulative_cost_cents: int = 0
    last_step_at: str = ""
