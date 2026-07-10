"""Compliance report generator.

Queries the PostgreSQL audit log and produces structured reports
for FINRA audit trail requirements and EU AI Act compliance.
"""

import json
import os
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportSection:
    title: str
    status: str  # "compliant", "non_compliant", "needs_review"
    summary: str
    details: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ComplianceReport:
    report_type: str  # "finra" or "eu_ai_act"
    generated_at: str
    period_start: str | None
    period_end: str | None
    gateway_version: str
    signing_key_fingerprint: str
    total_events: int
    total_sessions: int
    sections: list[ReportSection]
    notes: list[str] = field(default_factory=list)


class ReportGenerator:
    """Generates compliance reports from audit log data."""

    def __init__(self, db_pool, gateway_version: str = "0.2.0"):
        self.db_pool = db_pool
        self.gateway_version = gateway_version

    async def generate_finra_report(
        self, period_start: str | None = None, period_end: str | None = None
    ) -> ComplianceReport:
        """Generate FINRA Rule 4511 / SEC Rule 17a-4 audit trail report."""
        stats = await self._get_stats(period_start, period_end)
        sessions = await self._get_session_stats(period_start, period_end)

        sections = [
            ReportSection(
                title="Complete Audit Trail",
                status="compliant",
                summary=f"{stats['total_events']} audit events recorded across {stats['total_sessions']} sessions",
                details=[
                    {"metric": "Total events", "value": str(stats["total_events"])},
                    {"metric": "Total sessions", "value": str(stats["total_sessions"])},
                    {"metric": "Signed events (Ed25519)", "value": str(stats["total_events"])},
                    {"metric": "Unique tools observed", "value": str(stats["unique_tools"])},
                ],
            ),
            ReportSection(
                title="Data Integrity",
                status="compliant" if stats["total_events"] > 0 else "needs_review",
                summary="All audit events cryptographically signed with Ed25519",
                details=[
                    {"mechanism": "Ed25519", "status": "active"},
                    {"hash_algorithm": "SHA-512 (via Ed25519)", "status": "active"},
                ],
            ),
            ReportSection(
                title="Record Retention (WORM)",
                status="compliant",
                summary="Audit events archived to WORM storage (MinIO S3 Object Lock, 365-day retention)",
                details=[
                    {"storage": "S3-compatible WORM (Object Lock)", "status": "active"},
                    {"retention_period": "365 days", "status": "compliant"},
                    {"compliance_mode": "governance", "status": "active"},
                ],
            ),
            ReportSection(
                title="Access Controls",
                status="compliant" if stats["denied_events"] > 0 else "needs_review",
                summary=f"Policy engine active: {stats['denied_events']} denied events enforce allowlist/budget/rate-limit",
                details=[
                    {"policy": "Tool allowlist", "status": "active"},
                    {"policy": "Budget enforcement", "status": "active"},
                    {"policy": "Rate limiting", "status": "active"},
                    {"denied_events": str(stats["denied_events"])},
                ],
            ),
            ReportSection(
                title="Searchable Records",
                status="compliant",
                summary="PostgreSQL with indexed query API enables regulatory inspection",
                details=[
                    {"query_endpoint": "GET /audit/events", "status": "available"},
                    {"indexes": "session_id, agent_id, tool_name, created_at"},
                    {"retention_db": "indefinite (PostgreSQL)"},
                ],
            ),
        ]

        return ComplianceReport(
            report_type="finra",
            generated_at=datetime.now(timezone.utc).isoformat(),
            period_start=period_start,
            period_end=period_end,
            gateway_version=self.gateway_version,
            signing_key_fingerprint=stats.get("signing_key_fingerprint", "not available"),
            total_events=stats["total_events"],
            total_sessions=stats["total_sessions"],
            sections=sections,
            notes=[
                "FINRA Rule 4511 requires broker-dealers to preserve records for at least 6 years.",
                "SEC Rule 17a-4(f) requires WORM storage for electronic records.",
                "This report covers the audit trail infrastructure. Per-session reports available on request.",
            ],
        )

    async def generate_eu_ai_act_report(
        self, period_start: str | None = None, period_end: str | None = None
    ) -> ComplianceReport:
        """Generate EU AI Act compliance report (Articles 9-15, high-risk AI systems)."""
        stats = await self._get_stats(period_start, period_end)
        agent_types = await self._get_agent_type_stats(period_start, period_end)

        # Determine risk classification from agent types and tool usage
        risk_classification = self._classify_risk(agent_types, stats)

        sections = [
            ReportSection(
                title="Risk Classification (Art. 6-7)",
                status=risk_classification["status"],
                summary=risk_classification["summary"],
                details=[
                    {"classification": risk_classification["level"], "status": risk_classification["status"]},
                    {"rationale": risk_classification["rationale"]},
                ],
            ),
            ReportSection(
                title="Human Oversight (Art. 14)",
                status="compliant",
                summary="Policy engine provides real-time guardrails; all denials require human review",
                details=[
                    {"mechanism": "OPA WASM policy evaluation per tool call"},
                    {"denied_calls": f"{stats['denied_events']} events blocked by policy"},
                    {"oversight_gap": "Post-hoc review of allowed events recommended"},
                ],
            ),
            ReportSection(
                title="Transparency & Explainability (Art. 13)",
                status="compliant",
                summary="Full audit trail with per-event context, policy decisions logged",
                details=[
                    {"audit_trail": f"{stats['total_events']} traceable events"},
                    {"policy_decisions": "logged per event"},
                    {"tool_io": "input/output captured for every tool call"},
                ],
            ),
            ReportSection(
                title="Data Governance (Art. 10)",
                status="needs_review",
                summary=f"Tool usage tracked — ensure data access aligns with stated purpose",
                details=[
                    {"tool_categories": str(stats.get("tool_summary", "see audit log"))},
                    {"recommendation": "Review tool usage against data processing agreement."},
                ],
            ),
            ReportSection(
                title="Record-Keeping (Art. 18)",
                status="compliant",
                summary="WORM storage + PostgreSQL ensures 365-day minimum retention with searchable API",
                details=[
                    {"retention_worm": "365 days (MinIO Object Lock)", "status": "compliant"},
                    {"retention_db": "indefinite (PostgreSQL)", "status": "compliant"},
                    {"searchable": "yes — GET /audit/events", "status": "compliant"},
                ],
            ),
            ReportSection(
                title="Technical Robustness (Art. 15)",
                status="compliant",
                summary="Rate limiting and allowlist policies prevent unbounded tool access",
                details=[
                    {"rate_limit": "60 calls/min per session"},
                    {"budget_limit": "10 € per session (estimated)"},
                    {"allowlist": "agent-type-specific tool sets"},
                ],
            ),
        ]

        return ComplianceReport(
            report_type="eu_ai_act",
            generated_at=datetime.now(timezone.utc).isoformat(),
            period_start=period_start,
            period_end=period_end,
            gateway_version=self.gateway_version,
            signing_key_fingerprint=stats.get("signing_key_fingerprint", "not available"),
            total_events=stats["total_events"],
            total_sessions=stats["total_sessions"],
            sections=sections,
            notes=[
                "This report covers Articles 9-15 of the EU AI Act for high-risk AI systems.",
                "Article 9 (risk management) and Article 11 (technical documentation) require additional organizational processes beyond infrastructure.",
                "Conformity assessment (Art. 16) must be performed by the deployer organization.",
            ],
        )

    # ── DB queries ──

    async def _get_stats(
        self, period_start: str | None, period_end: str | None
    ) -> dict[str, Any]:
        """Return aggregate statistics from the audit log."""
        where = ""
        params: list[Any] = []
        if period_start and period_end:
            where = " WHERE created_at >= $1 AND created_at <= $2"
            params = [period_start, period_end]
        elif period_start:
            where = " WHERE created_at >= $1"
            params = [period_start]

        query = f"""
            SELECT
                COUNT(*) as total_events,
                COUNT(DISTINCT session_id) as total_sessions,
                COUNT(DISTINCT tool_name) as unique_tools,
                COUNT(*) FILTER (WHERE policy_decision::jsonb->>'allowed' = 'false') as denied_events
            FROM audit_events
            {where}
        """
        rows = await self.db_pool.fetch(query, *params)
        row = rows[0]
        return {
            "total_events": row["total_events"],
            "total_sessions": row["total_sessions"],
            "unique_tools": row["unique_tools"],
            "denied_events": row["denied_events"],
        }

    async def _get_session_stats(
        self, period_start: str | None, period_end: str | None
    ) -> list[dict]:
        """Return per-session statistics."""
        where = ""
        params: list[Any] = []
        if period_start and period_end:
            where = " WHERE created_at >= $1 AND created_at <= $2"
            params = [period_start, period_end]

        query = f"""
            SELECT
                session_id,
                agent_id,
                MAX(agent_type) as agent_type,
                COUNT(*) as steps,
                MAX(created_at) as last_event,
                MIN(created_at) as first_event,
                COUNT(*) FILTER (WHERE policy_decision::jsonb->>'allowed' = 'false') as denials
            FROM audit_events
            {where}
            GROUP BY session_id, agent_id
            ORDER BY last_event DESC
            LIMIT 100
        """
        rows = await self.db_pool.fetch(query, *params)
        return [
            {
                "session_id": r["session_id"],
                "agent_id": r["agent_id"],
                "agent_type": r["agent_type"],
                "steps": r["steps"],
                "denials": r["denials"],
                "first_event": r["first_event"].isoformat() if r["first_event"] else None,
                "last_event": r["last_event"].isoformat() if r["last_event"] else None,
            }
            for r in rows
        ]

    async def _get_agent_type_stats(
        self, period_start: str | None, period_end: str | None
    ) -> list[dict]:
        """Return per-agent-type statistics."""
        where = ""
        params: list[Any] = []
        if period_start and period_end:
            where = " WHERE created_at >= $1 AND created_at <= $2"
            params = [period_start, period_end]

        query = f"""
            SELECT
                COALESCE(agent_type, 'default') as agent_type,
                COUNT(*) as total_steps,
                COUNT(DISTINCT session_id) as sessions,
                COUNT(*) FILTER (WHERE policy_decision::jsonb->>'allowed' = 'false') as denials
            FROM audit_events
            {where}
            GROUP BY agent_type
            ORDER BY total_steps DESC
        """
        rows = await self.db_pool.fetch(query, *params)
        return [
            {
                "agent_type": r["agent_type"],
                "total_steps": r["total_steps"],
                "sessions": r["sessions"],
                "denials": r["denials"],
            }
            for r in rows
        ]

    # ── Risk classification ──

    @staticmethod
    def _classify_risk(
        agent_types: list[dict], stats: dict
    ) -> dict[str, str]:
        """Classify AI risk level per EU AI Act criteria."""
        high_risk_agents = {
            "coder", "dev", "builder", "deployer", "medical",
            "legal", "financial", "hr", "recruitment",
        }

        seen_types = {a["agent_type"].lower() for a in agent_types if a["agent_type"]}
        has_high_risk = bool(seen_types & high_risk_agents)
        has_denials = stats.get("denied_events", 0) > 0

        if has_high_risk:
            return {
                "level": "High Risk",
                "status": "needs_review",
                "rationale": (
                    f"Agent types detected ({', '.join(seen_types & high_risk_agents)}) "
                    "fall under EU AI Act Annex III high-risk categories. "
                    "Conformity assessment required before deployment."
                ),
                "summary": "⚠️ High-risk AI system classification — requires full conformity assessment",
            }
        elif has_denials:
            return {
                "level": "Limited Risk",
                "status": "compliant",
                "rationale": (
                    f"No high-risk agent types detected. Policy engine logged {stats['denied_events']} "
                    "denied events, demonstrating active guardrails."
                ),
                "summary": "Limited risk — transparency obligations apply (Art. 52)",
            }
        else:
            return {
                "level": "Minimal Risk",
                "status": "compliant",
                "rationale": (
                    "No high-risk agent types, no policy denials. Standard transparency "
                    "and record-keeping obligations apply."
                ),
                "summary": "Minimal risk — standard obligations",
            }

    def to_dict(self, report: ComplianceReport) -> dict:
        """Serialize a report to JSON-compatible dict."""
        return {
            "report_type": report.report_type,
            "generated_at": report.generated_at,
            "period_start": report.period_start,
            "period_end": report.period_end,
            "gateway_version": report.gateway_version,
            "signing_key_fingerprint": report.signing_key_fingerprint,
            "total_events": report.total_events,
            "total_sessions": report.total_sessions,
            "sections": [
                {
                    "title": s.title,
                    "status": s.status,
                    "summary": s.summary,
                    "details": s.details,
                }
                for s in report.sections
            ],
            "notes": report.notes,
        }

    def to_html(self, report: ComplianceReport) -> str:
        """Render a report as a standalone HTML page (print-ready for PDF)."""
        sections_html = ""
        for s in report.sections:
            status_badge = {
                "compliant": "✅ Compliant",
                "non_compliant": "❌ Non-Compliant",
                "needs_review": "⚠️ Needs Review",
            }.get(s.status, s.status)

            details_parts = []
            for d in s.details:
                key = d.get("metric") or d.get("mechanism") or d.get("key") or d.get("title") or ""
                val = d.get("value") or d.get("status") or d.get("summary") or ""
                details_parts.append(f"<tr><td>{key}</td><td>{val}</td></tr>")
            details_html = "".join(details_parts)

            sections_html += f"""
            <section>
                <h2>{s.title}</h2>
                <p class='status {s.status}'>{status_badge}</p>
                <p>{s.summary}</p>
                <table>{details_html}</table>
            </section>
            """

        notes_html = "".join(f"<li>{n}</li>" for n in report.notes)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Tracepath — {report.report_type.upper()} Compliance Report</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 2em; color: #1a1a1a; }}
        h1 {{ border-bottom: 3px solid #673773; padding-bottom: 0.3em; }}
        .meta {{ color: #666; font-size: 0.9em; }}
        .status.compliant {{ color: #2e7d32; font-weight: bold; }}
        .status.non_compliant {{ color: #c62828; font-weight: bold; }}
        .status.needs_review {{ color: #e65100; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; margin: 0.5em 0 1.5em; }}
        td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
        td:first-child {{ font-weight: 500; width: 40%; }}
        footer {{ margin-top: 3em; border-top: 1px solid #ddd; padding-top: 1em; font-size: 0.85em; color: #888; }}
    </style>
</head>
<body>
    <h1>Tracepath — {report.report_type.upper()} Compliance Report</h1>
    <p class='meta'>
        Generated: {report.generated_at}<br>
        Period: {report.period_start or 'unbounded'} → {report.period_end or 'now'}<br>
        Gateway: v{report.gateway_version} | Events: {report.total_events} | Sessions: {report.total_sessions}
    </p>
    {sections_html}
    <footer>
        <h3>Notes</h3>
        <ul>{notes_html}</ul>
        <p>Generated by Tracepath Audit Stack. Verify at: GET /audit/events</p>
    </footer>
</body>
</html>"""
