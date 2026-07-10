"""Semantic incident classifier using Google Gemini.

Refines threshold-based incident severity by analyzing the
semantic context of audit events — distinguishing true threats
from false positives (e.g., debugging loops vs. actual attacks).
"""

import asyncio
import json
import logging
import os
from typing import Optional

from .models import Incident, Severity

logger = logging.getLogger("tracepath.incident.gemini")

CLASSIFIER_PROMPT = """You are an AI audit incident classifier for Tracepath, an agent audit stack.

Your job: given a threshold-triggered incident, classify its REAL severity.

Context you receive:
- incident: the threshold-triggered alert (type, severity, session context)
- session_summary: what the agent has been doing in this session (tool usage, costs, denials)

Rules:
- "false_positive": the pattern looks benign (e.g., normal debugging, expected batch processing, testing)
- "info": genuinely interesting but not actionable
- "warning": needs attention but not urgent
- "critical": active threat, policy bypass attempt, data exfiltration risk

Return ONLY a JSON object with:
{
  "severity": "false_positive" | "info" | "warning" | "critical",
  "reasoning": "one sentence explaining the classification"
}
"""


class GeminiClassifier:
    """Refines incident severity using Gemini semantic analysis."""

    def __init__(self) -> None:
        self._client = None
        self._enabled = False
        self._model = "gemini-2.0-flash"
        self._cache: dict[str, dict] = {}  # deduplicate identical incident patterns

        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if api_key:
            try:
                from google import genai
                self._client = genai.Client(api_key=api_key)
                self._enabled = True
                logger.info("Gemini classifier enabled (model: %s)", self._model)
            except Exception as e:
                logger.warning("Gemini classifier init failed: %s — falling back to thresholds only", e)
        else:
            logger.info("Gemini classifier disabled (set GOOGLE_API_KEY to enable)")

    async def refine(self, incident: Incident, session_summary: str) -> Incident:
        """Refine an incident's severity. Returns the (possibly modified) incident."""
        if not self._enabled or not self._client:
            return incident

        # Deduplicate: same incident type + same session
        cache_key = f"{incident.incident_type.value}:{incident.session_id}"
        if cache_key in self._cache:
            logger.debug("Gemini cache hit for %s", cache_key)
            cached = self._cache[cache_key]
            incident.severity = Severity(cached["severity"])
            incident.context["gemini_reasoning"] = cached["reasoning"]
            incident.context["gemini_cached"] = True
            return incident

        prompt = json.dumps({
            "incident": {
                "type": incident.incident_type.value,
                "severity": incident.severity.value,
                "message": incident.message,
            },
            "session_summary": session_summary,
        })

        try:
            response = await asyncio.to_thread(
                lambda: self._client.models.generate_content(
                    model=self._model,
                    contents=f"{CLASSIFIER_PROMPT}\n\nInput:\n{prompt}",
                )
            )

            text = (response.text or "").strip()
            # Extract JSON from response (handle markdown code blocks)
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()

            result = json.loads(text)
            new_severity = result.get("severity", incident.severity.value)
            reasoning = result.get("reasoning", "no reasoning provided")

            # Update the incident
            old_severity = incident.severity.value
            incident.severity = Severity(new_severity)
            incident.context["gemini_reasoning"] = reasoning
            incident.context["gemini_original_severity"] = old_severity

            if new_severity != old_severity:
                logger.info(
                    "Gemini reclassified %s: %s → %s (%s)",
                    cache_key, old_severity, new_severity, reasoning,
                )

            # Cache the result
            self._cache[cache_key] = {"severity": new_severity, "reasoning": reasoning}

        except Exception as e:
            logger.warning("Gemini classification failed (non-fatal): %s", e)
            incident.context["gemini_error"] = str(e)

        return incident

    def build_session_summary(self, event_count: int, tool_counts: dict[str, int],
                               denied_count: int, cost_cents: int) -> str:
        """Build a human-readable session summary for Gemini context."""
        tools = ", ".join(f"{t}×{c}" for t, c in sorted(tool_counts.items(), key=lambda x: -x[1]))
        return (
            f"Session has {event_count} events. "
            f"Tools used: {tools}. "
            f"Policy denials: {denied_count}. "
            f"Estimated cost: {cost_cents} cents."
        )
