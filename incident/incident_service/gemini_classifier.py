"""Semantic incident classifier using Gemini via OpenRouter.

Refines threshold-based incident severity by analyzing the
semantic context of audit events — distinguishing true threats
from false positives (e.g., debugging loops vs. actual attacks).

Supports both Google AI native API and OpenRouter as backends.
"""

import asyncio
import json
import logging
import os
from typing import Optional

import httpx

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
        self._client: Optional[httpx.AsyncClient] = None
        self._enabled = False
        self._backend: str = "none"  # "google" | "openrouter" | "none"
        self._model = "gemini-2.0-flash"
        self._cache: dict[str, dict] = {}
        self._cache_file = os.environ.get("GEMINI_CACHE_FILE", "/data/gemini-cache.json")

        # ── Backend selection ──
        google_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        openrouter_key = os.environ.get("OPENROUTER_API_KEY")

        if openrouter_key:
            self._setup_openrouter(openrouter_key)
        elif google_key:
            self._setup_google(google_key)
        else:
            logger.info(
                "Gemini classifier disabled "
                "(set OPENROUTER_API_KEY or GOOGLE_API_KEY to enable)"
            )

    def _setup_openrouter(self, api_key: str) -> None:
        self._backend = "openrouter"
        self._model = os.environ.get(
            "OPENROUTER_MODEL", "google/gemini-2.0-flash-001"
        )
        self._client = httpx.AsyncClient(
            base_url="https://openrouter.ai/api/v1/",
            headers={
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://tracepath.dev",
                "X-Title": "Tracepath",
            },
            timeout=30.0,
        )
        self._enabled = True
        logger.info("Gemini classifier enabled via OpenRouter (model: %s)", self._model)
        self._load_cache()

    def _setup_google(self, api_key: str) -> None:
        try:
            from google import genai

            self._backend = "google"
            self._client = genai.Client(api_key=api_key)  # type: ignore[assignment]
            self._enabled = True
            logger.info("Gemini classifier enabled via Google AI (model: %s)", self._model)
            self._load_cache()
        except Exception as e:
            logger.warning(
                "Gemini classifier init failed: %s — falling back to thresholds only", e
            )

    async def _call_openrouter(self, prompt: str) -> str:
        """Call Gemini via OpenRouter chat completions API."""
        assert self._client is not None
        resp = await self._client.post(
            "chat/completions",
            json={
                "model": self._model,
                "messages": [
                    {"role": "system", "content": CLASSIFIER_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.0,
                "max_tokens": 200,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()

    async def _call_google(self, prompt: str) -> str:
        """Call Gemini via Google AI native SDK."""
        assert self._client is not None
        response = await asyncio.to_thread(
            lambda: self._client.models.generate_content(  # type: ignore[union-attr]
                model=self._model,
                contents=f"{CLASSIFIER_PROMPT}\n\nInput:\n{prompt}",
            )
        )
        return (response.text or "").strip()

    async def refine(self, incident: Incident, session_summary: str) -> Incident:
        """Refine an incident's severity. Returns the (possibly modified) incident."""
        logger.info("Gemini refine called: enabled=%s type=%s session=%s", self._enabled, incident.incident_type.value, incident.session_id)
        if not self._enabled:
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
            if self._backend == "openrouter":
                text = await self._call_openrouter(prompt)
            else:
                text = await self._call_google(prompt)

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
            self._cache[cache_key] = {
                "severity": new_severity,
                "reasoning": reasoning,
                "backend": self._backend,
            }
            self._save_cache()

        except Exception as e:
            logger.warning("Gemini classification failed (non-fatal): %s", e)
            incident.context["gemini_error"] = str(e)

            # Cache the error too so the dashboard shows it
            self._cache[cache_key] = {
                "severity": "error",
                "reasoning": f"Gemini API ({self._backend}): {e}",
            }
            self._save_cache()

        return incident

    def build_session_summary(
        self,
        event_count: int,
        tool_counts: dict[str, int],
        denied_count: int,
        cost_cents: int,
    ) -> str:
        """Build a human-readable session summary for Gemini context."""
        tools = ", ".join(
            f"{t}×{c}" for t, c in sorted(tool_counts.items(), key=lambda x: -x[1])
        )
        return (
            f"Session has {event_count} events. "
            f"Tools used: {tools}. "
            f"Policy denials: {denied_count}. "
            f"Estimated cost: {cost_cents} cents."
        )

    def _load_cache(self) -> None:
        """Load persisted Gemini cache from disk."""
        try:
            if os.path.isfile(self._cache_file):
                with open(self._cache_file) as f:
                    self._cache = json.load(f)
                logger.info("Gemini cache loaded: %d entries", len(self._cache))
        except Exception:
            logger.debug("No Gemini cache file found (first run)")

    def _save_cache(self) -> None:
        """Persist Gemini cache to disk."""
        try:
            os.makedirs(os.path.dirname(self._cache_file), exist_ok=True)
            with open(self._cache_file, "w") as f:
                json.dump(self._cache, f)
        except Exception as e:
            logger.warning("Failed to save Gemini cache: %s", e)