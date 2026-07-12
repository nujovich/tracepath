"""Tracepath Incident Service — real-time audit event monitoring.

Subscribes to NATS JetStream, evaluates every audit event through
detectors, emits incidents as structured logs, and serves them via
a simple HTTP API for the dashboard.
"""

import asyncio
import json
import logging
import os
import signal
import uuid
from datetime import datetime, timezone

import nats
from aiohttp import web
from nats.js.api import ConsumerConfig, StorageType, StreamConfig

from .detector import Detector
from .gemini_classifier import GeminiClassifier
from .models import AuditEvent

logger = logging.getLogger("tracepath.incident")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

STREAM_NAME = "AUDIT_EVENTS"
SUBJECT = "audit.events.>"
DURABLE_NAME = "incident-service"
INCIDENTS_FILE = os.environ.get("INCIDENTS_FILE", "/data/incidents.jsonl")

# ── Module-level Gemini reference (set in main) ──
_gemini: "GeminiClassifier | None" = None

# ── In-memory incident cache ──
_incidents: list[dict] = []
_MAX_INCIDENTS = 1000


def _persist_incident(incident_dict: dict) -> None:
    """Append incident to JSONL file and in-memory list."""
    _incidents.append(incident_dict)
    if len(_incidents) > _MAX_INCIDENTS:
        _incidents.pop(0)
    try:
        os.makedirs(os.path.dirname(INCIDENTS_FILE), exist_ok=True)
        with open(INCIDENTS_FILE, "a") as f:
            f.write(json.dumps(incident_dict) + "\n")
    except OSError as e:
        logger.error("failed to persist incident: %s", e)


def _load_incidents_from_file() -> None:
    """Load existing incidents from JSONL file on startup."""
    try:
        if os.path.exists(INCIDENTS_FILE):
            with open(INCIDENTS_FILE) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        _incidents.append(json.loads(line))
            _incidents[-_MAX_INCIDENTS:]  # keep last N
            logger.info("loaded %d incidents from %s", len(_incidents), INCIDENTS_FILE)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("could not load incidents file: %s", e)


# ── HTTP handlers ──

async def handle_incidents(request: web.Request) -> web.Response:
    """GET /api/incidents — return recent incidents."""
    limit = int(request.query.get("limit", "100"))
    session_id = request.query.get("session_id")
    severity = request.query.get("severity")

    filtered = _incidents
    if session_id:
        filtered = [i for i in filtered if i.get("session_id") == session_id]
    if severity:
        filtered = [i for i in filtered if i.get("severity") == severity]

    result = filtered[-limit:]  # most recent
    return web.json_response({"incidents": result, "total": len(result)})


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "tracepath-incident"})


async def handle_gemini_status(request: web.Request) -> web.Response:
    """GET /api/gemini/status — Gemini classifier status and recent reclassifications."""
    gemini = _gemini
    if gemini is None:
        return web.json_response({"enabled": False, "reason": "not initialized"})

    return web.json_response({
        "enabled": gemini._enabled,
        "model": gemini._model,
        "cache_size": len(gemini._cache),
        "cache_entries": [
            {"key": k, "severity": v["severity"], "reasoning": v["reasoning"]}
            for k, v in list(gemini._cache.items())[-20:]
        ],
    })


async def handle_reports(request: web.Request) -> web.Response:
    """GET /api/reports — list generated report files."""
    import glob
    reports_dir = "/data"
    files = sorted(glob.glob(f"{reports_dir}/*-report.html"), reverse=True)
    result = []
    for f in files:
        name = os.path.basename(f)
        stat = os.stat(f)
        result.append({
            "name": name,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })
    return web.json_response({"reports": result, "total": len(result)})


async def handle_report_file(request: web.Request) -> web.Response:
    """GET /api/reports/{name} — serve a specific report file."""
    name = request.match_info.get("name", "")
    path = os.path.join("/data", os.path.basename(name))
    if not os.path.isfile(path):
        return web.json_response({"error": "not found"}, status=404)
    return web.FileResponse(path)


async def handle_report_generate(request: web.Request) -> web.Response:
    """POST /api/reports/generate — generate a compliance report."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    report_type = body.get("type", "finra")
    if report_type not in ("finra", "eu-ai-act"):
        return web.json_response({"error": "invalid type"}, status=400)

    import asyncpg
    from .reports import ReportGenerator

    db_url = os.environ.get("DATABASE_URL", "postgres://tracepath:tracepath@localhost:5432/tracepath")
    pool = await asyncpg.create_pool(db_url)
    try:
        gen = ReportGenerator(pool)
        if report_type == "finra":
            report = await gen.generate_finra_report()
            filename = "finra-report.html"
        else:
            report = await gen.generate_eu_ai_act_report()
            filename = "eu-ai-act-report.html"

        html = gen.to_html(report)
        outpath = os.path.join("/data", filename)
        with open(outpath, "w") as f:
            f.write(html)
        return web.json_response({"ok": True, "file": filename, "events": report.total_events})
    finally:
        await pool.close()


# ── NATS consumer ──

async def ensure_stream(js):
    """Create JetStream stream if it doesn't exist."""
    try:
        await js.stream_info(STREAM_NAME)
        logger.info("JetStream stream '%s' already exists", STREAM_NAME)
    except nats.js.errors.NotFoundError:
        await js.add_stream(
            StreamConfig(
                name=STREAM_NAME,
                subjects=[SUBJECT],
                storage=StorageType.FILE,
                max_age=7 * 24 * 60 * 60,  # 7 days
                max_msgs=1_000_000,
            )
        )
        logger.info("JetStream stream '%s' created", STREAM_NAME)


async def process_event(detector: Detector, msg):
    """Parse an audit event from NATS, run detectors, log and store incidents."""
    await msg.ack()
    try:
        data = json.loads(msg.data)
        event = AuditEvent(**data)
    except Exception:
        logger.warning("unparseable audit event on subject %s", msg.subject)
        return

    incident = await detector.evaluate(event)
    if incident:
        incident_dict = {
            "id": incident.id,
            "type": incident.incident_type.value,
            "severity": incident.severity.value,
            "session_id": incident.session_id,
            "agent_id": incident.agent_id,
            "message": incident.message,
            "context": incident.context,
            "detected_at": incident.detected_at.isoformat()
            if isinstance(incident.detected_at, datetime)
            else incident.detected_at,
        }
        payload = json.dumps(incident_dict)
        logger.warning("INCIDENT|%s", payload)
        _persist_incident(incident_dict)


async def run_nats_consumer(nc, js, detector):
    """Run NATS pull consumer loop."""
    consumer_config = ConsumerConfig(
        durable_name=DURABLE_NAME,
        deliver_policy="all",
        ack_policy="explicit",
    )
    await js.add_consumer(STREAM_NAME, consumer_config)

    sub = await js.pull_subscribe(
        subject=SUBJECT,
        durable=DURABLE_NAME,
        stream=STREAM_NAME,
    )
    logger.info("incident service subscribed to %s (stream: %s)", SUBJECT, STREAM_NAME)

    while True:
        try:
            msgs = await sub.fetch(batch=10, timeout=5)
            for msg in msgs:
                await process_event(detector, msg)
        except asyncio.TimeoutError:
            continue
        except nats.errors.TimeoutError:
            continue


# ── Main ──

async def main():
    nats_url = os.environ.get("NATS_URL", "nats://localhost:4222")
    http_port = int(os.environ.get("INCIDENT_HTTP_PORT", "9004"))

    # Load persisted incidents
    _load_incidents_from_file()

    # Connect NATS
    nc = await nats.connect(nats_url)
    js = nc.jetstream()
    await ensure_stream(js)

    gemini = GeminiClassifier()
    detector = Detector(gemini=gemini)
    global _gemini
    _gemini = gemini

    # Start HTTP server
    app = web.Application()
    app.router.add_get("/api/incidents", handle_incidents)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/api/reports", handle_reports)
    app.router.add_get("/api/reports/{name}", handle_report_file)
    app.router.add_post("/api/reports/generate", handle_report_generate)
    app.router.add_get("/api/gemini/status", handle_gemini_status)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", http_port)
    await site.start()
    logger.info("incident HTTP API listening on 0.0.0.0:%d", http_port)

    # Graceful shutdown
    shutdown = asyncio.Event()

    def _signal_handler():
        logger.info("shutdown signal received")
        shutdown.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    # Run NATS consumer as background task
    consumer_task = asyncio.create_task(run_nats_consumer(nc, js, detector))

    try:
        await shutdown.wait()
    finally:
        consumer_task.cancel()
        await nc.drain()
        await runner.cleanup()
        logger.info("incident service stopped")


if __name__ == "__main__":
    asyncio.run(main())
