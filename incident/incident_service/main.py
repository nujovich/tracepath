"""Tracepath Incident Service — real-time audit event monitoring.

Subscribes to NATS JetStream, evaluates every audit event through
detectors, and emits incidents as structured logs.
"""

import asyncio
import json
import logging
import os
import signal
import uuid

import nats
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
    """Parse an audit event from NATS, run detectors, log incidents."""
    await msg.ack()
    try:
        data = json.loads(msg.data)
        event = AuditEvent(**data)
    except Exception:
        logger.warning("unparseable audit event on subject %s", msg.subject)
        return

    incident = await detector.evaluate(event)
    if incident:
        payload = json.dumps(
            {
                "id": incident.id,
                "type": incident.incident_type.value,
                "severity": incident.severity.value,
                "session_id": incident.session_id,
                "agent_id": incident.agent_id,
                "message": incident.message,
                "context": incident.context,
                "detected_at": incident.detected_at,
            }
        )
        logger.warning("INCIDENT|%s", payload)


async def main():
    nats_url = os.environ.get("NATS_URL", "nats://localhost:4222")
    nc = await nats.connect(nats_url)
    js = nc.jetstream()

    await ensure_stream(js)

    gemini = GeminiClassifier()
    detector = Detector(gemini=gemini)

    # Subscribe with durable consumer for at-least-once delivery
    consumer_config = ConsumerConfig(
        durable_name="incident-service",
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

    # Graceful shutdown
    shutdown = asyncio.Event()

    def _signal_handler():
        logger.info("shutdown signal received")
        shutdown.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    try:
        while not shutdown.is_set():
            try:
                msgs = await sub.fetch(batch=10, timeout=5)
                for msg in msgs:
                    await process_event(detector, msg)
            except asyncio.TimeoutError:
                continue
            except nats.errors.TimeoutError:
                continue
    finally:
        await nc.drain()
        logger.info("incident service stopped")


if __name__ == "__main__":
    asyncio.run(main())