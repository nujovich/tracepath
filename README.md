# Tracepath

**Auditable multi-agent middleware.** Make any AI agent framework (LangChain, CrewAI, AutoGen, LangGraph) compliant with EU AI Act, FINRA, and SOC2.

> "Can you audit what your agents did yesterday?"
> Tracepath answers that with immutable logs, policy gates, and compliance reports.

---

## Quickstart

### Prerequisites

- Docker + Docker Compose
- Python 3.10+ (for SDK)
- Rust 1.80+ (for gateway development)

### 1. Start the stack

```bash
cd docker
AUDIT_SIGNING_KEY=$(openssl rand -hex 32) docker compose up -d
```

### 2. Open the dashboard

```
http://localhost:3000
```

Three tabs: **Audit** (event trail), **Incidents** (real-time detection), **Policies** (OPA rules).

### 3. Record your first audit step

```bash
curl -X POST http://localhost:9001/audit/step \
  -H "Content-Type: application/json" \
  -d '{
    "session_id":"demo","agent_id":"test","agent_type":"coder",
    "step_number":1,"tool_name":"read_file",
    "tool_input":{"path":"/tmp/test"},"tool_output":{"lines":10},
    "timestamp":"2026-07-11T12:00:00Z"
  }'
# → {"status":"recorded","signature":"<ed25519>","policy_decision":{"allowed":true,"denials":[]}}
```

### 4. Use the Python SDK

```bash
cd sdk/python
pip install --no-build-isolation -e ".[dev]"
```

```python
from tracepath_sdk import AsyncAuditClient, audit

client = AsyncAuditClient(agent_type="coder")

@audit(client)
async def read_file(path: str) -> dict:
    return {"lines": 42}

async with client:
    result = await read_file(path="/tmp/x")
    # → POST /audit/step sent automatically with Ed25519 signature
    events = await client.query_events(limit=10)
    incidents = await client.get_incidents()
```

---

## Phase 2 — Incident Response (current)

| Feature | Status |
|---|---|
| NATS JetStream real-time event streaming | ✅ |
| Rego-based incident detection (denial spike, budget exceeded, suspicious pattern, rate limit breach) | ✅ |
| Incident API (`GET /incidents`) | ✅ |
| Dashboard (React + Tailwind + shadcn/ui) — Audit / Incidents / Policies | ✅ |
| Gemini semantic classifier (severity refinement) | ✅ |
| FINRA + EU AI Act PDF reports | ✅ |

### Detection rules

| Incident type | Severity | Trigger |
|---|---|---|
| `denial_spike` | CRITICAL | >5 policy denials in a single session |
| `budget_exceeded` | WARNING | >1000 cost cents accumulated per session |
| `suspicious_pattern` | WARNING | ≥10 consecutive calls to the same tool |
| `rate_limit_breach` | WARNING | >60 calls/minute per session |

---

## Phase 1 — MVP (foundation)

| Feature | Status |
|---|---|
| Ed25519 signing per event | ✅ |
| OPA WASM policy engine (allowlist, budget, rate limit) | ✅ |
| PostgreSQL audit log with query API | ✅ |
| WORM storage (MinIO S3 Object Lock, 365d retention) | ✅ |
| Python SDK (async + sync, typed, `@audit` decorator) | ✅ |
| TypeScript SDK (typed, native fetch) | ✅ |
| Java SDK (java.net.http, Gson) | ✅ |
| Docker Compose (gateway + postgres + nats + minio + dashboard) | ✅ |

---

## Architecture

```
Agent (LangChain / CrewAI / custom)
    │
    ▼
Tracepath SDK (Python / TypeScript / Java)
    │
    ▼
Audit Gateway (Rust + actix-web, :9001)
    ├─ Ed25519 signing ───────────────► PostgreSQL (audit log)
    ├─ OPA WASM policy engine ────────► policy decision (allowed / denied)
    ├─ Allowed events ────────────────► MinIO S3 (WORM, Object Lock)
    │
    ├─ NATS JetStream ────────────────► Incident Detector (Python)
    │                                      ├─ Denial spike
    │                                      ├─ Budget exceeded
    │                                      ├─ Suspicious pattern
    │                                      └─ Rate limit breach
    │
    └─ API ───────────────────────────► Dashboard (React, :3000)
                                           ├─ Audit trail
                                           ├─ Incident timeline
                                           └─ Policy viewer
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Gateway health |
| `GET` | `/health/policy` | Policy engine smoke test |
| `POST` | `/audit/step` | Record an audit step (signed + policy-checked) |
| `GET` | `/audit/events` | Query audit events (filtered: `session_id`, `agent_id`, `tool_name`; paginated) |
| `GET` | `/incidents` | Query incidents detected by the incident service |

---

## Python SDK

```python
from tracepath_sdk import AsyncAuditClient, SyncAuditClient, audit, PolicyDenied

# ── Async client ──────────────────────────────
client = AsyncAuditClient(agent_type="coder")

async with client:
    # Record a tool call
    resp = await client.record_step("read_file", {"path": "/x"}, {"lines": 10})
    assert resp.policy_decision.allowed

    # Query the audit trail
    events = await client.query_events(session_id=client.session_id)
    print(f"{events.count} events recorded")

    # Check for incidents
    for inc in await client.get_incidents():
        print(f"[{inc.severity}] {inc.type}: {inc.message}")

# ── Decorator (auto-audits every call) ────────
@audit(client)
async def web_search(query: str) -> list:
    return ["result1", "result2"]

# ── Sync client ───────────────────────────────
with SyncAuditClient(agent_type="researcher") as sync:
    sync.record_step("web_search", {"q": "x"}, {"results": 3})
    print(sync.health())
```

### SDK features

- `AsyncAuditClient` — full async (aiohttp/httpx), context manager
- `SyncAuditClient` — thin sync wrapper for scripts and non-async frameworks
- `@audit` decorator — wraps any async/sync function; tool name = function name
- `PolicyDenied` exception — raised on deny with `.denials` list and `.signature`
- Pydantic models — `AuditResponse`, `AuditQueryResult`, `Incident`, `PolicyDecision`
- `query_events()` — session, agent, and tool filters with pagination
- `get_incidents()` — fetch real-time incident timeline
- 14 tests (7 unit + 7 integration) — all passing

---

## Policies

Located in `policies/rules/`. Compile with:

```bash
opa build -t wasm -e tracepath/main/decision -o policies/bundle.tar.gz policies/rules/
```

Three base policies:

| Policy | Rule |
|---|---|
| **Allowlist** | Reject tools not in the agent type's allowed set |
| **Budget** | Reject if cumulative tool cost exceeds session budget |
| **Rate limit** | Reject if >60 calls/minute per session |

Agent type allowlists:

| Agent type | Allowed tools |
|---|---|
| `coder` | `read_file`, `write_file`, `terminal`, `search_files`, `patch`, `execute_code` |
| `researcher` | `web_search`, `web_extract`, `browser_navigate`, `browser_snapshot` |
| `assistant` | `read_file`, `web_search`, `web_extract`, `terminal` |
| `default` | `read_file`, `web_search`, `web_extract` |

---

## Observability (OpenTelemetry)

The gateway exports traces to **LangFuse** via OTLP (HTTP). Disabled by default — enable with env vars:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://cloud.langfuse.com/api/public/otel"
export OTEL_SERVICE_NAME="tracepath-gateway"
export LANGFUSE_PUBLIC_KEY="pk-lf-..."
export LANGFUSE_SECRET_KEY="sk-lf-..."
```

When unset, the gateway logs to stdout (JSON) with zero OTLP overhead.

---

## License

Apache 2.0
