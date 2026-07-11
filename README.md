# Tracepath

**Auditable multi-agent middleware for AI governance.** Make any agent framework (LangChain, CrewAI, AutoGen, LangGraph) compliant with EU AI Act, FINRA, and SOC2 — in a single `docker compose up`.

> *"Can you audit what your agents did yesterday?"*
> Tracepath answers that with immutable Ed25519-signed logs, real-time policy enforcement, and a compliance dashboard.

---

## Table of Contents

- [Quickstart](#quickstart)
- [What Tracepath Does](#what-tracepath-does)
- [Architecture](#architecture)
- [Phase 1 — Foundation (MVP)](#phase-1--foundation-mvp)
- [Phase 2 — Incident Response](#phase-2--incident-response)
- [Phase 3 — Policy Evolution](#phase-3--policy-evolution)
- [API Reference](#api-reference)
- [Python SDK](#python-sdk)
- [Policy Engine](#policy-engine)
- [Observability](#observability)
- [What's Next](#whats-next)
- [License](#license)

---

## Quickstart

### Prerequisites

- Docker + Docker Compose
- Python 3.10+ (for SDK)
- Rust 1.80+ (for gateway development)

### 1. Start the stack

```bash
git clone https://github.com/nujovich/tracepath.git
cd tracepath/docker
AUDIT_SIGNING_KEY=$(openssl rand -hex 32) docker compose up -d
```

### 2. Open the dashboard

```
http://localhost:3000
```

Three tabs: **Audit** (event trail), **Incidents** (real-time detection), **Policies** (OPA versioning).

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

## What Tracepath Does

Tracepath sits between your AI agent and the tools it calls. Every tool invocation is intercepted, signed, checked against policy, and stored in an immutable audit trail. A real-time incident detector watches for anomalies — denial spikes, budget overruns, suspicious patterns, and rate limit breaches — and surfaces them in a dashboard.

| Capability | How it works |
|---|---|
| **Sign every call** | Ed25519 signature per event → cryptographic non-repudiation |
| **Enforce policy** | OPA WASM engine evaluates allowlists, budgets, rate limits in <1ms |
| **Immutable audit log** | PostgreSQL (queryable) + MinIO S3 Object Lock (WORM, 365-day retention) |
| **Detect incidents** | NATS JetStream → real-time detector → dashboard alerts |
| **Version policies** | Git-based policy versioning with diff, rollback, and replay |
| **Multi-SDK** | Python (async + sync, `@audit` decorator), TypeScript, Java |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Agent (LangChain / CrewAI / custom)                     │
│     │                                                    │
│     ▼                                                    │
│  Tracepath SDK (Python / TypeScript / Java)              │
│     │                                                    │
│     ▼                                                    │
│  Audit Gateway (Rust + actix-web, :9001)                 │
│     ├─ Ed25519 signing ───────────────► PostgreSQL       │
│     ├─ OPA WASM policy engine ────────► allow / deny     │
│     ├─ Allowed events ────────────────► MinIO S3 (WORM)  │
│     │                                                    │
│     ├─ NATS JetStream ────────────────► Incident Detector│
│     │                                      ├─ Denial spike│
│     │                                      ├─ Budget      │
│     │                                      ├─ Suspicious  │
│     │                                      └─ Rate limit  │
│     │                                                    │
│     ├─ Proxy ─────────────────────────► Policy API (:9003)│
│     │                                      ├─ Versions   │
│     │                                      ├─ Diff       │
│     │                                      └─ Rollback   │
│     │                                                    │
│     └─ API ───────────────────────────► Dashboard (:3000)│
│                                            ├─ Audit trail│
│                                            ├─ Incidents  │
│                                            └─ Policies   │
└─────────────────────────────────────────────────────────┘
```

---

## Phase 1 — Foundation (MVP)

All four building blocks of auditable AI.

| Feature | Status |
|---|---|
| Ed25519 signing per event | ✅ |
| OPA WASM policy engine (allowlist, budget, rate limit) | ✅ |
| PostgreSQL audit log with query API | ✅ |
| WORM storage (MinIO S3 Object Lock, 365-day retention) | ✅ |
| Python SDK (async + sync, typed, `@audit` decorator) | ✅ |
| TypeScript SDK (typed, native fetch) | ✅ |
| Java SDK (java.net.http, Gson) | ✅ |
| Docker Compose (gateway + postgres + nats + minio + dashboard) | ✅ |

---

## Phase 2 — Incident Response

Real-time anomaly detection with NATS JetStream streaming.

| Detector | Trigger | Severity |
|---|---|---|
| **Denial spike** | >5 policy denials in a single session | CRITICAL |
| **Budget exceeded** | >1000 cost cents accumulated per session | WARNING |
| **Suspicious pattern** | ≥10 consecutive calls to the same tool | WARNING |
| **Rate limit breach** | >60 calls/minute per session | WARNING |

![Incidents Dashboard — Rate Limit Breach](docs/screenshots/incidents-rate-limit.png)

### Detection pipeline

```
Audit event → Gateway → NATS JetStream → Incident Detector (Python)
                                              │
                                              ├─ Threshold pass (Rego-like rules)
                                              ├─ Gemini refinement (optional semantic pass)
                                              └─ Incident persisted → Dashboard API
```

---

## Phase 3 — Policy Evolution

Git-based policy lifecycle management — version, diff, rollback, and replay.

![Policy Version History](docs/screenshots/policies-version-history.png)

| Feature | Description |
|---|---|
| **Version history** | Every policy change is a git commit with author, message, and changed files |
| **Visual diff** | Side-by-side unified diff with color-coded additions/deletions |
| **Rollback** | One-click restore to any previous policy version |
| **Replay engine** | Replay historical audit events against a selected policy version to answer: *"What would have happened if this policy was active then?"* |
| **HTTP API** | `GET /versions`, `GET /diff`, `GET /content`, `POST /rollback` |
| **CLI** | `python3 -m policy_engine.cli versions|diff|rollback|replay` |

---

## API Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Gateway health |
| `GET` | `/health/policy` | OPA policy engine smoke test |
| `POST` | `/audit/step` | Record an audit step (signed + policy-checked) |
| `GET` | `/audit/events` | Query audit events (filtered: `session_id`, `agent_id`, `tool_name`; paginated) |
| `GET` | `/incidents` | Query incidents detected by the incident service |
| `GET` | `/policies/versions` | List policy versions (git history) |
| `GET` | `/policies/diff?old=<hash>&new=<hash>` | Unified diff between two policy versions |
| `GET` | `/policies/content?hash=<hash>&file=<name>` | Get policy file content at a specific version |
| `POST` | `/policies/rollback` | Rollback to a previous policy version |

---

## Python SDK

```python
from tracepath_sdk import AsyncAuditClient, SyncAuditClient, audit, PolicyDenied

# ── Async client with decorator ──────────────────
client = AsyncAuditClient(agent_type="coder")

@audit(client)
async def read_file(path: str) -> dict:
    return {"lines": 42}

async with client:
    # Auto-audited call
    result = await read_file(path="/tmp/x")

    # Manual audit
    resp = await client.record_step("terminal", {"cmd": "ls"}, {"exit": 0})

    # Query the audit trail
    events = await client.query_events(session_id=client.session_id)
    print(f"{events.count} events recorded")

    # Check for incidents
    for inc in await client.get_incidents():
        print(f"[{inc.severity}] {inc.type}: {inc.message}")

# ── Sync client ──────────────────────────────────
with SyncAuditClient(agent_type="researcher") as sync:
    sync.record_step("web_search", {"q": "test"}, {"results": 3})
    print(sync.health())
```

### SDK features

| Feature | API |
|---|---|
| Async client | `AsyncAuditClient` with `async with` context manager |
| Sync client | `SyncAuditClient` thin wrapper for scripts |
| `@audit` decorator | Wraps any async/sync function; tool name = function name |
| Policy denied detection | `PolicyDenied` exception with `.denials` list and `.signature` |
| Audit trail query | `query_events(session_id, agent_id, tool_name, limit, offset)` |
| Incident timeline | `get_incidents(limit)` |
| Pydantic models | `AuditResponse`, `AuditQueryResult`, `Incident`, `PolicyDecision` |
| Tests | 14 tests (7 unit + 7 integration) |

---

## Policy Engine

Three base policies, compiled to OPA WASM and evaluated at the gateway:

| Policy | Rule |
|---|---|
| **Allowlist** | Reject tools not in the agent type's allowed set |
| **Budget** | Reject if cumulative tool cost exceeds session budget |
| **Rate limit** | Reject if >60 calls/minute per session |

### Agent type allowlists

| Agent type | Allowed tools |
|---|---|
| `coder` | `read_file`, `write_file`, `terminal`, `search_files`, `patch`, `execute_code` |
| `researcher` | `web_search`, `web_extract`, `browser_navigate`, `browser_snapshot` |
| `assistant` | `read_file`, `web_search`, `web_extract`, `terminal` |
| `default` | `read_file`, `web_search`, `web_extract` |

### Recompiling policies

```bash
cd policies
opa build -t wasm -e tracepath/main/decision -o bundle.tar.gz rules/
# Restart gateway to load the new bundle
```

---

## Observability

The gateway exports traces to **LangFuse** via OTLP (HTTP). Disabled by default — enable with:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://cloud.langfuse.com/api/public/otel"
export OTEL_SERVICE_NAME="tracepath-gateway"
export LANGFUSE_PUBLIC_KEY="pk-lf-..."
export LANGFUSE_SECRET_KEY="sk-lf-..."
```

When unset, the gateway logs to stdout (JSON) with zero OTLP overhead.

---

## What's Next

| Item | Status |
|---|---|
| Rollback short-hash bug | 🔧 Fix committed, needs Docker rebuild |
| Replay engine end-to-end | 📋 Code complete, needs DB connection test |
| Gemini semantic classifier | 📋 Code complete, needs `GOOGLE_API_KEY` |
| FINRA + EU AI Act PDF reports | 📋 Code complete, needs CLI trigger test |
| TypeScript SDK parity | 📋 Port `@audit` decorator + `query_events` + `get_incidents` |
| Helm chart (Phase 4) | 📋 Kubernetes deployment |

---

## License

Apache 2.0