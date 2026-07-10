# Tracepath

**Auditable multi-step AI agent middleware.** Make any agent framework (LangGraph, CrewAI, AutoGen) compliant with EU AI Act, FINRA, and SOC2.

> "¿Podés auditar lo que hicieron tus agentes ayer?"

## Quickstart

### Prerequisites
- Rust 1.80+
- Docker + Docker Compose (for PostgreSQL, MinIO)

### 1. Start the stack
```bash
cd docker
AUDIT_SIGNING_KEY=$(openssl rand -hex 32) docker compose up -d
```

### 2. Test it
```bash
# Health check
curl http://localhost:9001/health
# → {"status":"ok","service":"tracepath-gateway","version":"0.2.0"}

# Policy engine smoke test
curl http://localhost:9001/health/policy
# → {"policy_engine":"ok","smoke_test":{"allowed":true,"denials":[]}}

# Record an audit step
curl -X POST http://localhost:9001/audit/step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"demo","agent_id":"test","step_number":1,"tool_name":"read_file","tool_input":{"path":"/tmp/test"},"tool_output":{"lines":10},"timestamp":"2026-07-09T00:00:00Z"}'
# → {"status":"recorded","signature":"<ed25519-sig>","policy_decision":{"allowed":true,"denials":[]}}

# Query events
curl "http://localhost:9001/audit/events?session_id=demo&limit=10"
```

### 3. Use the SDKs

**Python**
```bash
cd sdk/python && uv sync
```
```python
from tracepath_sdk import AuditClient

client = AuditClient(session_id="demo", agent_id="my-agent", agent_type="coder")
result = await client.record_step("read_file", {"path": "/tmp/x"}, {"lines": 10})
print(result.signature)  # ed25519 base64
```

**TypeScript**
```bash
cd sdk/typescript && npm install && npm run build
```
```typescript
import { AuditClient } from "@tracepath/sdk";

const client = new AuditClient({ sessionId: "demo", agentId: "my-agent" });
const result = await client.recordStep("web_search", { q: "test" }, { results: [] });
console.log(result.policy_decision?.allowed); // true | false
```

**Java**
```java
import com.tracepath.sdk.AuditClient;

var client = new AuditClient("demo", "my-agent");
var resp = client.recordStep("terminal", Map.of("cmd", "ls"), Map.of("exit", 0));
System.out.println(resp.status); // "recorded" | "denied"
```

## Features (Fase 1 — MVP)

| Feature | Status |
|---|---|
| Ed25519 signing per event | ✅ |
| OPA WASM policy engine (budget, allowlist, rate limit) | ✅ |
| PostgreSQL audit log with query API | ✅ |
| WORM storage (MinIO S3 Object Lock, 365d retention) | ✅ |
| Python SDK (typed, async) | ✅ |
| TypeScript SDK (typed, native fetch) | ✅ |
| Java SDK (java.net.http, Gson) | ✅ |
| Docker Compose (gateway + postgres + minio) | ✅ |

## Architecture

```
Agent (any framework)
    ↓
Tracepath SDK (Python / TypeScript / Java)
    ↓
Audit Gateway (Rust, :9001)
    ├→ Ed25519 signing
    ├→ OPA WASM policy evaluation
    ├→ PostgreSQL (queryable audit log)
    └→ MinIO S3 (WORM, Object Lock)
    ↓
Dashboard (React, Fase 2)
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Gateway health |
| `GET` | `/health/policy` | Policy engine smoke test |
| `POST` | `/audit/step` | Record an audit step (signed + policy-checked) |
| `GET` | `/audit/events` | Query audit events (filtered, paginated) |

## Observability (OpenTelemetry)

The gateway exports traces and spans to **LangFuse** via OTLP (HTTP). Disabled by default — enable with env vars:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://cloud.langfuse.com/api/public/otel"
export OTEL_SERVICE_NAME="tracepath-gateway"
export LANGFUSE_PUBLIC_KEY="pk-lf-..."
export LANGFUSE_SECRET_KEY="sk-lf-..."
```

Alternative: set `LANGFUSE_OTLP_ENDPOINT` instead of `OTEL_EXPORTER_OTLP_ENDPOINT` for self-hosted LangFuse.

When unset, the gateway logs to stdout (JSON) with zero overhead from OTLP.

## Policies

Located in `policies/rules/`. Compile with:

```bash
opa build -t wasm -e tracepath/main/decision -o policies/bundle.tar.gz policies/rules/
```

Three base policies:
- **Budget** — reject if cumulative tool cost exceeds session budget
- **Allowlist** — reject tools not in the agent type's allowed set
- **Rate limit** — reject if >60 calls/minute per session

## License

Apache 2.0