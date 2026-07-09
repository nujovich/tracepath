# Tracepath

**Auditable multi-step AI agent middleware.** Make any agent framework (LangGraph, CrewAI, AutoGen) compliant with EU AI Act, FINRA, and SOC2.

## Quickstart

### Prerequisites
- Rust 1.80+
- Docker (optional, for PostgreSQL)

### 1. Generate a signing key
```bash
openssl rand -hex 32 > .env
echo "AUDIT_SIGNING_KEY=$(cat .env)" >> .env
```

### 2. Run the gateway
```bash
source .env
cargo run --release
```

### 3. Test it
```bash
curl http://localhost:9001/health
# {"status":"ok","service":"tracepath-gateway"}

curl -X POST http://localhost:9001/audit/step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"demo","agent_id":"test","step_number":1,"tool_name":"search","tool_input":{"q":"test"},"tool_output":{"results":[]},"timestamp":"2026-07-09T00:00:00Z"}'
# {"status":"recorded","signature":"..."}
```

### 4. Use the Python SDK
```bash
cd sdk/python && uv sync
```
```python
from tracepath_sdk import AuditClient

client = AuditClient(agent_id="my-agent")
result = await client.record_step("search", {"q": "test"}, {"results": []})
print(result)  # {"status": "recorded", "signature": "..."}
```

## Architecture

```
Agent (any framework)
    ↓
Tracepath SDK (Python/TS/Java)
    ↓
Audit Gateway (Rust, :9001)  ←  Ed25519 signing
    ↓
PostgreSQL + S3 WORM
    ↓
Dashboard (React, coming soon)
```

## License

Apache 2.0