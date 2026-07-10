# Tracepath Onboarding Guide

Welcome. This guide gets your first AI agent auditable in under 10 minutes.

---

## 1. Prerequisites

- Kubernetes cluster (any: EKS, GKE, AKS, kind, minikube)
- Helm 3.8+
- `openssl` (for signing key generation)

---

## 2. Generate your signing key

```bash
export AUDIT_SIGNING_KEY=$(openssl rand -hex 32)
echo "Save this: $AUDIT_SIGNING_KEY"  # ⚠️ store securely
```

---

## 3. Install Tracepath

```bash
helm repo add tracepath https://charts.tracepath.dev
helm install tracepath tracepath/tracepath \
  --set gateway.signingKey="$AUDIT_SIGNING_KEY"
```

Wait ~60 seconds for all pods to start:

```bash
kubectl get pods -l app.kubernetes.io/name=tracepath
```

---

## 4. Verify the gateway

```bash
kubectl port-forward svc/tracepath-gateway 9001:9001

# Health check
curl http://localhost:9001/health
# → {"status":"ok","service":"tracepath-gateway","version":"0.3.0"}

# Policy engine smoke test
curl http://localhost:9001/health/policy
# → {"policy_engine":"ok","smoke_test":{"allowed":true,"denials":[]}}
```

---

## 5. Instrument your agent

Choose your SDK:

**Python**
```bash
pip install tracepath-sdk
```
```python
from tracepath_sdk import AuditClient

client = AuditClient(
    gateway_url="http://localhost:9001",
    session_id="my-first-session",
    agent_id="my-agent",
    agent_type="coder"
)

# Wrap every tool call
result = await client.record_step(
    tool_name="read_file",
    tool_input={"path": "/tmp/example"},
    tool_output={"lines": 42}
)
print(f"Audited: {result.signature[:16]}...")
print(f"Policy: {'allowed' if result.policy_decision.allowed else 'denied'}")
```

**TypeScript**
```bash
npm install @tracepath/sdk
```
```typescript
import { AuditClient } from "@tracepath/sdk";

const client = new AuditClient({
  gatewayUrl: "http://localhost:9001",
  sessionId: "my-first-session",
  agentId: "my-agent",
  agentType: "coder",
});

const result = await client.recordStep(
  "web_search",
  { q: "kubernetes networking" },
  { results: ["..."] }
);
```

**Java**
```xml
<dependency>
  <groupId>com.tracepath</groupId>
  <artifactId>tracepath-sdk</artifactId>
  <version>0.3.0</version>
</dependency>
```
```java
var client = new AuditClient("http://localhost:9001", "my-session", "my-agent");
var resp = client.recordStep("terminal", Map.of("cmd", "ls"), Map.of("exit", 0));
System.out.println(resp.status); // "recorded" | "denied"
```

---

## 6. View the dashboard

```bash
kubectl port-forward svc/tracepath-dashboard 3000:80
# Open http://localhost:3000
```

You'll see:
- **Audit tab**: real-time event feed, policy decisions, tool usage
- **Policies tab**: version history, diffs, rollback

---

## 7. Generate your first compliance report

```bash
kubectl exec deploy/tracepath-incident -- \
  python3 -m incident_service.report_cli finra \
  --format html --output /tmp/finra-report.html

kubectl cp tracepath-incident:/tmp/finra-report.html ./finra-report.html
# Open finra-report.html in a browser
```

---

## 8. What to expect

| Day | Milestone |
|---|---|
| Day 1 | Gateway running, first audit events flowing |
| Day 3 | Dashboard showing real-time stats |
| Day 7 | First compliance report generated |
| Day 14 | Gemini classifier (optional) reducing false positives |
| Day 30 | Ready for SOC2 evidence collection |

---

## Support

- Docs: https://docs.tracepath.dev
- Email: support@tracepath.dev
- Slack: tracepath-community.slack.com

## Next: Enterprise onboarding

For custom policies, multi-tenancy, or regulatory consulting:
contact@tracepath.dev
