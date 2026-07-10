# SOC2 Compliance Guide

How Tracepath maps to SOC2 Trust Services Criteria (TSC 2017).
This is a self-assessment guide — a SOC2 auditor will verify each control.

## Trust Services Criteria Coverage

### Security (Common Criteria — CC)

| Criterion | Tracepath Implementation | Evidence |
|---|---|---|
| CC1.1 — COSO Principle 1 | Infrastructure-as-code (Helm chart) with documented RBAC | `charts/tracepath/` |
| CC4.1 — Monitoring | OpenTelemetry → LangFuse, real-time incident detection | `gateway/src/main.rs`, `incident/incident_service/detector.py` |
| CC5.2 — Risk Assessment | Gemini semantic classifier catches false positives + real threats | `incident/incident_service/gemini_classifier.py` |
| CC6.1 — Logical Access | OPA WASM policy engine: allowlist, rate limit, budget per agent type | `policies/rules/` |
| CC6.3 — Access Control | Ed25519-signed audit events with non-repudiation | `gateway/src/main.rs:sign_event()` |
| CC6.6 — External Threats | Rate limiting (60 calls/min), deny on budget exceed | `policies/rules/ratelimit.rego`, `policies/rules/budget.rego` |
| CC7.2 — System Monitoring | Incident service with 4 detection rules + Gemini refinement | `incident/incident_service/detector.py` |
| CC7.5 — Incident Response | Structured incident logging (JSON), severity classification | `incident/incident_service/models.py` |
| CC8.1 — Change Management | Git-versioned policies with diff, rollback, and audit trail | `policies/policy_engine/versioning.py` |

### Availability (A)

| Criterion | Tracepath Implementation |
|---|---|
| A1.1 — Availability | Gateway: 2 replicas, health checks, readiness probes | `charts/tracepath/templates/gateway.yaml` |
| A1.2 — Recovery | StatefulSets for PostgreSQL, NATS, MinIO with PVC persistence | `charts/tracepath/values.yaml` |

### Confidentiality (C)

| Criterion | Tracepath Implementation |
|---|---|
| C1.1 — Confidential Information | Secrets via Kubernetes Secrets, not plaintext | `charts/tracepath/templates/configmap.yaml` |
| C1.2 — Disposal | WORM storage with 365-day Object Lock retention (compliance mode) | MinIO bucket config |

---

## Audit Evidence Package

To prepare for a SOC2 Type II audit, collect:

```bash
# 1. Policy version history (proves change management)
python3 -m policy_engine.cli versions > soc2-policy-history.txt

# 2. FINRA compliance report (proves audit trail completeness)
python3 -m incident_service.report_cli finra --format html --output soc2-finra-report.html

# 3. EU AI Act compliance report (proves regulatory alignment)
python3 -m incident_service.report_cli eu-ai-act --format html --output soc2-eu-ai-act-report.html

# 4. Incident log (proves monitoring)
# Captured from incident service stdout — structured JSON per incident

# 5. Infrastructure config (proves security controls)
helm get values tracepath > soc2-helm-values.yaml
```

## Readiness

| Trust Service | Readiness | Gap |
|---|---|---|
| Security | ✅ Ready | — |
| Availability | ✅ Ready | — |
| Confidentiality | ✅ Ready | — |
| Processing Integrity | ⚠️ Partial | Add input validation fuzzing tests |
| Privacy | ⚠️ Partial | Need data classification matrix for PII in audit events |

## Next Steps for Certification

1. Engage a SOC2 auditor (AICPA-licensed CPA firm)
2. Run Tracepath in production for 3-6 months (observation period)
3. Collect evidence package monthly
4. Schedule Type I (point-in-time) audit first, then Type II (continuous)
