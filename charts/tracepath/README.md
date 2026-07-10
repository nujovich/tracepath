# Tracepath Helm Chart

Deploy the Tracepath Agent Audit Stack on Kubernetes.

## Quickstart

```bash
# Generate signing key
export AUDIT_SIGNING_KEY=$(openssl rand -hex 32)

# Install with defaults
helm install tracepath ./charts/tracepath \
  --set gateway.signingKey="$AUDIT_SIGNING_KEY"

# Enable OpenTelemetry → LangFuse
helm install tracepath ./charts/tracepath \
  --set gateway.signingKey="$AUDIT_SIGNING_KEY" \
  --set gateway.otel.enabled=true \
  --set gateway.otel.endpoint="https://cloud.langfuse.com/api/public/otel" \
  --set gateway.otel.langfusePublicKey="pk-lf-..." \
  --set gateway.otel.langfuseSecretKey="sk-lf-..."

# Enable Gemini incident classification
helm install tracepath ./charts/tracepath \
  --set gateway.signingKey="$AUDIT_SIGNING_KEY" \
  --set incident.gemini.enabled=true \
  --set incident.gemini.apiKey="$GOOGLE_API_KEY"
```

## Production checklist

- [ ] Set `gateway.signingKey` to a secure random 32-byte hex string
- [ ] Change `postgresql.auth.password`
- [ ] Change `minio.auth.rootPassword`
- [ ] Enable TLS via `gateway.ingress.tls`
- [ ] Set resource limits appropriate for your workload
- [ ] Configure persistent storage classes
- [ ] Enable OTel if using LangFuse

## Components

| Component | Default | Purpose |
|---|---|---|
| Gateway | 2 replicas | Audit event ingestion + policy enforcement |
| PostgreSQL | 1 replica | Audit log storage |
| NATS | 1 replica | Event streaming |
| MinIO | 1 replica | WORM archival storage |
| Incident | 1 replica | Real-time detection |
| Policies | 1 replica | Policy versioning API |
| Dashboard | 1 replica | Compliance UI |