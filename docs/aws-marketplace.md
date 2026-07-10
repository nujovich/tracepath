# AWS Marketplace Listing

## Product Metadata

```yaml
title: "Tracepath — Agent Audit Stack"
short_description: "Make any AI agent framework (LangGraph, CrewAI, AutoGen) auditable, traceable, and compliant with EU AI Act, FINRA, and SOC2."
long_description: |
  Tracepath intercepts every tool call from your AI agents and
  produces a cryptographically signed, WORM-archived audit trail
  that satisfies regulatory requirements.

  Built for teams deploying AI agents in regulated industries
  (finance, healthcare, legal) where every decision must be
  auditable.

  - Ed25519-signed audit events
  - OPA WASM policy engine (allowlist, budget, rate limit)
  - WORM archival (S3 Object Lock, 365-day retention)
  - Real-time incident detection with Gemini semantic classification
  - FINRA + EU AI Act compliance reports
  - Helm chart for Kubernetes deployment

categories:
  - Compliance & Auditing
  - AI/ML Infrastructure
  - Security

pricing_model: BYOL (Bring Your Own License)
free_trial: "30 days"
support: "Email + Slack (business hours)"

keywords:
  - ai audit
  - ai compliance
  - eu ai act
  - finra
  - soc2
  - agent audit
  - opa
  - open policy agent
  - audit trail
  - worm storage
  - ed25519
```

## Architecture Diagram (for listing page)

```
┌─────────┐     ┌──────────┐     ┌────────────┐
│ Agent   │────▶│ Gateway  │────▶│ PostgreSQL │
│ (any    │     │ (Rust)   │     │ (audit log)│
│  fwk)   │     └────┬─────┘     └────────────┘
└─────────┘          │
                     │ Ed25519 sign
                     │ OPA WASM policy
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
    ┌─────────┐ ┌───────┐ ┌──────────┐
    │ MinIO   │ │ NATS  │ │ OTel →   │
    │ (WORM)  │ │stream │ │ LangFuse │
    └─────────┘ └──┬────┘ └──────────┘
                   │
                   ▼
            ┌────────────┐
            │ Incident   │
            │ Service    │
            │ + Gemini   │
            └────────────┘
```

## Pricing Tiers

| Tier | Price | Includes |
|---|---|---|
| Starter | $499/mo | Up to 100K events/mo, 1 agent type, email support |
| Team | $1,499/mo | Up to 1M events/mo, 5 agent types, Slack support |
| Enterprise | Custom | Unlimited events, custom policies, SOC2 audit support, SLA |

## Launch Checklist

- [ ] Create AWS Marketplace seller account
- [ ] Build + push container images to ECR
- [ ] Create Helm chart listing
- [ ] Submit for review
- [ ] Publish test listing
- [ ] Go live
