---
title: "Tracepath — I Built an AI Agent Audit Middleware in One Weekend (Passion Edition)"
published: true
tags: devchallenge, weekendchallenge, ai, security, rust, python, googleai
---

*This is a submission for [Weekend Challenge: Passion Edition](https://dev.to/challenges/weekend-2026-07-09)*

## What I Built

**Tracepath** is an open-source middleware that makes any AI agent — LangChain, CrewAI, AutoGen, or your own — **auditable, traceable, and compliant** with regulations like the EU AI Act and FINRA.

It's a full audit stack you can spin up with a single `docker compose up`. Every tool call your agent makes gets intercepted, signed with Ed25519, checked against OPA policies, stored in an immutable WORM log, and monitored in real-time for anomalies.

> **"Can you audit what your agents did yesterday?"** — Tracepath answers that.

### The dashboard in one screenshot

![Tracepath Compliance Dashboard — Gemini tab showing semantic classification](https://raw.githubusercontent.com/nujovich/tracepath/main/docs/screenshots/dashboard-gemini-classification.png)

Five tabs: **Audit** (event trail), **Incidents** (real-time detection), **Policies** (versioned OPA rules with diff & rollback), **Reports** (FINRA & EU AI Act compliance), and **Gemini** (semantic incident classification).

---

## 🤍 The Passion Behind It

I didn't start in AI. I started in **security**.

When I began working in tech, I specialized in web application security — OWASP Top 10, XSS, CSRF, DoS attacks. I spent years thinking about how to **control** what applications do, how to prevent them from being abused, how to draw a boundary between "allowed" and "denied."

Then AI happened. And I fell in love with building agents — autonomous systems that can reason, use tools, and make decisions. But the security part of my brain wouldn't shut up:

- *How do you know what your agent did yesterday?*
- *What if it calls a tool it shouldn't?*
- *What if it burns through your budget?*
- *How do you prove compliance to a regulator?*

**That's the passion.** Marrying the two halves of my career: the security engineer who says "trust nothing, verify everything" and the AI builder who wants agents to be powerful and autonomous.

The EU AI Act was the spark. When I read Article 50 — the requirement for high-risk AI systems to maintain logs and enable human oversight — I realized: *this is exactly what I spent years doing for web apps, but nobody's built it for AI agents yet.*

So I built it. In one weekend. Because that's what passion does — it makes you forget to sleep.

---

## Demo

### One command to start

```bash
git clone https://github.com/nujovich/tracepath.git
cd tracepath/docker
AUDIT_SIGNING_KEY=$(openssl rand -hex 32) docker compose up -d
```

### Dashboard at `http://localhost:3000`

![Tracepath Dashboard — Audit Trail](https://raw.githubusercontent.com/nujovich/tracepath/main/docs/screenshots/dashboard-audit.png)
*Every tool call is signed, policy-checked, and stored in PostgreSQL + MinIO WORM storage.*

![Tracepath Dashboard — Incidents](https://raw.githubusercontent.com/nujovich/tracepath/main/docs/screenshots/dashboard-incidents.png)
*Real-time incident detection: denial spikes, budget overruns, suspicious patterns, rate limit breaches.*

![Tracepath Dashboard — Policies](https://raw.githubusercontent.com/nujovich/tracepath/main/docs/screenshots/dashboard-policies.png)
*Git-based policy versioning with visual diff and one-click rollback.*

![Tracepath Dashboard — Reports](https://raw.githubusercontent.com/nujovich/tracepath/main/docs/screenshots/dashboard-reports.png)
*One-click FINRA and EU AI Act compliance reports.*

### What happens when you send audit events

```bash
curl -X POST http://localhost:9001/audit/step \
  -H "Content-Type: application/json" \
  -d '{
    "session_id":"demo","agent_id":"researcher","agent_type":"researcher",
    "step_number":1,"tool_name":"web_search",
    "tool_input":{"q":"EU AI Act Article 50"},
    "tool_output":{"results":3},"cost_cents":5,
    "timestamp":"2026-07-12T12:00:00Z"
  }'
# → {"status":"recorded","signature":"<ed25519>","policy_decision":{"allowed":true,"denials":[]}}
```

Every event is:
1. **Signed** with Ed25519 (cryptographic non-repudiation)
2. **Checked** against OPA WASM policies (allowlist, budget, rate limit) in <1ms
3. **Stored** in PostgreSQL (queryable) + MinIO S3 Object Lock (WORM, 365 days)
4. **Streamed** via NATS JetStream to the incident detector
5. **Classified** by Gemini 2.5 Flash for semantic severity refinement

---

## Code

{% github nujovich/tracepath %}

The stack:
- **Rust** (actix-web + OPA WASM + Ed25519) — the audit gateway
- **Python** (NATS JetStream + aiohttp + Gemini) — the incident detector
- **React** (TypeScript + Tailwind + shadcn/ui) — the compliance dashboard
- **OPA** (Rego → WASM) — policy engine
- **PostgreSQL** — queryable audit log
- **MinIO** (S3 Object Lock) — WORM storage
- **NATS JetStream** — event bus

---

## How I Built It

### Phase 1: Foundation (Saturday morning)

The core pipeline: intercept → sign → check → store. I built the Rust gateway with actix-web, embedded OPA WASM for policy evaluation, and wired Ed25519 signing. PostgreSQL for the queryable audit log, MinIO with S3 Object Lock for immutable WORM storage.

### Phase 2: Incident Response (Saturday afternoon)

Streamed events from the gateway to NATS JetStream, then built a Python incident detector that watches for four anomaly types: denial spikes, budget overruns, suspicious patterns, and rate limit breaches. All surfaced in a React dashboard with real-time polling.

### Phase 3: Policy Evolution (Saturday night)

Implemented git-based policy versioning. Every OPA policy change is a git commit. Built a visual diff viewer and one-click rollback in the dashboard. Added a replay engine that lets you replay historical events against a different policy version to answer: *"What would have happened if this policy was active then?"*

### Phase 4: Compliance & Gemini (Sunday)

Generated FINRA and EU AI Act compliance reports as HTML. Integrated **Google Gemini 2.5 Flash** via OpenRouter as a semantic classifier — it takes threshold-triggered incidents and refines their severity by analyzing the context. A denial spike from a misconfigured policy gets downgraded from CRITICAL to WARNING. A real attack stays CRITICAL.

The Gemini integration caches classifications persistently, so the dashboard shows the reasoning behind every severity decision even between container restarts.

### What I discovered about the EU AI Act

Article 50 of the EU AI Act requires high-risk AI systems to:
- **Automatically record events** (logs) during operation
- **Enable human oversight** through monitoring and intervention
- **Ensure traceability** of AI system decisions

Tracepath implements all three. The FINRA report validates data integrity (Ed25519 signatures), record retention (WORM storage), and access controls (API authentication).

---

## Prize Categories

I'm submitting to **Best Use of Google AI**.

Tracepath uses **Gemini 2.5 Flash** (via Google AI) as a semantic classifier that refines incident severity. Instead of blindly flagging every threshold breach as CRITICAL, Gemini analyzes the context:

| Incident | Original Severity | Gemini Reasoning | Final Severity |
|---|---|---|---|
| 6 `image_generate` denials in a session | CRITICAL | *"All denials were for image generation, suggesting a misconfiguration rather than a malicious attempt"* | WARNING |
| Budget exceeded by 2x in a single session | WARNING | *"The tools used match a legitimate research workflow with no policy bypass attempts"* | INFO |

This is the difference between a noisy alert system and a useful one — and it's powered by Google AI.

---

## What's Next

This is a weekend project, but it's not a toy. The roadmap:

- [ ] **Helm chart** for Kubernetes deployment
- [ ] **TypeScript SDK** with `@audit` decorator parity
- [ ] **PDF reports** for FINRA/EU AI Act (currently HTML)
- [ ] **SOC2 certification** readiness package
- [ ] **AWS Marketplace** listing
- [ ] **Multi-tenant** dashboard with organization scoping
- [ ] **Webhook alerts** for incident notifications (Slack, PagerDuty)
- [ ] **Custom policy UI** — write Rego rules directly in the dashboard

→ [Star the repo](https://github.com/nujovich/tracepath) to follow along.

---

*Built with ❤️‍🔥 by [Nadia Ujovich](https://github.com/nujovich) — a security engineer turned AI builder who still believes the best agents are auditable ones.*