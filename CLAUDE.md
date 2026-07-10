# Tracepath — Agent Audit Stack

Middleware que hace a cualquier agente AI (LangGraph, CrewAI, AutoGen, etc.) auditable, trazable y compliant con EU AI Act, FINRA y SOC2.

## Pitch

"¿Podés auditar lo que hicieron tus agentes ayer?"
Tracepath responde esa pregunta con logs inmutables, approval gates y reportes regulatorios.

## Stack

| Capa | Tecnología |
|---|---|
| **Audit Gateway (core)** | Rust + actix-web + OPA WASM |
| **Incident Response** | Python + NATS JetStream + OPA Rego |
| **Policy Evolution** | Python + libgit2 |
| **Dashboard** | React + Tailwind + shadcn/ui |
| **Event bus** | NATS JetStream |
| **DB** | PostgreSQL + particionado |
| **WORM storage** | S3 Object Lock / MinIO |
| **Observability** | OpenTelemetry → LangFuse |
| **Firma** | Ed25519 |

## Estructura del monorepo

```
tracepath/
├── gateway/          # Rust — Audit Gateway (crate)
├── incident/         # Python — Incident Response
├── policies/         # Python — Policy Evolution engine
├── dashboard/        # React — Compliance dashboard
├── sdk/              # SDKs multi-lenguaje
│   ├── python/
│   ├── typescript/
│   └── java/
├── docs/             # Documentación
├── docker/           # Docker Compose para dev
└── README.md
```

## Roadmap

### Fase 0 — Fundación (semanas 1–2)
- [ ] Monorepo con estructura de directorios
- [ ] Gateway Rust: proyecto Cargo, actix-web, passthrough proxy
- [ ] SDK Python: wrapper mínimo que intercepta tool calls
- [ ] Schema PostgreSQL: migration inicial
- [ ] Firma Ed25519 por evento
- [x] OpenTelemetry export a LangFuse
- [ ] Docker Compose para dev (gateway + postgres + nats)
- [ ] README con quickstart

### Fase 1 — MVP (semanas 3–6)
- [x] OPA WASM embebido en Gateway
- [x] Reglas base: presupuesto, tool allowlist, rate limit
- [x] API REST de consulta de auditoría
- [x] WORM storage con S3/MinIO Object Lock
- [x] SDKs TypeScript + Java

### Fase 2 — Incident Response (semanas 7–10)
- [x] NATS JetStream streaming
- [x] Detección real-time con OPA
- [x] Reportes FINRA + EU AI Act (PDF)
- [x] Dashboard compliance
- [x] Clasificación semántica con Gemini (Google AI) — refinamiento de severidad post-thresholds

### Fase 3 — Policy Evolution (semanas 11–14)
- [x] Versionado Git de policies
- [x] Replay engine sobre logs históricos
- [x] Diff visual + rollback

### Fase 4 — GTM (semanas 15–18)
- [x] Helm chart
- [x] AWS Marketplace
- [x] SOC2 certification
- [x] Primer cliente

## Convenciones

- **Lenguaje**: inglés para código, docs y commits
- **Commits**: conventional commits (`feat:`, `fix:`, `docs:`, `chore:`)
- **Tests**: unit tests en cada crate/package, integration tests en CI
- **Rust**: workspace Cargo.toml en raíz con members
- **Python**: uv o Poetry, type hints obligatorios, pytest
- **React**: TypeScript, componentes shadcn/ui, Tailwind

## Agentes disponibles

- **@rust-dev**: especialista en Rust (actix-web, OPA WASM, Ed25519)
- **@python-dev**: especialista en Python (NATS, OPA Rego, FastAPI)
- **@react-dev**: especialista en React (Tailwind, shadcn/ui, Vite)
- **@infra-dev**: Docker Compose, CI/CD, PostgreSQL, NATS

## Tarea actual: Fase 0 — Fundación

Dividir en subtareas y delegar a los agentes especializados. No escribir código sin revisar primero el estado del repo.
