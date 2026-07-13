# 🧠 Lo que aprendí construyendo un middleware de auditoría para agentes de IA

### Un fin de semana. 7 servicios. 3 SDKs. 1 docker compose up.

---

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   🏗️  ARQUITECTURA EN 1 MINUTO                          │
│                                                         │
│   Agente → SDK → Gateway (Rust) → PostgreSQL + WORM     │
│                       ↓                                 │
│                 NATS JetStream                           │
│                       ↓                                 │
│           Incident Detector (Python)                     │
│                       ↓                                 │
│              Gemini 2.5 Flash ✨                         │
│                       ↓                                 │
│            Dashboard (React, 5 tabs)                     │
│                                                         │
│   Todo en:  docker compose up -d                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 PARA DATA SCIENTISTS

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   🔬 Tu pipeline de research, AUDITABLE con 0 código    │
│                                                         │
│   from tracepath_sdk import AsyncAuditClient, audit     │
│                                                         │
│   client = AsyncAuditClient(agent_type="researcher")    │
│                                                         │
│   @audit(client)                                        │
│   async def search_papers(query): ...                   │
│                                                         │
│   → Cada llamada se firma, audita y almacena            │
│     automáticamente. Sin tocar tu lógica.               │
│                                                         │
│   ✅ Trazabilidad: qué consultó, cuánto gastó            │
│   ✅ Budget: "no gastes más de €10"                     │
│   ✅ Allowlists: "web_search sí, terminal no"           │
│   ✅ Reportes: FINRA + EU AI Act en 1 click              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 🔐 PARA FULLSTACK

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   🛡️  Lo que ya sabés de seguridad web...               │
│       ...aplica a agentes de IA                         │
│                                                         │
│   Web tradicional         →     Agentes de IA           │
│   ─────────────────            ─────────────────       │
│   WAF / API Gateway       →     Audit Gateway           │
│   JWT / HMAC              →     Ed25519 por evento      │
│   RBAC / OPA              →     OPA WASM <1ms           │
│   Logs en Elasticsearch   →     WORM (S3 Object Lock)   │
│   Alertas en Grafana      →     Dashboard + Gemini      │
│                                                         │
│   Si hiciste middleware de auth en Express,             │
│   FastAPI o Actix → ya entendés la arquitectura.        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## ⚡ MÉTRICAS DEL PROYECTO

```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│              │              │              │              │
│   <1ms       │   7          │   4          │   3          │
│   policy     │   servicios  │   detectores │   SDKs       │
│   check      │   en compose │   en prod    │   (PY,TS,JV) │
│              │              │              │              │
├──────────────┼──────────────┼──────────────┼──────────────┤
│              │              │              │              │
│   48h        │   5          │   14         │   1          │
│   de build  │   tabs en    │   tests      │   comando    │
│   (finde)   │   dashboard  │   Python SDK │   para       │
│              │              │              │   arrancar   │
│              │              │              │              │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

---

## 🧠 GEMINI — EL DIFERENCIADOR

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   Los detectores de thresholds son RUIDOSOS.            │
│   Gemini 2.5 Flash pone CONTEXTO.                       │
│                                                         │
│   Incidente: 8 denials en sesión coder                  │
│   Threshold: ⚡ CRITICAL                                │
│   Gemini:    "Todas las denials son image_generate,     │
│              probablemente una mala configuración,      │
│              no un ataque real."                        │
│   Resultado: ⚠️  WARNING                               │
│                                                         │
│   No bloqueante. Si Gemini falla → severidad original.  │
│   Cache persistente. Clasificaciones sobreviven reinicio│
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📜 EU AI ACT — POR QUÉ IMPORTA

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   El Artículo 50 exige 3 cosas:                         │
│                                                         │
│   📋 Registro automático de eventos                     │
│      → Gateway intercepta CADA tool call                │
│                                                         │
│   👁️  Supervisión humana                                 │
│      → Dashboard con 5 tabs de monitoreo                │
│                                                         │
│   🔍 Trazabilidad de decisiones                         │
│      → PostgreSQL: query por session, agent, tool       │
│                                                         │
│   No es un "nice to have". Es un requisito.             │
│   Y nadie lo está construyendo. Hasta ahora.            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 STACK TÉCNICO

```
┌─────────────┬──────────────────────────────────────────┐
│ Rust        │ Gateway: actix-web + OPA WASM + Ed25519   │
├─────────────┼──────────────────────────────────────────┤
│ Python      │ Detector: NATS + aiohttp + Gemini        │
├─────────────┼──────────────────────────────────────────┤
│ React/TS    │ Dashboard: 5 tabs, Tailwind, shadcn/ui    │
├─────────────┼──────────────────────────────────────────┤
│ OPA/Rego    │ Políticas: allowlist, budget, rate limit  │
├─────────────┼──────────────────────────────────────────┤
│ PostgreSQL  │ Audit log: queryable, particionado        │
├─────────────┼──────────────────────────────────────────┤
│ MinIO       │ WORM: S3 Object Lock, 365 días            │
├─────────────┼──────────────────────────────────────────┤
│ NATS        │ Event bus: JetStream persistente          │
├─────────────┼──────────────────────────────────────────┤
│ Gemini 2.5  │ Clasificador semántico vía OpenRouter     │
└─────────────┴──────────────────────────────────────────┘
```

---

## 🚀 3 TAKEAWAYS

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  1. Agentes sin auditoría = código en prod sin logs     │
│     Impensable en backend. Normal en AI. Por ahora.     │
│                                                         │
│  2. El gap security ↔ AI se cierra en 2026              │
│     Quien entienda AMBOS va a ser invaluable.           │
│                                                         │
│  3. El EU AI Act no es un problema, es un MERCADO       │
│     Miles de empresas van a necesitar audit trails.     │
│     El que llegue primero con open-source, gana.        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  ⭐ github.com/nujovich/tracepath                       │
│                                                         │
│  git clone + docker compose up -d → 3 comandos          │
│                                                         │
│  Built with ❤️‍🔥 by Nadia Ujovich                        │
│  Security engineer → AI builder                         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```