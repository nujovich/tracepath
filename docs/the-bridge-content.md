# Lo que aprendí construyendo un middleware de auditoría para agentes de IA en un fin de semana

*Contenido para The Bridge — perfiles Fullstack y Data Science*

---

## 🎯 De qué va esto

Este fin de semana construí [Tracepath](https://github.com/nujovich/tracepath): un middleware open-source que audita agentes de IA en tiempo real. Lo levantás con `docker compose up` y cada tool call de tu agente queda firmado, verificado contra políticas y almacenado en un log inmutable. Si algo huele raro — muchas denegaciones, presupuesto excedido, rate limit violado — salta una alerta en el dashboard y Gemini 2.5 Flash le pone contexto humano: "esto no es un ataque, es un bug de configuración."

Pero este post no es sobre el proyecto. Es sobre lo que aprendí y lo que le sirve a un perfil técnico, ya sea fullstack o data scientist, que está metiéndose en el mundo de los agentes.

---

## 🧠 1. Un agente es una API con esteroides (y sin barandas)

Para un fullstack, un agente de IA no es magia negra. Es un loop:

```
user prompt → LLM decide qué tool llamar → ejecuta tool → resultado → LLM decide siguiente paso → ...
```

Cada "tool call" es literalmente un POST a un endpoint. La diferencia con una API REST tradicional es que **el que decide qué endpoint llamar no es un frontend, es un modelo de lenguaje.** Y los LLMs son creativos. A veces demasiado.

**Lo que importa para fullstack:** Si ya sabés construir APIs, middleware y pipelines de eventos, ya tenés el 80% de lo que necesitás para trabajar con agentes. Lo nuevo es el **control**: ¿cómo limitás lo que el agente puede hacer? ¿Cómo sabés qué hizo?

---

## 🔐 2. El patrón "interceptar, firmar, verificar" es universal

El núcleo de Tracepath es un gateway en Rust que intercepta cada tool call, lo firma con Ed25519 y lo pasa por un motor de políticas OPA WASM. Tres conceptos que ya existen en seguridad web:

| Concepto | Web tradicional | Agentes de IA |
|---|---|---|
| **Interceptar** | WAF / API Gateway (Kong, Envoy) | Audit Gateway (Tracepath) |
| **Firmar** | JWT / HMAC en requests | Ed25519 por evento |
| **Verificar** | RBAC / OPA policies | OPA WASM (allowlist, budget, rate limit) |

**Para fullstack:** Si alguna vez implementaste un middleware de auth en Express, FastAPI o Actix, ya entendés la arquitectura. Solo cambia el contexto.

**Para data scientists:** No necesitás saber Rust. El SDK de Python te da un decorator `@audit` que wrappea cualquier función y la audita automáticamente. Cero código extra.

```python
from tracepath_sdk import AsyncAuditClient, audit

client = AsyncAuditClient(agent_type="researcher")

@audit(client)
async def search_papers(query: str) -> dict:
    # Tu lógica de búsqueda
    return {"results": 42}

# Cada vez que llamás search_papers(), se audita automáticamente
```

---

## 📊 3. Para data scientists: tu pipeline ya es auditable, solo falta la capa de control

El caso de uso más común para un data scientist usando agentes es:

```
Agente investigador: busca papers → extrae datos → corre análisis → genera reporte
```

Cada paso es un tool call. Si lo pasás por Tracepath, obtenés:

- **Trazabilidad:** Qué papers consultó, qué queries hizo, cuánto gastó en tokens
- **Control de presupuesto:** "No gastes más de €10 en esta sesión de research"
- **Allowlists:** "Podés usar `web_search` y `read_file`, pero no `terminal`"
- **Reportes de compliance:** Un click y tenés un reporte FINRA o EU AI Act

**Esto no es solo para fintech.** Cualquier empresa que use agentes para análisis de datos en sectores regulados (salud, finanzas, legal) va a necesitar esto. No es un "nice to have", es un requisito.

---

## 🐍 4. Stack técnico: lo que un fullstack/ds debería mirar

| Componente | Tech | Por qué importa |
|---|---|---|
| **Gateway** | Rust + actix-web | Performance. <1ms por request. Sin GC pauses. |
| **Policy engine** | OPA + Rego → WASM | Las políticas corren en el mismo proceso, sin network hop. |
| **Event bus** | NATS JetStream | Persistente. Si el detector se cae, no pierde eventos. |
| **Dashboard** | React + TypeScript + Tailwind | 5 tabs. Nada fancy, puro dato. |
| **WORM storage** | MinIO + S3 Object Lock | "Ni el admin puede borrar esto." Requisito regulatorio real. |
| **Clasificador** | Gemini 2.5 Flash vía OpenRouter | Refinamiento semántico de alertas. No bloqueante. |

---

## 🚨 5. Lo que descubrí sobre el EU AI Act (y por qué importa)

El **Artículo 50** del EU AI Act dice que los sistemas de IA de alto riesgo deben:

1. **Registrar eventos automáticamente** durante la operación
2. **Permitir supervisión humana** mediante monitoreo e intervención
3. **Garantizar trazabilidad** de las decisiones del sistema

Traducción: si tu empresa despliega agentes que toman decisiones (aunque sea "qué herramienta llamar"), necesitás un audit trail. No en 2028 cuando la ley entre en vigor. Ahora, mientras diseñás la arquitectura.

**Para fullstack:** Esto es un feature de arquitectura, no de compliance. Se construye desde el día 1 o se paga 10x después.

**Para data scientists:** Si tu modelo o agente está en un pipeline que afecta decisiones de negocio, preguntale a tu equipo de engineering: "¿Cómo auditamos esto?" Si no tienen respuesta, acabás de identificar un riesgo.

---

## 🔮 6. ¿Qué skills necesitás para construir algo así?

| Skill | ¿Lo necesitás? | ¿Por qué? |
|---|---|---|
| **Rust** | Si construís el gateway | Performance + seguridad de memoria. Pero el SDK en Python ya existe. |
| **Python** | Sí | El detector, el SDK, los reportes. Todo en Python. |
| **React/TS** | Para el dashboard | Pero es un dashboard de monitoreo, no una SPA compleja. |
| **OPA/Rego** | Básico | Las políticas son 20 líneas de Rego. Se aprende en una tarde. |
| **Docker** | Sí | Todo el stack se levanta con compose. |
| **NATS/Kafka** | Conceptual | JetStream es más simple que Kafka. Perfecto para empezar. |

---

## 🎓 Lo que me llevo del finde

1. **Los agentes sin auditoría son código en producción sin logs.** Impensable en backend, normal en AI. Por ahora.

2. **El gap entre "AI engineer" y "security engineer" se va a cerrar.** Quien entienda ambos va a ser invaluable.

3. **No necesitás 6 meses para construir algo que funcione.** Un fin de semana enfocado, un stack definido, y a iterar. El MVP de Tracepath — gateway, políticas, dashboard, detector, reportes y Gemini — salió en 48 horas.

4. **El EU AI Act no es un problema, es un mercado.** Hay miles de empresas que van a necesitar audit trails para agentes. El que llegue primero con una solución open-source y fácil de integrar, gana.

---

*¿Querés probarlo? `git clone https://github.com/nujovich/tracepath && cd docker && docker compose up -d`. Son 3 comandos. Después contame qué pensás.*

— Nadia