# Tracepath — Technical Interview Cheat Sheet

---

## 🎯 Elevator Pitch (30 segundos)

> "Tracepath es un middleware open-source que hace que cualquier agente de AI sea auditable y compliant con EU AI Act y FINRA. Lo construí en un fin de semana. En production, lo levantás con un `docker compose up`. Cada tool call de tu agente se firma con Ed25519, se chequea contra políticas OPA, se almacena en WORM y se monitorea en tiempo real con Gemini 2.5 Flash clasificando incidentes."

---

## 🏗️ Arquitectura (lo que tenés que saber explicar)

```
Agente → SDK → Gateway (Rust) → PostgreSQL + MinIO WORM
                        ↓
                  NATS JetStream → Incident Detector (Python) → Gemini 2.5 Flash
                        ↓
                  Dashboard (React, 5 tabs)
```

**Lo importante:** el gateway es el punto único de enforcement. Todo pasa por ahí. No hay side channels.

---

## 🔑 Decisiones técnicas clave (hablá de estas)

| Decisión | Por qué | Impacto |
|---|---|---|
| **Rust para el gateway** | Performance + seguridad de memoria. El policy engine tiene que evaluar en <1ms | Sin garbage collection, sin race conditions |
| **OPA WASM embebido** | Ejecuta políticas en el mismo proceso, sin llamada de red | Latencia sub-milisegundo. 0 dependencia externa en runtime |
| **Ed25519 por evento** | Firma criptográfica individual, no por batch | Non-repudiation: cada evento es verificable independientemente |
| **WORM con S3 Object Lock** | MinIO con compliance mode, 365 días | Auditoría inmutable. "Ni el admin puede borrar esto" |
| **NATS JetStream** | Streaming persistente, no solo pub/sub | Si el detector se cae, no pierde eventos. Los reprocesa |
| **Gemini vía OpenRouter** | Un solo endpoint, misma API key para múltiples modelos | Si Google AI está caído o sin cuota, cambiás de backend sin tocar código |

---

## 📊 Métricas que impresionan

| Métrica | Valor |
|---|---|
| **Latencia de firma + policy check** | <1ms (Ed25519 + OPA WASM) |
| **Stack completo** | 7 servicios en 1 docker compose |
| **Lenguajes** | Rust, Python, TypeScript (React), Rego (OPA) |
| **Detectores** | 4 en tiempo real + 1 semántico (Gemini) |
| **SDKs** | 3 lenguajes (Python, TypeScript, Java) |
| **Tests** | 14 tests Python SDK (7 unit + 7 integración) |

---

## 🧠 Gemini Classifier (tu Google AI angle)

**Problema:** Los detectores de thresholds son ruidosos. Un denial spike puede ser un ataque real o un developer probando una tool nueva.

**Solución:** Gemini 2.5 Flash recibe el incidente + contexto de la sesión y reclasifica:

```
Threshold: "8 denials in session → CRITICAL"
Gemini: "All denials were image_generate for coder agent → probable misconfiguration"
Result: CRITICAL → WARNING ✅
```

**Lo técnico:** El clasificador no es bloqueante. Si Gemini falla (429, timeout), el incidente se registra igual con la severidad original. El cache persiste a disco.

---

## 📜 Compliance (EU AI Act + FINRA)

**EU AI Act Article 50** exige 3 cosas para high-risk AI:

| Requisito | Cómo lo cumple Tracepath |
|---|---|
| **Automatic logging** | Gateway intercepta y firma cada tool call |
| **Human oversight** | Dashboard con 5 tabs de monitoreo en tiempo real |
| **Traceability** | PostgreSQL permite query por session_id, agent_id, tool |

**FINRA Rule 4511** (Books & Records):
- WORM storage → "non-erasable, non-rewritable"
- Ed25519 signatures → "data integrity"
- 365-day retention → "prescribed period"

---

## 🚀 Roadmap (si te preguntan "¿y después?")

1. **Helm chart** → Kubernetes
2. **PDF reports** → compliance officers
3. **Webhook alerts** → Slack, PagerDuty
4. **Custom policy UI** → escribir Rego desde el dashboard
5. **AWS Marketplace** → one-click deploy
6. **SOC2 readiness** → evidence package

---

## ⚡ Preguntas que te pueden hacer (y cómo responder)

**Q: "¿Por qué no usaste OpenTelemetry para todo el tracing?"**
> Ya está cableado. El gateway exporta a LangFuse vía OTLP. Pero el audit trail es más que tracing — es evidencia regulatoria. Necesitás firma criptográfica y WORM. OTel no te da eso.

**Q: "¿Esto no es un API gateway con pasos extra?"**
> No exactamente. Un API gateway enruta requests. Tracepath los audita. La diferencia es el WORM, la firma Ed25519, y los reportes regulatorios. Un Kong o un Envoy no te generan un FINRA report.

**Q: "¿Cómo escala esto en producción?"**
> El gateway es stateless (Rust, actix-web). PostgreSQL con particionado por fecha. NATS JetStream para desacoplar el detector. MinIO en cluster mode. Kubernetes con Helm.

**Q: "¿Qué pasa si Gemini no está disponible?"**
> El clasificador es no-bloqueante. Si falla, el incidente se registra con la severidad del threshold. El dashboard muestra el error en el cache. No hay degradación del pipeline principal.

**Q: "¿Cómo manejás secretos y rotación de keys?"**
> AUDIT_SIGNING_KEY se pasa por environment variable. En producción, iría a un vault (HashiCorp, AWS Secrets Manager). La rotación implica re-firmar eventos históricos — tenemos un replay engine para eso.

---

## 🎤 Cierre

> "Tracepath no es un producto todavía — es una prueba de que la auditoría de agentes no tiene que ser un afterthought. Se puede construir en un fin de semana con herramientas open-source. Y cuando la regulación llegue — porque ya está llegando — vas a necesitar algo como esto."

---

*Arma para la entrevista: Nadia Ujovich · [github.com/nujovich/tracepath](https://github.com/nujovich/tracepath)*