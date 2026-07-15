# LinkedIn Post — Tracepath (Spanish)

---

## POST PRINCIPAL

🚀 Construí esto en un fin de semana. Y creo que resolví un problema que nadie está mirando.

**Tracepath: middleware open-source para auditar agentes de IA.**

---

Hace 10 años me especializaba en seguridad web. OWASP Top 10. XSS, CSRF, DoS. Mi trabajo era decir "no" — dibujar la línea entre lo permitido y lo prohibido.

Después me enamoré de los agentes de IA. Sistemas que razonan, usan herramientas, toman decisiones. Pero la parte de seguridad en mí no se callaba:

👉 ¿Cómo sabés qué hizo tu agente ayer?
👉 ¿Qué pasa si llama una herramienta que no debería?
👉 ¿Cómo demostrás compliance a un regulador?

**El EU AI Act lo deja claro.** Artículo 50: sistemas de IA de alto riesgo deben registrar eventos, permitir supervisión humana y garantizar trazabilidad.

Así que construí Tracepath. En 48 horas.

---

**¿Qué hace?**

Cada tool call de tu agente pasa por un gateway que lo firma con Ed25519, lo chequea contra políticas OPA, lo almacena en WORM (inmutable) y lo monitorea en tiempo real. Si algo huele raro — muchas denegaciones, presupuesto excedido, rate limit violado — salta una alerta.

Y Gemini 2.5 Flash le pone contexto: "esto no es un ataque, es un bug de configuración."

---

**El stack:**

⚙️ Rust + actix-web — el gateway de auditoría
🐍 Python + NATS JetStream — el detector de incidentes
⚛️ React + TypeScript — el dashboard (5 tabs)
🛡️ OPA WASM — políticas en <1ms
📦 PostgreSQL + MinIO WORM — almacenamiento inmutable
🧠 Gemini 2.5 Flash — clasificación semántica de incidentes

Todo en un `docker compose up`.

---

**¿Por qué importa?**

El 3 de julio, Daniel Avila publicó "The invisible crisis in AI Observability". Su tesis: cuando un agente falla o explota en costos, los equipos no tienen visibilidad. Esto ya se resolvió en software tradicional hace 10 años. En AI agents, no.

Tracepath es la respuesta.

---

**¿Qué sigue?**

No es un producto. Es una prueba de que la auditoría de agentes no tiene que ser un afterthought. Se puede construir en un finde con herramientas open-source. Y cuando la regulación llegue — porque ya está llegando — vas a necesitar algo como esto.

Si te interesa, el repo es público. Si querés contribuir, las issues están abiertas. Si querés charlar, mis DMs también.

---

## COMENTARIO 1 (inmediatamente después de publicar)

🔗 **Repo:** github.com/nujovich/tracepath
📝 **Blog post completo (DEV Challenge):** https://dev.to/nujovich/tracepath-i-built-an-ai-agent-audit-middleware-in-one-weekend-foi
🎥 **Demo en 1 minuto:** YouTube

---

## COMENTARIO 2 (opcional, para engagement)

¿Tu equipo ya está pensando en cómo auditar agentes? ¿O es "lo vemos después"? 👇