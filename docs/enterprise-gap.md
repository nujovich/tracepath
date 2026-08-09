# Enterprise Gap Analysis — Tracepath

## Findings OSS comunes

- Seguridad/billing atado a la persona, no a la org
- Documentación de instalación real sin tutorial feliz
- Observabilidad operativa del producto, no solo del cliente
- Testing de contratos, no solo unit tests
- Onboarding autoservicio sin intervención manual

## Lo que falta para enterprise

### Security
- Rotación de credenciales documentada y automatizada
- `AUDIT_SIGNING_KEY` con generación guiada; hoy es placeholder o hardcodeado
- Scopes/permisos por servicio en docker-compose

### Reliability
- Health checks reales por servicio (gateway, NATS, Postgres, MinIO, otel-collector)
- Estrategia de migraciones de schema DB con versionado
- Reintentos y backoff en NATS/S3
- Límite de cola/backpressure para no saturar el gateway

### Observabilidad operativa
- Métricas propias del gateway: latency p99, tasa OPA allow/deny, errores de firma, errores de persistencia
- Dashboards/alertas para SRE

### Gobernanza de policies
- `POLICY_BUNDLE_PATH` documentado con flujo de actualización sin downtime
- Rollback de policies y auditoría de cambios

### Soporte y SLA
- Guía de upgrade entre versiones
- RUNBOOKs para incidentes comunes
- Soporte comercial o community SLA
