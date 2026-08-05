use actix_web::{web, App, HttpServer, HttpResponse, HttpRequest};
use awc::Client;
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{event, info, warn, Level};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use opa_wasm::{Policy, Runtime, DefaultContext};
use opa_wasm::wasmtime::{Engine as WasmEngine, Module, Store};
use aws_sdk_s3::Client as S3Client;
use aws_config::BehaviorVersion;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{TracerProvider, Config as TraceConfig};
use opentelemetry_otlp::WithExportConfig;
use async_nats::Client as NatsClient;

// ── Data models ──

#[derive(Debug, Deserialize, Serialize)]
struct AuditStep {
    session_id: String,
    agent_id: String,
    agent_type: Option<String>,
    step_number: u32,
    tool_name: String,
    tool_input: serde_json::Value,
    tool_output: serde_json::Value,
    timestamp: String,
    /// Accumulated cost so far in this session, in USD cents.
    /// Provider-agnostic: the caller (agent instrumentation) supplies it.
    /// Defaults to 0 when omitted (serde default for Option<u32>).
    #[serde(default)]
    spent_so_far_cents: Option<u32>,
    /// Optional metadata for LLM-backed tool calls. These fields are flat to
    /// keep the wire format easy to emit from framework callbacks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    llm_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    llm_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    llm_prompt_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    llm_completion_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    llm_total_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    llm_latency_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    llm_cost_cents: Option<f64>,
}

#[derive(Debug, PartialEq)]
struct GenAiSpanAttributes<'a> {
    system: Option<&'a str>,
    model: Option<&'a str>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    latency_ms: Option<f64>,
    cost_cents: Option<f64>,
}

impl<'a> From<&'a AuditStep> for GenAiSpanAttributes<'a> {
    fn from(event: &'a AuditStep) -> Self {
        Self {
            system: event.llm_provider.as_deref(),
            model: event.llm_model.as_deref(),
            input_tokens: event.llm_prompt_tokens,
            output_tokens: event.llm_completion_tokens,
            latency_ms: event.llm_latency_ms,
            cost_cents: event.llm_cost_cents,
        }
    }
}

fn record_gen_ai_attributes(span: &tracing::Span, event: &AuditStep) {
    let attributes = GenAiSpanAttributes::from(event);
    if let Some(value) = attributes.system {
        span.record("gen_ai.system", value);
    }
    if let Some(value) = attributes.model {
        span.record("gen_ai.request.model", value);
    }
    if let Some(value) = attributes.input_tokens {
        span.record("gen_ai.usage.input_tokens", value);
    }
    if let Some(value) = attributes.output_tokens {
        span.record("gen_ai.usage.output_tokens", value);
    }
    if let Some(value) = attributes.latency_ms {
        span.record("gen_ai.latency", value);
    }
    if let Some(value) = attributes.cost_cents {
        span.record("gen_ai.cost", value);
    }
}

#[derive(Debug, Serialize)]
struct AuditResponse {
    status: String,
    signature: String,
    policy_decision: Option<PolicyDecision>,
}

#[derive(Debug, Serialize, Clone)]
struct PolicyDecision {
    allowed: bool,
    denials: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    session_id: Option<String>,
    agent_id: Option<String>,
    tool_name: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

// ── App state ──

struct PolicyEngine {
    engine: WasmEngine,
    module: Module,
    store: Mutex<Store<()>>,
    policy: Policy<DefaultContext>,
}

struct AppState {
    signing_key: SigningKey,
    policy_engine: PolicyEngine,
    db_pool: sqlx::PgPool,
    s3_client: S3Client,
    worm_bucket: String,
    tracer_provider: Option<TracerProvider>,
    nats: Option<NatsClient>,
}

// ── Tracing + OpenTelemetry ──

/// Initializes tracing subscriber with optional OTLP export to LangFuse.
/// Returns a TracerProvider that must be kept alive — dropping it shuts down OTel.
fn init_tracing() -> Option<TracerProvider> {
    let otlp_enabled = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("tracepath_gateway=debug"));

    let fmt_layer = tracing_subscriber::fmt::layer().json();

    match otlp_enabled {
        Some(endpoint) => {
            let service_name = std::env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "tracepath-gateway".to_string());

            let mut headers = HashMap::new();
            if let Ok(raw) = std::env::var("OTEL_EXPORTER_OTLP_TRACES_HEADERS") {
                for part in raw.split(',') {
                    let mut seg = part.splitn(2, '=');
                    if let (Some(k), Some(v)) = (seg.next(), seg.next()) {
                        headers.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
            }

            match opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .http()
                        .with_endpoint(&endpoint)
                        .with_headers(headers),
                )
                .with_trace_config(
                    TraceConfig::default().with_resource(
                        opentelemetry_sdk::Resource::new(vec![
                            opentelemetry::KeyValue::new("service.name", service_name.clone()),
                        ]),
                    ),
                )
                .install_batch(opentelemetry_sdk::runtime::Tokio)
            {
                Ok(tracer_provider) => {
                    let tracer = tracer_provider.tracer("tracepath-gateway");
                    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(fmt_layer)
                        .with(otel_layer)
                        .init();

                    info!(%endpoint, %service_name, "OpenTelemetry OTLP export enabled → LangFuse");

                    Some(tracer_provider)
                }
                Err(err) => {
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(fmt_layer)
                        .init();

                    warn!(?err, "OpenTelemetry OTLP exporter failed — continuing without LangFuse export");
                    None
                }
            }
        }
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();

            info!("OpenTelemetry OTLP export disabled (set OTEL_EXPORTER_OTLP_ENDPOINT to enable)");

            None
        }
    }
}

// ── Ed25519 signing ──

fn canonical_event(event: &AuditStep) -> serde_json::Value {
    let mut canonical = serde_json::json!({
        "session_id": event.session_id,
        "agent_id": event.agent_id,
        "step_number": event.step_number,
        "tool_name": event.tool_name,
        "tool_input": event.tool_input,
        "tool_output": event.tool_output,
        "timestamp": event.timestamp,
    });

    let object = canonical
        .as_object_mut()
        .expect("canonical event is an object");
    macro_rules! insert_optional {
        ($name:literal, $value:expr) => {
            if let Some(value) = $value {
                object.insert($name.to_string(), serde_json::json!(value));
            }
        };
    }
    insert_optional!("llm_model", event.llm_model.as_deref());
    insert_optional!("llm_provider", event.llm_provider.as_deref());
    insert_optional!("llm_prompt_tokens", event.llm_prompt_tokens);
    insert_optional!("llm_completion_tokens", event.llm_completion_tokens);
    insert_optional!("llm_total_tokens", event.llm_total_tokens);
    insert_optional!("llm_latency_ms", event.llm_latency_ms);
    insert_optional!("llm_cost_cents", event.llm_cost_cents);

    canonical
}

fn sign_event(key: &SigningKey, event: &AuditStep) -> String {
    let canonical = canonical_event(event);
    let canonical_bytes = serde_json::to_vec(&canonical).expect("serialization failed");
    let signature = key.sign(&canonical_bytes);
    BASE64.encode(signature.to_bytes())
}

// ── OPA Policy Engine ──

async fn load_policy() -> PolicyEngine {
    let bundle_path = std::env::var("POLICY_BUNDLE_PATH")
        .unwrap_or_else(|_| "policies/bundle.tar.gz".to_string());

    let wasm_bytes = opa_wasm::read_bundle(&bundle_path)
        .await
        .expect(&format!("failed to read policy bundle at {}", bundle_path));

    info!(path = %bundle_path, "policy bundle loaded");

    let engine = WasmEngine::default();
    let module = Module::new(&engine, wasm_bytes)
        .expect("failed to compile OPA WASM module");

    let mut store = Store::new(&engine, ());

    let runtime = Runtime::new(&mut store, &module)
        .await
        .expect("failed to create OPA runtime");

    let policy = runtime.without_data(&mut store)
        .await
        .expect("failed to instantiate policy");

    info!("OPA WASM runtime initialized");

    PolicyEngine {
        engine,
        module,
        store: Mutex::new(store),
        policy,
    }
}

async fn evaluate_policy(engine: &PolicyEngine, input: &serde_json::Value) -> PolicyDecision {
    let mut store = engine.store.lock().await;

    let result: Result<serde_json::Value, _> = engine.policy.evaluate(
        &mut *store,
        "tracepath/main/decision",
        input,
    ).await;

    match result {
        Ok(val) => {
            // Debug: log the raw OPA result shape
            info!(
                raw_result_type = %std::any::type_name_of_val(&val),
                raw_result_preview = %format!("{:.200}", val),
                "OPA evaluate result"
            );
            let allowed = val[0]["result"]["allowed"].as_bool().unwrap_or(false);
            let denials: Vec<String> = val[0]["result"]["denials"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            PolicyDecision { allowed, denials }
        }
        Err(e) => {
            warn!(error = %e, "OPA evaluation failed");
            PolicyDecision {
                allowed: false,
                denials: vec![format!("policy engine error: {}", e)],
            }
        }
    }
}

// ── WORM archival (S3 with Object Lock) ──

async fn worm_archive(
    s3: &S3Client,
    bucket: &str,
    session_id: &str,
    step_number: u32,
    signature: &str,
    event: &AuditStep,
) -> Result<(), String> {
    let key = format!("{}/{}_{}.json", session_id, step_number, &signature[..16.min(signature.len())]);
    let body = serde_json::to_vec(event).map_err(|e| e.to_string())?;

    s3.put_object()
        .bucket(bucket)
        .key(&key)
        .body(body.into())
        .send()
        .await
        .map_err(|e| format!("S3 put_object failed: {}", e))?;

    info!(bucket = %bucket, key = %key, "archived to WORM storage");
    Ok(())
}

// ── NATS ──

async fn connect_nats() -> Option<NatsClient> {
    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    match async_nats::connect(&nats_url).await {
        Ok(client) => {
            info!(%nats_url, "NATS connected");
            Some(client)
        }
        Err(e) => {
            warn!(%nats_url, error = %e, "NATS connection failed — event streaming disabled");
            None
        }
    }
}

async fn publish_audit_event(
    nats: &Option<NatsClient>,
    event: &AuditStep,
    signature: &str,
    decision: &PolicyDecision,
) {
    let Some(client) = nats else { return };
    let payload = serde_json::json!({
        "session_id": event.session_id,
        "agent_id": event.agent_id,
        "agent_type": event.agent_type,
        "step_number": event.step_number,
        "tool_name": event.tool_name,
        "tool_input": event.tool_input,
        "tool_output": event.tool_output,
        "llm_model": event.llm_model,
        "llm_provider": event.llm_provider,
        "llm_prompt_tokens": event.llm_prompt_tokens,
        "llm_completion_tokens": event.llm_completion_tokens,
        "llm_total_tokens": event.llm_total_tokens,
        "llm_latency_ms": event.llm_latency_ms,
        "llm_cost_cents": event.llm_cost_cents,
        "timestamp": event.timestamp,
        "signature": signature,
        "policy_decision": {
            "allowed": decision.allowed,
            "denials": decision.denials,
        },
    });
    let subject = format!(
        "audit.events.{}",
        event.agent_type.as_deref().unwrap_or("default")
    );
    let data = serde_json::to_vec(&payload).unwrap_or_default();
    if let Err(e) = client.publish(subject.clone(), data.into()).await {
        warn!(%subject, error = %e, "NATS publish failed (non-fatal)");
    }
}

// ── Handlers ──

async fn audit_step(
    state: web::Data<Arc<AppState>>,
    body: web::Json<AuditStep>,
) -> HttpResponse {
    let event = body.into_inner();

    info!(
        session_id = %event.session_id,
        agent_id = %event.agent_id,
        step_number = event.step_number,
        tool_name = %event.tool_name,
        "audit step received"
    );

    // Critical path span: policy evaluation + signing.
    let (decision, sig_b64) = {
        let inner = tracing::info_span!(
            "audit_step",
            session_id = %event.session_id,
            agent_id = %event.agent_id,
            agent_type = %event.agent_type.as_deref().unwrap_or("default"),
            step_number = event.step_number,
            tool_name = %event.tool_name,
            policy.allowed = false,
            gen_ai.system = tracing::field::Empty,
            gen_ai.request.model = tracing::field::Empty,
            gen_ai.usage.input_tokens = tracing::field::Empty,
            gen_ai.usage.output_tokens = tracing::field::Empty,
            gen_ai.latency = tracing::field::Empty,
            gen_ai.cost = tracing::field::Empty,
        );
        record_gen_ai_attributes(&inner, &event);
        let _inner = inner.entered();

        let policy_input = serde_json::json!({
            "action": "audit_step",
            "agent_type": event.agent_type.as_deref().unwrap_or("default"),
            "tool_name": event.tool_name,
            "estimated_cost_cents": 0,
            "spent_so_far_cents": event.spent_so_far_cents.unwrap_or(0),
            "calls_last_minute": 0,
        });

        let decision = evaluate_policy(&state.policy_engine, &policy_input).await;
        tracing::Span::current().record("policy.allowed", decision.allowed);

        let sig_b64 = sign_event(&state.signing_key, &event);

        if !decision.allowed {
            tracing::event!(
                Level::WARN,
                session_id = %event.session_id,
                tool_name = %event.tool_name,
                denial_msgs = ?decision.denials,
                "policy denied audit step"
            );
        }

        (decision, sig_b64)
    };

    // Persistence spans — off the critical path.
    let _sql = tracing::info_span!("audit_step.persist").entered();
    let result = sqlx::query(
        "INSERT INTO audit_events (session_id, agent_id, agent_type, step_number, tool_name, tool_input, tool_output, signature, policy_decision,
                                   llm_model, llm_provider, llm_prompt_tokens, llm_completion_tokens, llm_total_tokens, llm_latency_ms, llm_cost_cents)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"
    )
    .bind(&event.session_id)
    .bind(&event.agent_id)
    .bind(&event.agent_type)
    .bind(event.step_number as i32)
    .bind(&event.tool_name)
    .bind(&event.tool_input)
    .bind(&event.tool_output)
    .bind(&sig_b64)
    .bind(&serde_json::to_string(&decision).unwrap_or_default())
    .bind(&event.llm_model)
    .bind(&event.llm_provider)
    .bind(event.llm_prompt_tokens)
    .bind(event.llm_completion_tokens)
    .bind(event.llm_total_tokens)
    .bind(event.llm_latency_ms)
    .bind(event.llm_cost_cents)
    .execute(&state.db_pool)
    .await;
    drop(_sql);

    if let Err(e) = result {
        warn!(error = %e, "failed to persist audit event");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": format!("persistence failed: {}", e),
            "signature": sig_b64,
        }));
    }

    let _nats = tracing::info_span!("audit_step.nats").entered();
    publish_audit_event(&state.nats, &event, &sig_b64, &decision).await;
    drop(_nats);

    if !decision.allowed {
        return HttpResponse::Forbidden().json(AuditResponse {
            status: "denied".to_string(),
            signature: sig_b64,
            policy_decision: Some(decision),
        });
    }

    let _worm = tracing::info_span!("audit_step.worm").entered();
    if let Err(e) = worm_archive(
        &state.s3_client,
        &state.worm_bucket,
        &event.session_id,
        event.step_number,
        &sig_b64,
        &event,
    )
    .await
    {
        warn!(error = %e, "failed to archive to WORM storage (non-fatal)");
    }
    drop(_worm);

    HttpResponse::Ok().json(AuditResponse {
        status: "recorded".to_string(),
        signature: sig_b64,
        policy_decision: Some(decision),
    })
}

async fn query_events(
    state: web::Data<Arc<AppState>>,
    query: web::Query<QueryParams>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50).min(500);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        "SELECT id, session_id, agent_id, agent_type, step_number, tool_name, signature, policy_decision,
                llm_model, llm_provider, llm_prompt_tokens, llm_completion_tokens, llm_total_tokens, llm_latency_ms, llm_cost_cents, created_at
         FROM audit_events WHERE 1=1"
    );

    let mut n = 1;

    if query.session_id.is_some() {
        sql.push_str(&format!(" AND session_id = ${}", n));
        n += 1;
    }
    if query.agent_id.is_some() {
        sql.push_str(&format!(" AND agent_id = ${}", n));
        n += 1;
    }
    if query.tool_name.is_some() {
        sql.push_str(&format!(" AND tool_name = ${}", n));
        n += 1;
    }

    sql.push_str(&format!(" ORDER BY created_at DESC LIMIT ${} OFFSET ${}", n, n + 1));

    #[derive(sqlx::FromRow)]
    struct AuditRow {
        id: uuid::Uuid,
        session_id: String,
        agent_id: String,
        agent_type: Option<String>,
        step_number: i32,
        tool_name: String,
        signature: String,
        policy_decision: Option<String>,
        llm_model: Option<String>,
        llm_provider: Option<String>,
        llm_prompt_tokens: Option<i64>,
        llm_completion_tokens: Option<i64>,
        llm_total_tokens: Option<i64>,
        llm_latency_ms: Option<f64>,
        llm_cost_cents: Option<f64>,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    let mut q = sqlx::query_as::<_, AuditRow>(&sql);

    if let Some(ref sid) = query.session_id {
        q = q.bind(sid);
    }
    if let Some(ref aid) = query.agent_id {
        q = q.bind(aid);
    }
    if let Some(ref tn) = query.tool_name {
        q = q.bind(tn);
    }
    q = q.bind(limit);
    q = q.bind(offset);

    let rows = q.fetch_all(&state.db_pool).await;

    match rows {
        Ok(events) => {
            let out: Vec<serde_json::Value> = events.iter().map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "session_id": r.session_id,
                    "agent_id": r.agent_id,
                    "agent_type": r.agent_type,
                    "step_number": r.step_number,
                    "tool_name": r.tool_name,
                    "signature": r.signature,
                    "policy_decision": r.policy_decision,
                    "llm_model": r.llm_model,
                    "llm_provider": r.llm_provider,
                    "llm_prompt_tokens": r.llm_prompt_tokens,
                    "llm_completion_tokens": r.llm_completion_tokens,
                    "llm_total_tokens": r.llm_total_tokens,
                    "llm_latency_ms": r.llm_latency_ms,
                    "llm_cost_cents": r.llm_cost_cents,
                    "created_at": r.created_at.to_rfc3339(),
                })
            }).collect();

            HttpResponse::Ok().json(serde_json::json!({
                "events": out,
                "count": out.len(),
                "limit": limit,
                "offset": offset,
            }))
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("query failed: {}", e),
            }))
        }
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok".to_string(),
        service: "tracepath-gateway".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn proxy_incidents(req: HttpRequest) -> HttpResponse {
    let client = Client::new();
    let qs = req.query_string();
    let incident_url = if qs.is_empty() {
        "http://incident:9004/api/incidents".to_string()
    } else {
        format!("http://incident:9004/api/incidents?{}", qs)
    };

    match client.get(&incident_url).send().await {
        Ok(mut res) => {
            let body = res.body().await.unwrap_or_default();
            HttpResponse::Ok()
                .content_type("application/json")
                .body(body)
        }
        Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "incident service unavailable"
        })),
    }
}

async fn proxy_reports(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let client = Client::new();
    let path = req.path();
    let qs = req.query_string();

    let target_path = if path == "/reports/generate" {
        "http://incident:9004/api/reports/generate"
    } else {
        // /reports → list, /reports/{name} → serve file
        let rest = path.strip_prefix("/reports").unwrap_or("");
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        if rest.is_empty() {
            "http://incident:9004/api/reports"
        } else {
            // URL-encode the filename segment
            &format!("http://incident:9004/api/reports/{}", rest)
        }
    };

    let target_url = if qs.is_empty() {
        target_path.to_string()
    } else {
        format!("{}?{}", target_path, qs)
    };

    let result = match req.method().as_str() {
        "GET" => client.get(&target_url).send().await,
        "POST" => client.post(&target_url).send_body(body.to_vec()).await,
        _ => {
            return HttpResponse::MethodNotAllowed().json(serde_json::json!({
                "error": "method not allowed"
            }))
        }
    };

    match result {
        Ok(mut res) => {
            let resp_body = res.body().await.unwrap_or_default();
            let ct = res
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json");
            HttpResponse::Ok().content_type(ct).body(resp_body)
        }
        Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "incident service unavailable"
        })),
    }
}

async fn proxy_gemini(req: HttpRequest) -> HttpResponse {
    let client = Client::new();
    let qs = req.query_string();
    let url = if qs.is_empty() {
        "http://incident:9004/api/gemini/status".to_string()
    } else {
        format!("http://incident:9004/api/gemini/status?{}", qs)
    };

    match client.get(&url).send().await {
        Ok(mut res) => {
            let body = res.body().await.unwrap_or_default();
            HttpResponse::Ok().content_type("application/json").body(body)
        }
        Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "incident service unavailable"
        })),
    }
}

async fn proxy_policies(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    let client = Client::new();
    let path = req.path();
    // Strip /policies prefix → forward to policy service's /api/policies/...
    let target_path = path.replacen("/policies", "/api/policies", 1);
    let qs = req.query_string();
    let policy_url = if qs.is_empty() {
        format!("http://policies:9003{}", target_path)
    } else {
        format!("http://policies:9003{}?{}", target_path, qs)
    };

    let result = match req.method().as_str() {
        "GET" => client.get(&policy_url).send().await,
        "POST" => client.post(&policy_url).send_body(body.to_vec()).await,
        _ => {
            return HttpResponse::MethodNotAllowed().json(serde_json::json!({
                "error": "method not allowed"
            }))
        }
    };

    match result {
        Ok(mut res) => {
            let resp_body = res.body().await.unwrap_or_default();
            HttpResponse::Ok()
                .content_type("application/json")
                .body(resp_body)
        }
        Err(_) => HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "policy service unavailable"
        })),
    }
}

async fn policy_health(state: web::Data<Arc<AppState>>) -> HttpResponse {
    let test_input = serde_json::json!({
        "action": "health_check",
        "agent_type": "default",
        "tool_name": "read_file",
        "estimated_cost_cents": 0,
        "spent_so_far_cents": 0,
        "calls_last_minute": 0,
    });
    let decision = evaluate_policy(&state.policy_engine, &test_input).await;
    HttpResponse::Ok().json(serde_json::json!({
        "policy_engine": "ok",
        "smoke_test": decision,
    }))
}

// ── Main ──

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    let tracer_provider = init_tracing();

    // Signing key
    let signing_key_hex = std::env::var("AUDIT_SIGNING_KEY")
        .expect("AUDIT_SIGNING_KEY must be set (64 hex chars, 32-byte Ed25519 seed)");
    let key_bytes = hex::decode(&signing_key_hex)
        .expect("AUDIT_SIGNING_KEY must be valid hex");
    let key_array: [u8; 32] = key_bytes.try_into()
        .expect("AUDIT_SIGNING_KEY must be exactly 32 bytes");
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    info!(
        verifying_key = %hex::encode(verifying_key.to_bytes()),
        "gateway signing key loaded"
    );

    // OPA policy engine (async load)
    let policy_engine = load_policy().await;

    // PostgreSQL connection
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let db_pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("failed to connect to PostgreSQL");

    info!("PostgreSQL connected");

    // Run migrations — split by statement because sqlx::query rejects multi-statement SQL
    for stmt in include_str!("../../docker/init.sql")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sqlx::query(stmt)
            .execute(&db_pool)
            .await
            .expect("failed to run migration statement");
    }

    info!("schema migration applied");

    // S3 client for WORM storage
    let worm_bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "tracepath-worm".to_string());
    let s3_endpoint = std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string());
    let s3_region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let aws_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
        .endpoint_url(&s3_endpoint)
        .force_path_style(true)
        .region(aws_types::region::Region::new(s3_region.clone()))
        .build();
    let s3_client = S3Client::from_conf(s3_config);

    info!(endpoint = %s3_endpoint, bucket = %worm_bucket, region = %s3_region, "S3 WORM client initialized");

    // NATS connection (optional)
    let nats = connect_nats().await;

    let state = Arc::new(AppState {
        signing_key,
        policy_engine,
        db_pool,
        s3_client,
        worm_bucket,
        tracer_provider,
        nats,
    });

    let state_for_shutdown = state.clone(); // kept for graceful OTel shutdown

    let host = std::env::var("GATEWAY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("GATEWAY_PORT")
        .unwrap_or_else(|_| "9001".to_string())
        .parse()
        .expect("GATEWAY_PORT must be valid");

    info!(host = %host, port = port, "listening");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/health", web::get().to(health))
            .route("/health/policy", web::get().to(policy_health))
            .route("/audit/step", web::post().to(audit_step))
            .route("/audit/events", web::get().to(query_events))
            .route("/incidents", web::get().to(proxy_incidents))
            .route("/reports", web::get().to(proxy_reports))
            .route("/reports/generate", web::post().to(proxy_reports))
            .route("/reports/{tail:.*}", web::get().to(proxy_reports))
            .route("/gemini", web::get().to(proxy_gemini))
            .route("/policies/{tail:.*}", web::route().to(proxy_policies))
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await?;

    // Graceful shutdown: flush and drop OTel tracer provider
    if let Some(ref tp) = state_for_shutdown.tracer_provider {
        info!("shutting down OpenTelemetry tracer provider");
        tp.shutdown().expect("failed to shutdown tracer provider");
    }
    // Drain NATS connection
    if let Some(ref nats) = state_for_shutdown.nats {
        info!("draining NATS connection");
        let _ = nats.drain().await;
    }
    info!("gateway stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_json() -> serde_json::Value {
        serde_json::json!({
            "session_id": "session-1",
            "agent_id": "agent-1",
            "step_number": 1,
            "tool_name": "search",
            "tool_input": {"query": "otel"},
            "tool_output": {"count": 2},
            "timestamp": "2026-08-05T00:00:00Z"
        })
    }

    #[test]
    fn legacy_audit_step_payload_remains_valid() {
        let event: AuditStep = serde_json::from_value(event_json()).unwrap();

        assert_eq!(event.llm_model, None);
        assert_eq!(event.llm_prompt_tokens, None);
        assert_eq!(event.llm_cost_cents, None);
        assert!(!canonical_event(&event)
            .as_object()
            .unwrap()
            .contains_key("llm_model"));
    }

    #[test]
    fn maps_llm_metadata_to_gen_ai_span_attributes() {
        let mut payload = event_json();
        let object = payload.as_object_mut().unwrap();
        object.insert("llm_model".into(), "gemini-2.5-flash".into());
        object.insert("llm_provider".into(), "google".into());
        object.insert("llm_prompt_tokens".into(), 120.into());
        object.insert("llm_completion_tokens".into(), 30.into());
        object.insert("llm_total_tokens".into(), 150.into());
        object.insert("llm_latency_ms".into(), 245.5.into());
        object.insert("llm_cost_cents".into(), 0.42.into());

        let event: AuditStep = serde_json::from_value(payload).unwrap();

        assert_eq!(
            GenAiSpanAttributes::from(&event),
            GenAiSpanAttributes {
                system: Some("google"),
                model: Some("gemini-2.5-flash"),
                input_tokens: Some(120),
                output_tokens: Some(30),
                latency_ms: Some(245.5),
                cost_cents: Some(0.42),
            }
        );
        assert_eq!(event.llm_total_tokens, Some(150));
        assert_eq!(
            canonical_event(&event)["llm_model"],
            serde_json::json!("gemini-2.5-flash")
        );
    }

    #[test]
    fn omits_missing_llm_metadata_when_serializing() {
        let event: AuditStep = serde_json::from_value(event_json()).unwrap();
        let serialized = serde_json::to_value(event).unwrap();

        assert!(!serialized.as_object().unwrap().contains_key("llm_model"));
        assert!(!serialized
            .as_object()
            .unwrap()
            .contains_key("llm_cost_cents"));
    }
}
