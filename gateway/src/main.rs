use actix_web::{web, App, HttpServer, HttpResponse};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

#[derive(Debug, Deserialize)]
struct AuditStep {
    session_id: String,
    agent_id: String,
    step_number: u32,
    tool_name: String,
    tool_input: serde_json::Value,
    tool_output: serde_json::Value,
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct AuditResponse {
    status: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    service: String,
}

struct AppState {
    signing_key: SigningKey,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tracepath_gateway=debug")),
        )
        .init();
}

fn sign_event(key: &SigningKey, event: &AuditStep) -> String {
    let canonical = serde_json::json!({
        "session_id": event.session_id,
        "agent_id": event.agent_id,
        "step_number": event.step_number,
        "tool_name": event.tool_name,
        "tool_input": event.tool_input,
        "tool_output": event.tool_output,
        "timestamp": event.timestamp,
    });

    let canonical_bytes = serde_json::to_vec(&canonical).expect("serialization failed");
    let signature = key.sign(&canonical_bytes);
    BASE64.encode(signature.to_bytes())
}

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

    let sig_b64 = sign_event(&state.signing_key, &event);

    HttpResponse::Ok().json(AuditResponse {
        status: "recorded".to_string(),
        signature: sig_b64,
    })
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok".to_string(),
        service: "tracepath-gateway".to_string(),
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

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

    let state = Arc::new(AppState { signing_key });

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
            .route("/audit/step", web::post().to(audit_step))
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}
