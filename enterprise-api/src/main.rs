//! B4AE Enterprise Control Plane MVP
//!
//! Minimal REST API for audit events. Production would connect to
//! persisted AuditSink storage (DB, SIEM).

use axum::{
    extract::Query,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use std::net::SocketAddr;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize)]
struct AuditEventItem {
    timestamp_ms: u64,
    event_type: String,
    peer_id_hash: Option<String>,
    context: Option<String>,
}

#[derive(Serialize)]
struct AuditListResponse {
    events: Vec<AuditEventItem>,
    total: usize,
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/audit/events", get(audit_events))
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("B4AE Enterprise API listening on http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn audit_events(
    Query(params): Query<AuditQuery>,
) -> (StatusCode, Json<AuditListResponse>) {
    let _limit = params.limit.unwrap_or(50).min(500);
    let _offset = params.offset.unwrap_or(0);

    // MVP: return empty list. Production: query DB from AuditSink.
    let events: Vec<AuditEventItem> = vec![];
    (
        StatusCode::OK,
        Json(AuditListResponse {
            total: events.len(),
            events,
        }),
    )
}
