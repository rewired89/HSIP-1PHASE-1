use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Default)]
pub struct AppState {
    inner: Arc<Mutex<Status>>,
    // TODO: wire these to real managers later
    // sessions: ...
    // reputation: ...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub protected: bool,
    pub active_sessions: u32,
    pub egress_peer: String,
    pub cipher: String,
    pub since: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub path: Vec<String>,

    // HSIP shield metrics (UDP guard + gateway)
    pub blocked_connections: u64,
    pub blocked_ips: u64,
    pub blocked_trackers: u64,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            protected: false,
            active_sessions: 0,
            egress_peer: "".into(),
            cipher: "ChaCha20-Poly1305".into(),
            since: "".into(),
            bytes_in: 0,
            bytes_out: 0,
            path: vec!["Local".into()],
            blocked_connections: 0,
            blocked_ips: 0,
            blocked_trackers: 0,
        }
    }
}

/// Read HSIP Web Gateway metrics from ~/.hsip/gateway_metrics.json
#[derive(Debug, Deserialize)]
struct GatewayMetricsFile {
    #[serde(default)]
    blocked_trackers: u64,
}

fn gateway_metrics_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".hsip").join("gateway_metrics.json")
}

fn read_blocked_trackers() -> u64 {
    let path = gateway_metrics_path();
    let data = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match serde_json::from_str::<GatewayMetricsFile>(&data) {
        Ok(m) => m.blocked_trackers,
        Err(e) => {
            eprintln!("[daemon] failed to parse gateway metrics {}: {e}", path.display());
            0
        }
    }
}

/// TODO: wire to real session metrics later.
pub fn snapshot_status() -> Status {
    Status {
        protected: true,
        active_sessions: 1,
        egress_peer: "NYTFBVDZFNSMDASRNINFBTWZJ4".into(),
        cipher: "ChaCha20-Poly1305".into(),
        since: chrono::Utc::now().to_rfc3339(),
        bytes_in: 123456,
        bytes_out: 234567,
        path: vec!["Local".into(), "HSIP".into(), "Exit-GW-1".into()],

        // UDP guard metrics (placeholder for now)
        blocked_connections: 0,
        blocked_ips: 0,

        // HSIP Web Gateway metrics (real from file)
        blocked_trackers: read_blocked_trackers(),
    }
}

pub mod http {
    use super::*;
    use axum::{
        extract::{Path, State},
        response::IntoResponse,
        routing::{get, post},
        Json, Router
    };
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    #[derive(Debug, Deserialize)]
    struct GrantRequest {
        grantee_pubkey_hex: String,
        purpose: String,
        expires_ms: u64,
    }

    #[derive(Debug, Serialize)]
    struct GrantResponse {
        token: String,
    }

    #[derive(Debug, Deserialize)]
    struct RevokeRequest {
        peer_id: String,
    }

    #[derive(Debug, Serialize, Default)]
    struct ReputationResponse {
        peer_id: String,
        score: i32,
        last_seen: String,
    }

    #[derive(Serialize)]
    struct SessionView {
        peer: String,
        age_secs: u64,
        bytes_in: u64,
        bytes_out: u64,
        cipher: String,
    }

    pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
        let state = AppState::default();

        {
            let mut g = state.inner.lock().unwrap();
            *g = super::snapshot_status();
        }

        let app = Router::new()
            .route("/status", get(get_status))
            .route("/sessions", get(get_sessions))
            .route("/consent/grant", post(post_consent_grant))
            .route("/consent/revoke", post(post_consent_revoke))
            .route("/reputation/:peer_id", get(get_reputation))
            .with_state(state);

        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }

    async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
        let s = state.inner.lock().unwrap().clone();
        Json(s)
    }

    async fn get_sessions() -> impl IntoResponse {
        let sessions = vec![SessionView {
            peer: "NYTFBVDZFNSMDASRNINFBTWZJ4".into(),
            age_secs: 42,
            bytes_in: 11111,
            bytes_out: 22222,
            cipher: "ChaCha20-Poly1305".into(),
        }];
        Json(sessions)
    }

    async fn post_consent_grant(
        Json(req): Json<GrantRequest>,
    ) -> Result<Json<GrantResponse>, axum::http::StatusCode> {
        // TODO: call your real token issuer; stubbed token:
        let token = format!("cap::{}/{}::{}", req.grantee_pubkey_hex, req.purpose, req.expires_ms);
        Ok(Json(GrantResponse { token }))
    }

    async fn post_consent_revoke(
        Json(req): Json<RevokeRequest>,
    ) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
        // TODO: kill session(s) by req.peer_id via your session manager
        Ok(Json(serde_json::json!({"ok": true, "revoked_for": req.peer_id})))
    }

    async fn get_reputation(
        Path(peer_id): Path<String>,
    ) -> Result<Json<ReputationResponse>, axum::http::StatusCode> {
        // TODO: query real reputation
        Ok(Json(ReputationResponse {
            peer_id,
            score: 0,
            last_seen: chrono::Utc::now().to_rfc3339(),
        }))
    }
}
