use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
            eprintln!(
                "[daemon] failed to parse gateway metrics {}: {e}",
                path.display()
            );
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
        Json, Router,
    };
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use hex;

    type HmacSha256 = Hmac<Sha256>;

    /// HMAC key for response integrity (should be loaded from secure storage in production)
    const RESPONSE_HMAC_KEY: &[u8] = b"HSIP-DAEMON-RESPONSE-INTEGRITY-KEY-V1-CHANGE-IN-PRODUCTION";

    /// Signed response wrapper with HMAC for integrity
    #[derive(Serialize)]
    struct SignedResponse<T: Serialize> {
        data: T,
        signature: String,
        #[serde(rename = "sig_alg")]
        signature_algorithm: String,
    }

    /// Generate HMAC-SHA256 signature for response data
    fn sign_response<T: Serialize>(data: &T) -> Result<String, String> {
        let json_bytes = serde_json::to_vec(data).map_err(|e| e.to_string())?;
        let mut mac = HmacSha256::new_from_slice(RESPONSE_HMAC_KEY)
            .map_err(|e| e.to_string())?;
        mac.update(&json_bytes);
        let signature = mac.finalize().into_bytes();
        Ok(hex::encode(signature))
    }

    /// Create a signed response with HMAC integrity protection
    fn create_signed_response<T: Serialize>(data: T) -> Result<impl IntoResponse, axum::http::StatusCode> {
        let signature = sign_response(&data).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(SignedResponse {
            data,
            signature,
            signature_algorithm: "HMAC-SHA256".to_string(),
        }))
    }

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
        create_signed_response(s).unwrap_or_else(|code| {
            (code, Json(serde_json::json!({"error": "signature_failed"}))).into_response()
        })
    }

    async fn get_sessions() -> impl IntoResponse {
        let sessions = vec![SessionView {
            peer: "NYTFBVDZFNSMDASRNINFBTWZJ4".into(),
            age_secs: 42,
            bytes_in: 11111,
            bytes_out: 22222,
            cipher: "ChaCha20-Poly1305".into(),
        }];
        create_signed_response(sessions).unwrap_or_else(|code| {
            (code, Json(serde_json::json!({"error": "signature_failed"}))).into_response()
        })
    }

    async fn post_consent_grant(
        Json(req): Json<GrantRequest>,
    ) -> impl IntoResponse {
        // TODO: call your real token issuer; stubbed token:
        let token = format!(
            "cap::{}/{}::{}",
            req.grantee_pubkey_hex, req.purpose, req.expires_ms
        );
        let response = GrantResponse { token };
        create_signed_response(response).unwrap_or_else(|code| {
            (code, Json(serde_json::json!({"error": "signature_failed"}))).into_response()
        })
    }

    async fn post_consent_revoke(
        Json(req): Json<RevokeRequest>,
    ) -> impl IntoResponse {
        // TODO: kill session(s) by req.peer_id via your session manager
        let response = serde_json::json!({"ok": true, "revoked_for": req.peer_id});
        create_signed_response(response).unwrap_or_else(|code| {
            (code, Json(serde_json::json!({"error": "signature_failed"}))).into_response()
        })
    }

    async fn get_reputation(
        Path(peer_id): Path<String>,
    ) -> impl IntoResponse {
        // TODO: query real reputation
        let response = ReputationResponse {
            peer_id,
            score: 0,
            last_seen: chrono::Utc::now().to_rfc3339(),
        };
        create_signed_response(response).unwrap_or_else(|code| {
            (code, Json(serde_json::json!({"error": "signature_failed"}))).into_response()
        })
    }
}
