// crates/hsip-cli/src/identity.rs
use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, Mac};
use jwt::{Header, SignWithKey, Token};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

static HSIP_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    let k = std::env::var("HSIP_LOCAL_JWT_KEY_HEX").unwrap_or_else(|_| {
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string()
    });
    hex::decode(k).expect("bad HSIP_LOCAL_JWT_KEY_HEX")
});

#[derive(Serialize)]
struct Status {
    ok: bool,
    version: &'static str,
}

#[derive(Deserialize)]
struct TokenReq {
    aud: Option<String>,
}

#[derive(Serialize)]
struct TokenResp {
    token: String,
}

pub async fn run_identity_broker() -> anyhow::Result<()> {
    let app = Router::new()
        .route(
            "/status",
            get(|| async {
                Json(Status {
                    ok: true,
                    version: "0.2.0-mvp",
                })
            }),
        )
        .route("/token", post(token))
        .route("/demo", get(demo))
        .layer(DefaultBodyLimit::disable());

    let addr_str =
        std::env::var("HSIP_IDENTITY_ADDR").unwrap_or_else(|_| "127.0.0.1:9100".to_string());
    let addr: SocketAddr = addr_str.parse()?;
    println!("[IDENTITY] serving on http://{addr}  (endpoints: /status, /token, /demo)");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn token(Json(req): Json<TokenReq>) -> impl IntoResponse {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = now + 5 * 60;
    let claims = serde_json::json!({
        "iss": "hsip://local",
        "sub": "hsip:demo",
        "iat": now,
        "exp": exp,
        "aud": req.aud.unwrap_or_else(|| "http://localhost".into())
    });

    let key = HmacSha256::new_from_slice(&HSIP_KEY).unwrap();
    let signed = Token::new(Header::default(), claims)
        .sign_with_key(&key)
        .unwrap();
    let token_str: String = signed.into(); // 👈 convert to String

    Json(TokenResp { token: token_str })
}

async fn demo() -> impl IntoResponse {
    Html(
        r#"<!doctype html><meta charset="utf-8" />
<title>HSIP Demo Login</title>
<style>body{font:16px system-ui;margin:40px} .card{max-width:520px;padding:20px;border:1px solid #ddd;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.06)}</style>
<div class="card">
  <h2>Login with HSIP (prototype)</h2>
  <p>No username or password. We request a short-lived local token.</p>
  <button id="btn">Sign in with HSIP</button>
  <pre id="out" style="margin-top:16px;white-space:pre-wrap"></pre>
</div>
<script>
const out = document.getElementById('out');
document.getElementById('btn').onclick = async () => {
  try {
    const r = await fetch('/token', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({aud: location.origin})});
    if (!r.ok) { out.textContent = 'HSIP token error.'; return; }
    const { token } = await r.json();
    out.textContent = 'Login success. Token (truncated):\\n' + token.slice(0, 80) + '...';
  } catch (e) {
    out.textContent = 'HSIP local service not running.';
  }
};
</script>
"#,
    )
}
