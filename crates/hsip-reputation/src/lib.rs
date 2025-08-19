use blake3::Hasher;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::Signer; // needed for sk.sign(...)
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum RepError {
    #[error("{0}")]
    Msg(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Decision {
    Allow { ttl_ms: u64 },
    Deny,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub idx: u64,
    pub prev_hash_hex: String,
    pub ts_ms: u64,

    // What was decided
    pub decision: Decision,

    // Optional context (helps with forensics)
    pub content_cid_hex: String,
    pub purpose: String,
    pub requester_peer_id: String,

    // Who signed this entry
    pub signer_pubkey_hex: String,

    // Integrity/auth
    pub entry_hash_hex: String, // hash of the preimage
    pub signature_hex: String,  // sig over the preimage
}

fn hash_preimage(pre: &str) -> String {
    let mut h = Hasher::new();
    h.update(pre.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

fn make_preimage(
    idx: u64,
    prev_hash_hex: &str,
    ts_ms: u64,
    decision: &Decision,
    content_cid_hex: &str,
    purpose: &str,
    requester_peer_id: &str,
    signer_pubkey_hex: &str,
) -> String {
    // Stable, explicit preimage (no serde ordering ambiguity)
    // Format: key=value lines, newline-separated.
    format!(
        "idx={}\nprev={}\nts={}\ndecision={}\ncid={}\npurpose={}\nreq_pid={}\nsigner={}",
        idx,
        prev_hash_hex,
        ts_ms,
        match decision {
            Decision::Allow { ttl_ms } => format!("allow:ttl_ms={ttl_ms}"),
            Decision::Deny => "deny".to_string(),
        },
        content_cid_hex,
        purpose,
        requester_peer_id,
        signer_pubkey_hex
    )
}

fn sign_preimage(sk: &SigningKey, pre: &str) -> String {
    let sig = sk.sign(pre.as_bytes());
    hex::encode(sig.to_bytes())
}

fn verify_signature(vk: &VerifyingKey, pre: &str, sig_hex: &str) -> Result<(), RepError> {
    let bytes = hex::decode(sig_hex).map_err(|e| RepError::Msg(format!("sig hex: {e}")))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| RepError::Msg("sig len".into()))?;
    let sig = Signature::from_bytes(&arr);
    vk.verify_strict(pre.as_bytes(), &sig)
        .map_err(|e| RepError::Msg(format!("sig verify: {e}")))
}

fn read_log(path: &str) -> Result<Vec<LogEntry>, RepError> {
    if !std::path::Path::new(path).exists() {
        return Ok(vec![]);
    }
    let data = std::fs::read_to_string(path).map_err(|e| RepError::Msg(format!("read log: {e}")))?;
    let mut out = Vec::new();
    for (i, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let e: LogEntry = serde_json::from_str(line)
            .map_err(|e| RepError::Msg(format!("json L{}: {e}", i + 1)))?;
        out.push(e);
    }
    Ok(out)
}

fn append_line(path: &str, line: &str) -> Result<(), RepError> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| RepError::Msg(format!("open log: {e}")))?;
    writeln!(f, "{}", line).map_err(|e| RepError::Msg(format!("write log: {e}")))?;
    Ok(())
}

pub fn append_decision(
    log_path: &str,
    sk: &SigningKey,
    vk: &VerifyingKey,
    ts_ms: u64,
    decision: Decision,
    content_cid_hex: String,
    purpose: String,
    requester_peer_id: String,
) -> Result<LogEntry, RepError> {
    let signer_pubkey_hex = hex::encode(vk.as_bytes());
    let existing = read_log(log_path)?;
    let (idx, prev_hash_hex) = if let Some(last) = existing.last() {
        (last.idx + 1, last.entry_hash_hex.clone())
    } else {
        (0, String::from("0".repeat(64))) // all-zero for genesis prev
    };

    let pre = make_preimage(
        idx,
        &prev_hash_hex,
        ts_ms,
        &decision,
        &content_cid_hex,
        &purpose,
        &requester_peer_id,
        &signer_pubkey_hex,
    );
    let entry_hash_hex = hash_preimage(&pre);
    let signature_hex = sign_preimage(sk, &pre);

    let entry = LogEntry {
        idx,
        prev_hash_hex,
        ts_ms,
        decision,
        content_cid_hex,
        purpose,
        requester_peer_id,
        signer_pubkey_hex,
        entry_hash_hex,
        signature_hex,
    };

    let line = serde_json::to_string(&entry).map_err(|e| RepError::Msg(format!("to json: {e}")))?;
    append_line(log_path, &line)?;
    Ok(entry)
}

pub fn verify_log(log_path: &str) -> Result<(), RepError> {
    let items = read_log(log_path)?;
    if items.is_empty() {
        return Ok(());
    }
    for (i, e) in items.iter().enumerate() {
        // prev hash continuity
        if i == 0 {
            if e.prev_hash_hex != "0".repeat(64) {
                return Err(RepError::Msg(format!(
                    "entry {} prev hash must be zeros",
                    e.idx
                )));
            }
        } else {
            let prev = &items[i - 1];
            if e.prev_hash_hex != prev.entry_hash_hex {
                return Err(RepError::Msg(format!(
                    "entry {} prev hash mismatch",
                    e.idx
                )));
            }
        }
        // recompute hash
        let pre = make_preimage(
            e.idx,
            &e.prev_hash_hex,
            e.ts_ms,
            &e.decision,
            &e.content_cid_hex,
            &e.purpose,
            &e.requester_peer_id,
            &e.signer_pubkey_hex,
        );
        let want = hash_preimage(&pre);
        if want != e.entry_hash_hex {
            return Err(RepError::Msg(format!("entry {} hash mismatch", e.idx)));
        }
        // signature check using embedded signer key
        let vk_bytes = hex::decode(&e.signer_pubkey_hex)
            .map_err(|er| RepError::Msg(format!("signer vk hex: {er}")))?;
        let vk = VerifyingKey::from_bytes(
            &vk_bytes
                .try_into()
                .map_err(|_| RepError::Msg("vk len".into()))?,
        )
        .map_err(|er| RepError::Msg(format!("vk parse: {er}")))?;
        verify_signature(&vk, &pre, &e.signature_hex)?;
    }
    Ok(())
}

pub fn read_all(log_path: &str) -> Result<Vec<LogEntry>, RepError> {
    read_log(log_path)
}
