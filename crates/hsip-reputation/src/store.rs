use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use fs2::FileExt; // for file locking (cross-platform)
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionType {
    TRUSTED,
    VERIFIED_ID,
    GOOD_BEHAVIOR,
    NOTE,
    APPEAL,
    REVERSAL,
    SPAM,
    MALFORMED,
    TIMEOUT,
    MISBEHAVIOR,
    REPLAY,
    INVALID_SIG,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,   // e.g., "pcap_hash"
    pub value: String,  // e.g., "sha256:..."
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub version: u32,
    pub event_id: String,        // uuid
    pub ts: String,              // timestamp
    pub actor_peer_id: String,
    pub subject_peer_id: String,
    pub decision_type: DecisionType,
    pub severity: u8,            // 0..3
    pub reason_code: String,
    pub reason_text: String,
    pub evidence: Vec<Evidence>,
    pub ttl: Option<String>,
    pub weight: i32,
    pub prev_hash: String,       // sha256 hex of previous line
    pub sig: String,             // hex of ed25519 signature
}

fn to_canonical_json<T: Serialize>(v: &T) -> anyhow::Result<Vec<u8>> {
    let s = serde_json::to_string(v)?;
    Ok(s.into_bytes())
}

fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}s", now)
}

#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let p = path.as_ref();
        if let Some(dir) = p.parent() { std::fs::create_dir_all(dir)?; }
        if !p.exists() {
            #[cfg(unix)] {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new().create(true).write(true).mode(0o600).open(p)?;
            }
            #[cfg(not(unix))] {
                OpenOptions::new().create(true).write(true).open(p)?;
            }
        }
        Ok(Self { path: p.to_path_buf() })
    }

    fn last_line_and_hash(&self) -> anyhow::Result<(Option<String>, String)> {
        let file = OpenOptions::new().read(true).open(&self.path)?;
        let mut reader = BufReader::new(file);
        let mut last = String::new();
        let mut buf = String::new();
        while reader.read_line(&mut buf)? > 0 {
            if !buf.trim().is_empty() { last = buf.trim_end().to_string(); }
            buf.clear();
        }
        let prev_hash = if last.is_empty() {
            "0".repeat(64)
        } else {
            let mut hasher = Sha256::new();
            hasher.update(last.as_bytes());
            hex::encode(hasher.finalize())
        };
        Ok((if last.is_empty() { None } else { Some(last) }, prev_hash))
    }

    fn weight_for(decision_type: &DecisionType, severity: u8) -> i32 {
        fn by_sev(base: [i32; 4], s: u8) -> i32 { base[std::cmp::min(s as usize, 3)] }
        match decision_type {
            DecisionType::TRUSTED       => by_sev([4,5,6,8], severity),
            DecisionType::VERIFIED_ID   => by_sev([3,4,5,6], severity),
            DecisionType::GOOD_BEHAVIOR => by_sev([1,2,3,4], severity),
            DecisionType::NOTE | DecisionType::APPEAL => 0,
            DecisionType::REVERSAL      => 0,
            DecisionType::SPAM          => by_sev([-2,-4,-5,-6], severity),
            DecisionType::MALFORMED     => by_sev([-1,-2,-3,-4], severity),
            DecisionType::TIMEOUT       => by_sev([-1,-1,-2,-3], severity),
            DecisionType::MISBEHAVIOR   => by_sev([-3,-5,-7,-9], severity),
            DecisionType::REPLAY        => by_sev([-2,-3,-4,-5], severity),
            DecisionType::INVALID_SIG   => by_sev([-4,-6,-8,-10], severity),
        }
    }

        // Append a new event atomically, with a single locked handle (Windows-safe)
    pub fn append(
        &self,
        signing_key: &SigningKey,
        actor_peer_id: &str,
        subject_peer_id: &str,
        decision_type: DecisionType,
        severity: u8,
        reason_code: &str,
        reason_text: &str,
        evidence: Vec<Evidence>,
        ttl: Option<String>,
    ) -> anyhow::Result<Event> {
        // Open once with read+append, then lock it before reading/writing.
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        file.lock_exclusive()?; // exclusive lock for whole append txn

        // Read last line *from the same handle* (via a cloned handle) to compute prev_hash.
        let mut last = String::new();
        {
            let mut reader = BufReader::new(file.try_clone()?);
            let mut buf = String::new();
            while reader.read_line(&mut buf)? > 0 {
                if !buf.trim().is_empty() {
                    last = buf.trim_end().to_string();
                }
                buf.clear();
            }
        }
        let prev_hash = if last.is_empty() {
            "0".repeat(64)
        } else {
            let mut hasher = Sha256::new();
            hasher.update(last.as_bytes());
            hex::encode(hasher.finalize())
        };

        let weight = Self::weight_for(&decision_type, severity);
        let mut event = Event {
            version: 1,
            event_id: Uuid::new_v4().to_string(),
            ts: now_rfc3339(),
            actor_peer_id: actor_peer_id.to_string(),
            subject_peer_id: subject_peer_id.to_string(),
            decision_type,
            severity,
            reason_code: reason_code.to_string(),
            reason_text: reason_text.to_string(),
            evidence,
            ttl,
            weight,
            prev_hash,
            sig: String::new(),
        };

        // Sign canonical JSON (sig over event with empty sig field)
        let bytes = to_canonical_json(&event)?;
        let signature: Signature = signing_key.sign(&bytes);
        event.sig = hex::encode(signature.to_bytes());

        // Final line to append
        let line = String::from_utf8(to_canonical_json(&event)?)? + "\n";

        // Write using the already-locked handle
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        file.unlock()?;
        Ok(event)
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> anyhow::Result<(bool, usize)> {
        let f = OpenOptions::new().read(true).open(&self.path)?;
        let reader = BufReader::new(f);
        let mut prev_hash = "0".repeat(64);
        let mut count = 0usize;
        for line in reader.lines() {
            let l = line?;
            if l.trim().is_empty() { continue; }
            let mut hasher = Sha256::new();
            hasher.update(l.as_bytes());
            let computed_for_this_line = hex::encode(hasher.finalize());

            let ev: Event = serde_json::from_str(&l)?;
            if ev.prev_hash != prev_hash { anyhow::bail!("prev_hash mismatch at index {}", count); }

            let mut ev_no_sig = ev.clone();
            ev_no_sig.sig = String::new();
            let bytes = to_canonical_json(&ev_no_sig)?;
            let sig_bytes = hex::decode(ev.sig)?;
            let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
            verifying_key.verify(&bytes, &sig)?;

            prev_hash = computed_for_this_line;
            count += 1;
        }
        Ok((true, count))
    }

    pub fn compute_score(&self, subject_peer_id: &str) -> anyhow::Result<i32> {
        let f = OpenOptions::new().read(true).open(&self.path)?;
        let reader = BufReader::new(f);
        let mut score: i32 = 0;
        for line in reader.lines() {
            let l = line?;
            if l.trim().is_empty() { continue; }
            let ev: Event = serde_json::from_str(&l)?;
            if ev.subject_peer_id == subject_peer_id { score += ev.weight; }
        }
        Ok(score)
    }
}