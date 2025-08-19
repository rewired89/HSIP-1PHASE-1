// crates/hsip-cli/src/cmd_rep.rs
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hsip_core::identity::peer_id_from_pubkey;
use hsip_core::keystore::load_keypair;
use hsip_reputation::store::{DecisionType, Evidence, Store};

#[derive(Args)]
pub struct RepArgs {
    #[command(subcommand)]
    pub cmd: RepCmd,
}

#[derive(Subcommand)]
pub enum RepCmd {
    /// Append a structured decision event to the reputation log
    Append {
        /// Subject peer ID (the peer you're scoring)
        #[arg(long)]
        peer: String,

        /// Decision type (e.g., SPAM, TRUSTED, TIMEOUT, INVALID_SIG, ...)
        #[arg(long)]
        r#type: String,

        /// Severity 0..3 (higher = stronger effect)
        #[arg(long, default_value_t = 1)]
        severity: u8,

        /// Short, controlled reason code (e.g., HELLO_FLOOD, BAD_PROTO_VERSION)
        #[arg(long)]
        reason: String,

        /// Optional human-readable context
        #[arg(long, default_value = "")]
        text: String,

        /// Optional evidence entries: kind:value (repeatable)
        #[arg(long)]
        evidence: Vec<String>,

        /// Optional TTL window (e.g., 7d)
        #[arg(long)]
        ttl: Option<String>,

        /// Path to reputation log file (default: ~/.hsip/reputation.log)
        #[arg(long)]
        log: Option<String>,
    },

    /// Show events (and optionally the computed score) for a peer
    Show {
        /// Subject peer ID
        #[arg(long)]
        peer: String,

        /// Also print the computed score
        #[arg(long)]
        score: bool,

        /// Path to reputation log file (default: ~/.hsip/reputation.log)
        #[arg(long)]
        log: Option<String>,
    },

    /// Verify hash-chain & signatures of the entire log
    Verify {
        /// Path to reputation log file (default: ~/.hsip/reputation.log)
        #[arg(long)]
        log: Option<String>,
    },
}

pub fn run_rep(args: RepArgs) -> Result<()> {
    match args.cmd {
        RepCmd::Append {
            peer,
            r#type,
            severity,
            reason,
            text,
            evidence,
            ttl,
            log,
        } => {
            let log_path = log.unwrap_or(default_log_path()?);
            let store = Store::open(log_path)?;
            let (signing_key, my_peer_id) = load_signing_key_and_peer_id()?;

            let decision_type = parse_decision_type(&r#type)?;

            let ev = store.append(
                &signing_key,
                &my_peer_id,
                &peer,
                decision_type,
                severity,
                &reason,
                &text,
                evidence
                    .into_iter()
                    .map(|e| {
                        let (k, v) = e.split_once(':').unwrap_or(("note", e.as_str()));
                        Evidence { kind: k.to_string(), value: v.to_string() }
                    })
                    .collect(),
                ttl,
            )?;

            println!("appended event {}", ev.event_id);
        }

        RepCmd::Show { peer, score, log } => {
            let log_path = log.unwrap_or(default_log_path()?);
            let f = OpenOptions::new().read(true).open(&log_path)?;
            for line in BufReader::new(f).lines() {
                println!("{}", line?);
            }
            if score {
                let store = Store::open(log_path)?;
                let s = store.compute_score(&peer)?;
                println!("score({}): {}", peer, s);
            }
        }

        RepCmd::Verify { log } => {
            let log_path = log.unwrap_or(default_log_path()?);
            let store = Store::open(log_path)?;
            let (_sk, vk, _my_peer_id) = load_keys_for_verify()?;
            let (ok, n) = store.verify(&vk)?;
            println!("verify: {} entries, ok={}", n, ok);
        }
    }
    Ok(())
}

// ------- helpers -------

fn default_log_path() -> Result<String> {
    Ok(format!("{}/.hsip/reputation.log", home_dir_string()?))
}

fn home_dir_string() -> Result<String> {
    let p = dirs::home_dir().ok_or_else(|| anyhow!("cannot resolve home directory"))?;
    Ok(p.to_string_lossy().to_string())
}

fn load_signing_key_and_peer_id() -> Result<(SigningKey, String)> {
    let (sk, vk): (SigningKey, VerifyingKey) = load_keypair().map_err(|e| anyhow!(e))?;
    let my_peer = peer_id_from_pubkey(&vk);
    Ok((sk, my_peer))
}

fn load_keys_for_verify() -> Result<(SigningKey, VerifyingKey, String)> {
    let (sk, vk): (SigningKey, VerifyingKey) = load_keypair().map_err(|e| anyhow!(e))?;
    let my_peer = peer_id_from_pubkey(&vk);
    Ok((sk, vk, my_peer))
}

fn parse_decision_type(s: &str) -> Result<DecisionType> {
    match s.trim().to_uppercase().as_str() {
        "TRUSTED"        => Ok(DecisionType::TRUSTED),
        "VERIFIED_ID"    => Ok(DecisionType::VERIFIED_ID),
        "GOOD_BEHAVIOR"  => Ok(DecisionType::GOOD_BEHAVIOR),
        "NOTE"           => Ok(DecisionType::NOTE),
        "APPEAL"         => Ok(DecisionType::APPEAL),
        "REVERSAL"       => Ok(DecisionType::REVERSAL),
        "SPAM"           => Ok(DecisionType::SPAM),
        "MALFORMED"      => Ok(DecisionType::MALFORMED),
        "TIMEOUT"        => Ok(DecisionType::TIMEOUT),
        "MISBEHAVIOR"    => Ok(DecisionType::MISBEHAVIOR),
        "REPLAY"         => Ok(DecisionType::REPLAY),
        "INVALID_SIG"    => Ok(DecisionType::INVALID_SIG),
        other => Err(anyhow!("unknown decision type '{}'", other)),
    }
}
