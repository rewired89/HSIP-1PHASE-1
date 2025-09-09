use anyhow::Result;
use rand::{rngs::OsRng, Rng, RngCore};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::sleep};

#[derive(Clone, Debug)]
pub struct CoverConfig {
    pub to: SocketAddr,
    pub rate_per_min: u32,
    pub min_size: usize,
    pub max_size: usize,
    pub jitter_ms: u64,
    pub max_packets: Option<u64>,
}

impl CoverConfig {
    pub fn mean_interval_ms(&self) -> u64 {
        let r = self.rate_per_min.max(1) as f64;
        (60_000.0 / r).round() as u64
    }
}

pub async fn run_udp_cover(cfg: CoverConfig) -> Result<()> {
    run_udp_cover_with_progress(cfg, 0).await
}

/// Same as run_udp_cover, but prints every `verbose_every` packets (if > 0).
pub async fn run_udp_cover_with_progress(cfg: CoverConfig, verbose_every: u64) -> Result<()> {
    if cfg.rate_per_min == 0 {
        return Ok(());
    }
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut sent: u64 = 0;
    let mut rng = rand::thread_rng();

    loop {
        if let Some(max) = cfg.max_packets {
            if sent >= max { break; }
        }

        // size ∈ [min, max]
        let size = if cfg.max_size <= cfg.min_size {
            cfg.min_size
        } else {
            cfg.min_size + rng.gen_range(0..=(cfg.max_size - cfg.min_size))
        };

        // ciphertext-like bytes
        let mut buf = vec![0u8; size];
        OsRng.fill_bytes(&mut buf);

        socket.send_to(&buf, cfg.to).await?;
        sent += 1;

        if verbose_every > 0 && sent % verbose_every == 0 {
            println!("sent {} decoys (last={} bytes) → {}", sent, size, cfg.to);
        }

        // sleep ≈ mean ± jitter (uniform)
        let mean = cfg.mean_interval_ms() as i64;
        let jit = cfg.jitter_ms as i64;
        let delta = if jit == 0 { 0 } else { rng.gen_range(-jit..=jit) };
        let sleep_ms = (mean + delta).max(0) as u64;

        sleep(Duration::from_millis(sleep_ms)).await;
    }

    if verbose_every > 0 {
        println!("done. total sent={}", sent);
    }
    Ok(())
}
