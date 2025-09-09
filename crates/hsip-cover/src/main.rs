use std::net::SocketAddr;
use clap::Parser;
use hsip_cover::{run_udp_cover, CoverConfig};

#[derive(Parser, Debug)]
#[command(name = "hsip-cover", about = "HSIP decoy/cover traffic generator")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9100")]
    to: SocketAddr,
    #[arg(long, default_value_t = 90)]
    rate_per_min: u32,
    #[arg(long, default_value_t = 256)]
    min_size: usize,
    #[arg(long, default_value_t = 1200)]
    max_size: usize,
    #[arg(long, default_value_t = 800)]
    jitter_ms: u64,
    /// 0 = run forever
    #[arg(long, default_value_t = 200u64)]
    max_packets: u64,
    /// Print progress every N packets (0 = silent)
    #[arg(long, default_value_t = 25u64)]
    verbose_every: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let cfg = CoverConfig {
        to: a.to,
        rate_per_min: a.rate_per_min,
        min_size: a.min_size,
        max_size: a.max_size,
        jitter_ms: a.jitter_ms,
        max_packets: if a.max_packets == 0 { None } else { Some(a.max_packets) },
    };
    println!(
        "hsip-cover → {} | ~{} pkt/min | sizes {}–{} bytes | jitter ±{} ms | cap {}",
        cfg.to,
        cfg.rate_per_min,
        cfg.min_size,
        cfg.max_size,
        cfg.jitter_ms,
        a.max_packets
    );
    hsip_cover::run_udp_cover_with_progress(cfg, a.verbose_every).await
}
