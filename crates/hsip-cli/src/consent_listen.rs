use anyhow::Result;
use clap::Args;
use std::net::SocketAddr;
use tokio::{net::UdpSocket, signal, task::JoinHandle};

/// Listen for CONSENT frames and (optionally) emit cover/decoy traffic to this same port.
/// NOTE: This is a minimal skeleton so you can compile/run today. We’ll replace the
/// placeholder packet handling with your real CONSENT parser next step.
#[derive(Args, Debug, Clone)]
pub struct ConsentListenArgs {
    /// UDP socket to listen on for CONSENT frames
    #[arg(long, default_value = "127.0.0.1:9100")]
    pub bind: SocketAddr,

    // ---- future options you already planned ----
    // #[arg(long)] pub auto_respond: Option<String>;
    // #[arg(long)] pub ttl_ms: Option<u64>;

    // ---- NEW: cover/chaff toggles ----
    /// Enable decoy traffic generator
    #[arg(long, default_value_t = false)]
    pub cover: bool,

    /// Decoy packets per minute (avg)
    #[arg(long, default_value_t = 90)]
    pub cover_rate_per_min: u32,

    /// Min payload size (bytes)
    #[arg(long, default_value_t = 256)]
    pub cover_min_size: usize,

    /// Max payload size (bytes)
    #[arg(long, default_value_t = 1200)]
    pub cover_max_size: usize,

    /// Jitter around mean interval (ms)
    #[arg(long, default_value_t = 800)]
    pub cover_jitter_ms: u64,

    /// Print progress every N packets (0 = silent)
    #[arg(long, default_value_t = 0u64)]
    pub cover_verbose_every: u64,
}

pub async fn run(args: ConsentListenArgs) -> Result<()> {
    // Optional background cover/chaff task
    let mut cover_task: Option<JoinHandle<anyhow::Result<()>>> = None;
    if args.cover {
        use hsip_cover::{run_udp_cover_with_progress, CoverConfig};
        let cfg = CoverConfig {
            to: args.bind,
            rate_per_min: args.cover_rate_per_min,
            min_size: args.cover_min_size,
            max_size: args.cover_max_size,
            jitter_ms: args.cover_jitter_ms,
            max_packets: None, // run until Ctrl+C or listener ends
        };
        println!(
            "[hsip-cli] cover ON → {} | ~{} pkt/min | sizes {}–{} | jitter ±{} ms",
            cfg.to, cfg.rate_per_min, cfg.min_size, cfg.max_size, cfg.jitter_ms
        );
        let verbose = args.cover_verbose_every;
        cover_task = Some(tokio::spawn(async move {
            run_udp_cover_with_progress(cfg, verbose).await
        }));
    }

    // Minimal UDP listener
    let sock = UdpSocket::bind(args.bind).await?;
    println!("[hsip-cli] consent-listen bound on {}", args.bind);

    let mut buf = vec![0u8; 4096];

    tokio::select! {
        res = async {
            loop {
                let (n, peer) = sock.recv_from(&mut buf).await?;
                // Placeholder handling: just log size/from.
                // Next step we’ll parse/verify CONSENT frames and auto-respond if enabled.
                println!("[consent] {} bytes from {}", n, peer);
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        } => {
            if let Err(e) = res {
                eprintln!("[hsip-cli] listener error: {e:?}");
            }
        }
        _ = signal::ctrl_c() => {
            println!("[hsip-cli] Ctrl+C received, shutting down listener…");
        }
    }

    // Stop cover task
    if let Some(t) = cover_task {
        t.abort();
    }
    Ok(())
}
