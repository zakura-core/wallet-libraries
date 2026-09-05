//! Measures recovery throughput against a real light server.
//!
//! ```text
//! cargo run --release -p zakura-wallet-lwd --example sync_bench -- \
//!     --blocks 10000 --budget 16
//! ```
//!
//! The workload is the one recovery actually does: trial-decrypt every action
//! in every block against a key that owns nothing. Whether the wallet finds
//! notes barely changes the cost, because the decryption attempt happens either
//! way; what changes is how much is written afterwards.

use std::time::Instant;

use zakura_wallet_core::pool::PoolId;
use zakura_wallet_lwd::LightwalletdSource;
use zakura_wallet_scan::{AccountId, ScanKeys, TransparentWatch};
use zakura_wallet_store::WalletDb;
use zakura_wallet_sync::{ByteBudget, CancellationToken, ChainSource, SyncConfig, SyncEngine};
use zcash_protocol::consensus::{BlockHeight, Network, NetworkUpgrade, Parameters};

/// Returns peak resident set size in bytes.
fn peak_rss() -> u64 {
    // `ru_maxrss` is bytes on macOS and kilobytes on Linux.
    #[allow(unsafe_code)]
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") { raw } else { raw * 1024 }
}

fn arg(name: &str, default: u32) -> u32 {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("ZAKURA_LWD")
        .unwrap_or_else(|_| "https://us.zec.stardust.rest:443".to_owned());
    let blocks = arg("--blocks", 5_000);
    let budget_mib = arg("--budget", 16);

    let params = Network::MainNetwork;
    let activation = params
        .activation_height(NetworkUpgrade::Nu6_3)
        .expect("Ironwood activates on mainnet");

    println!("connecting to {url}");
    let source = LightwalletdSource::connect(&url).await?;
    let tip = source.tip().await?;
    println!("tip {} (Ironwood activates at {activation})", tip.height);

    // Scan the most recent `blocks` blocks, which is where Ironwood activity
    // is; below activation there is none to find.
    let start = BlockHeight::from_u32(u32::from(tip.height).saturating_sub(blocks));
    let start = start.max(activation);
    println!("scanning {start}..{} ({} blocks)", tip.height, u32::from(tip.height) - u32::from(start));

    let mut db = WalletDb::in_memory()?;
    db.set_birthday(start)?;

    // A key that owns nothing: the recovery workload without the write volume
    // of a wallet that finds notes everywhere.
    let keys = ScanKeys::from_accounts([(
        AccountId(1),
        zakura_wallet_scan::testing::fvk_from_seed(1),
    )]);

    let mut engine = SyncEngine::new(
        source,
        params,
        db,
        keys,
        TransparentWatch::default(),
        SyncConfig {
            budget: ByteBudget::new(budget_mib as usize * 1024 * 1024),
            ..SyncConfig::default()
        },
    );

    let rss_before = peak_rss();
    let began = Instant::now();
    let summary = engine.run(&CancellationToken::new()).await?;
    let elapsed = began.elapsed();
    let rss_after = peak_rss();

    let (fetched, bytes) = engine.source().transferred();
    let scanned = engine
        .db()
        .block_height_extrema()?
        .map(|(lo, hi)| u32::from(hi) - u32::from(lo) + 1)
        .unwrap_or(0);

    println!("\n--- results ---");
    println!("blocks scanned      {scanned}");
    println!("blocks fetched      {fetched}");
    println!("batches             {}", summary.batches);
    println!("notes found         {}", summary.notes);
    println!("rewinds             {}", summary.rewinds);
    println!("elapsed             {:.2}s", elapsed.as_secs_f64());
    println!(
        "throughput          {:.0} blocks/s",
        scanned as f64 / elapsed.as_secs_f64()
    );
    println!(
        "downloaded          {:.1} MiB ({:.0} bytes/block)",
        bytes as f64 / (1024.0 * 1024.0),
        bytes as f64 / fetched.max(1) as f64
    );
    println!(
        "peak RSS            {:.1} MiB (was {:.1} MiB before syncing)",
        rss_after as f64 / (1024.0 * 1024.0),
        rss_before as f64 / (1024.0 * 1024.0),
    );

    let t = engine.timings();
    let pct = |d: std::time::Duration| 100.0 * d.as_secs_f64() / t.total().as_secs_f64();
    println!("\n--- where the time went ---");
    println!("fetch               {:>7.2}s  ({:.0}%)", t.fetch.as_secs_f64(), pct(t.fetch));
    println!("detect              {:>7.2}s  ({:.0}%)", t.detect.as_secs_f64(), pct(t.detect));
    println!("apply               {:>7.2}s  ({:.0}%)", t.apply.as_secs_f64(), pct(t.apply));
    println!(
        "pipelining headroom {:>7.2}s  ({:.0}% of accounted time)",
        t.pipelining_headroom().as_secs_f64(),
        pct(t.pipelining_headroom())
    );

    for pool in PoolId::ALL {
        let (covered, total) = engine.db().commitment_coverage(pool)?;
        println!("{pool:?} commitments  {covered} scanned, tree at {total}");
    }

    Ok(())
}
