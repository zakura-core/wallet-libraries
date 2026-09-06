//! A wallet at the command line, for exercising the stack without a device.
//!
//! Everything the interface does, done from a terminal: open, restore, sync,
//! and print what the wallet is worth. It exists because a defect in the
//! network path — a wrong endpoint, a missing entitlement, a birthday that
//! skips the money — looks the same from inside a test as everything working,
//! and only talking to a real server tells them apart.
//!
//! ```text
//! cargo run -p zakura-wallet-facade --example wallet -- \
//!     --dir /tmp/w --seconds 30 [--phrase "..."] [--birthday 3000000]
//! ```
//!
//! With no phrase it makes a new wallet, which has no history and so nothing to
//! find; pass one to watch a real restore.

use std::{path::PathBuf, time::Duration};

use zakura_wallet_facade::{NetworkKind, Wallet, WalletConfig, mnemonic};

fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == name {
            return args.next();
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(arg("--dir").unwrap_or_else(|| "/tmp/zakura-cli".into()));
    let seconds: u64 = arg("--seconds").and_then(|s| s.parse().ok()).unwrap_or(30);
    let url = arg("--url").unwrap_or_else(|| {
        std::env::var("ZAKURA_LWD").unwrap_or_else(|_| "https://us.zec.stardust.rest:443".into())
    });

    let wallet = Wallet::open(WalletConfig::in_dir(NetworkKind::Main, &dir, url.clone()))?;
    println!("wallet at {}", dir.display());
    println!("server    {url}");

    let account = match wallet.accounts()?.first() {
        Some(existing) => {
            println!("account   {} (birthday {})", existing.id, existing.birthday);
            existing.id
        }
        None => {
            let phrase = arg("--phrase").unwrap_or_else(|| mnemonic::generate().to_string());
            let seed = mnemonic::to_seed(&phrase, "")?;
            let birthday = arg("--birthday").and_then(|s| s.parse().ok());

            let id = match birthday {
                // A wallet being restored has history to find, so it starts
                // where it is told, or from the earliest possible height.
                Some(_) => wallet.import_wallet(&seed, birthday)?,
                None if arg("--phrase").is_some() => wallet.import_wallet(&seed, None)?,
                // A new wallet has no history, so it starts at the tip.
                None => wallet.create_wallet(&seed)?,
            };
            let created = wallet.accounts()?;
            println!("account   {id} (birthday {})", created[0].birthday);
            id
        }
    };

    println!("address   {}", wallet.next_address(account, None)?);
    println!("watching  {} transparent addresses", wallet.watched_transparent_addresses()?);

    wallet.start_sync()?;
    println!("\nsyncing for {seconds}s…");

    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let p = wallet.progress();
        let line = format!(
            "{:?} {:>5} block {} of {} ({} queued){}",
            p.phase,
            p.fraction
                .map(|f| format!("{:.1}%", f * 100.0))
                .unwrap_or_else(|| "-".into()),
            p.scanned_to.map(|h| h.to_string()).unwrap_or_else(|| "-".into()),
            p.tip.map(|h| h.to_string()).unwrap_or_else(|| "-".into()),
            p.blocks_remaining,
            if p.failed { "  FAILED" } else { "" },
        );
        if line != last {
            println!("  {line}");
            last = line;
        }
        if p.failed {
            break;
        }
    }
    wallet.stop_sync();

    if let Some(why) = wallet.sync_failure() {
        println!("\nsync stopped: {why}");
    }

    let balance = wallet.balance(account)?;
    println!("\nspendable   {}", balance.spendable);
    println!("pending     {}", balance.pending);
    println!("transparent {}", balance.transparent);
    println!("total       {}", balance.total());

    let history = wallet.history(account, 10)?;
    println!("\n{} transactions", history.len());
    for entry in &history {
        println!(
            "  {} {:>12} {}",
            entry
                .mined_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "unmined".into()),
            entry.net(),
            if entry.is_change_only { "(change)" } else { "" },
        );
    }
    Ok(())
}
