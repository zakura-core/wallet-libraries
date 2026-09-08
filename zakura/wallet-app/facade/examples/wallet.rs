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

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

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

    let mut config = WalletConfig::in_dir(NetworkKind::Main, &dir, url.clone());
    // Two services, named separately, because the public and private halves
    // must not come from one host. Unset means transparent tracking is off and
    // reported as uncovered, which is a different thing from a zero balance.
    config.transparent = match (
        std::env::var("ZAKURA_TRANSPARENT_FILTERS"),
        std::env::var("ZAKURA_TRANSPARENT_SHARDS"),
    ) {
        (Ok(filters), Ok(shards)) => Some(zakura_wallet_transparent::Endpoints::new(
            filters, shards,
        )),
        _ => None,
    };

    let wallet = Wallet::open(config)?;
    println!("wallet at {}", dir.display());
    println!("server    {url}");
    match wallet.config().transparent.as_ref() {
        Some(endpoints) => {
            println!("filters   {}", endpoints.filters_url);
            println!("shards    {}", endpoints.shards_url);
        }
        None => println!(
            "transparent tracking is off: set ZAKURA_TRANSPARENT_FILTERS and \
             ZAKURA_TRANSPARENT_SHARDS"
        ),
    }

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
                None if flag("--phrase") => wallet.import_wallet(&seed, None)?,
                // A new wallet has no history, so it starts at the tip.
                None => wallet.create_wallet(&seed)?,
            };
            let created = wallet.accounts()?;
            println!("account   {id} (birthday {})", created[0].birthday);
            id
        }
    };

    println!("address   {}", wallet.next_address(account, None)?);

    // Transparent funds going unseen looks exactly like having none, so print
    // what is watched, what the ledger holds, and how far it has read. The
    // third is the one that tells the two apart.
    let watched = wallet.transparent_addresses(account)?;
    println!("watching  {} transparent addresses", watched.len());
    if flag("--utxos") {
        for address in &watched {
            println!("            {address}");
        }
        match wallet.transparent_utxos(account) {
            Ok(utxos) if utxos.is_empty() => println!("  the ledger holds nothing unspent"),
            Ok(utxos) => {
                for (address, value, height) in utxos {
                    let at = height.map_or_else(|| "height unknown".to_owned(), |h| format!("block {h}"));
                    println!("  unspent   {value:>12} at {address} ({at})");
                }
            }
            Err(e) => println!("  the ledger could not be read: {e}"),
        }
        match wallet.transparent_coverage(account) {
            Ok(coverage) => match coverage.covered_through {
                Some(height) => println!(
                    "  current through block {height} (settled {}), {} unresolved spends",
                    coverage
                        .settled_through
                        .map_or_else(|| "none".to_owned(), |h| h.to_string()),
                    coverage.unresolved_spends
                ),
                None => println!(
                    "  nothing has been read: no transparent service configured, or the \
                     wallet has not scanned down to the covered range"
                ),
            },
            Err(e) => println!("  coverage could not be read: {e}"),
        }
    }

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
        let pools = |a: &zakura_wallet_facade::PoolAmounts| {
            let mut parts = Vec::new();
            if a.transparent > 0 {
                parts.push(format!("transparent {}", a.transparent));
            }
            if a.orchard > 0 {
                parts.push(format!("orchard {}", a.orchard));
            }
            if a.ironwood > 0 {
                parts.push(format!("ironwood {}", a.ironwood));
            }
            parts.join(", ")
        };

        println!(
            "  {} net {:>12} {}",
            entry
                .mined_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "unmined".into()),
            entry.net(),
            if entry.is_change_only { "(change only)" } else { "" },
        );
        if !entry.spent_by_pool.is_zero() {
            println!("      spent    {}", pools(&entry.spent_by_pool));
        }
        if !entry.received_by_pool.is_zero() {
            println!("      received {}", pools(&entry.received_by_pool));
        }

        // What the wallet's own side cannot say: where the value actually went.
        if let Some(shape) = wallet.transaction_shape(&entry.txid)? {
            println!(
                "      shape    transparent in {} out {} ({} zats), \
orchard {} actions (balance {}), ironwood {} actions (balance {})",
                shape.transparent_inputs,
                shape.transparent_outputs,
                shape.transparent_out_value,
                shape.orchard_actions,
                shape.orchard_value_balance,
                shape.ironwood_actions,
                shape.ironwood_value_balance,
            );
            if shape.is_unshielding() {
                println!("      >>> this made value public (unshielded)");
            }
            if shape.is_shielding() {
                println!("      >>> this made value private (shielded)");
            }
        }
    }
    Ok(())
}
