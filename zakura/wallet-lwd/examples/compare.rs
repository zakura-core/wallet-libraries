//! Compares the new wallet core against the forked librustzcash stack.
//!
//! Both scan byte-identical blocks, downloaded once and handed to each in turn,
//! so the network is excluded and what is measured is detection plus storage —
//! the part this rewrite actually replaces.
//!
//! ```text
//! cargo run --release -p zakura-wallet-lwd --example compare -- --blocks 5000
//! ```

use std::{sync::Mutex, time::Instant};

use rand::SeedableRng;

use prost::Message;
use secrecy::SecretVec;
use zakura_wallet_lwd::LightwalletdSource;
use zakura_wallet_scan::{
    AccountId, NullifierSnapshot, ScanKeys, TransparentWatch, detect_batch,
};
use zakura_wallet_store::WalletDb as NewDb;
use zakura_wallet_sync::ChainSource;
use zcash_protocol::consensus::{BlockHeight, Network, NetworkUpgrade, Parameters};

// The forked stack.
use zcash_client_backend::{
    data_api::{AccountBirthday, WalletWrite, chain::{BlockSource, scan_cached_blocks}},
    proto::compact_formats::CompactBlock as ForkBlock,
};
use zcash_client_sqlite::WalletDb as ForkDb;

/// A block source over blocks already in memory.
///
/// The fork's scanner takes its input through this trait rather than as a
/// slice, which is why it traverses its input twice: it cannot index into a
/// callback.
struct InMemory(Mutex<Vec<ForkBlock>>);

impl BlockSource for InMemory {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(
            ForkBlock,
        )
            -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>,
    {
        let blocks = self.0.lock().unwrap();
        let from = from_height.map_or(0, u32::from);
        for block in blocks
            .iter()
            .filter(|b| b.height as u32 >= from)
            .take(limit.unwrap_or(usize::MAX))
        {
            with_block(block.clone())?;
        }
        Ok(())
    }
}

fn peak_rss() -> u64 {
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
    let count = arg("--blocks", 5_000);

    let params = Network::MainNetwork;
    let activation = params.activation_height(NetworkUpgrade::Nu6_3).unwrap();

    let source = LightwalletdSource::connect(&url).await?;
    let tip = source.tip().await?;
    let start = BlockHeight::from_u32(u32::from(tip.height).saturating_sub(count)).max(activation);
    let range = start..tip.height;

    println!("downloading {start}..{} once, for both stacks", tip.height);
    let raw = source.fetch_raw(range.clone()).await?;
    let tree_state = source.tree_state_raw(start - 1).await?;
    println!("{} blocks downloaded\n", raw.len());

    // Re-decode into the fork's own generated types. Same wire format, so this
    // is a re-parse rather than a conversion, and both stacks see exactly the
    // same bytes.
    let fork_blocks: Vec<ForkBlock> = raw
        .iter()
        .map(|b| ForkBlock::decode(&b.encode_to_vec()[..]).expect("the wire format is shared"))
        .collect();
    let fork_treestate =
        zcash_client_backend::proto::service::TreeState::decode(&tree_state.encode_to_vec()[..])?;

    let ironwood: usize = raw
        .iter()
        .flat_map(|b| b.vtx.iter())
        .map(|tx| tx.ironwood_actions.len())
        .sum();
    let orchard: usize = raw
        .iter()
        .flat_map(|b| b.vtx.iter())
        .map(|tx| tx.actions.len())
        .sum();
    println!("workload: {orchard} Orchard actions, {ironwood} Ironwood actions");

    // ---------------------------------------------------------------- fork
    let rss_before_fork = peak_rss();
    let fork_elapsed = {
        let mut db = ForkDb::for_path(
            ":memory:",
            params,
            zcash_client_sqlite::util::SystemClock,
            rand::rngs::Xoshiro256PlusPlus::seed_from_u64(0),
        )?;
        zcash_client_sqlite::wallet::init::WalletMigrator::new()
            .init_or_migrate(&mut db)
            .map_err(|e| format!("{e:?}"))?;

        let birthday = AccountBirthday::from_treestate(fork_treestate, None)
            .map_err(|e| format!("{e:?}"))?;
        let seed = SecretVec::new(vec![0u8; 32]);
        db.create_account("bench", &seed, &birthday, None)
            .map_err(|e| format!("{e:?}"))?;

        let chain_state = birthday.prior_chain_state().clone();
        let cache = InMemory(Mutex::new(fork_blocks));

        let began = Instant::now();
        scan_cached_blocks(&params, &cache, &mut db, start, &chain_state, count as usize + 1)
            .map_err(|e| format!("{e:?}"))?;
        began.elapsed()
    };
    let rss_after_fork = peak_rss();

    // ------------------------------------------------------------- new core
    let new_blocks: Vec<_> = raw
        .into_iter()
        .map(LightwalletdSource::convert_block)
        .collect::<Result<_, _>>()?;

    let new_elapsed = {
        let mut db = NewDb::in_memory()?;
        db.set_birthday(start)?;
        let keys = ScanKeys::from_accounts([(
            AccountId(1),
            zakura_wallet_scan::testing::fvk_from_seed(1),
        )]);
        let anchor = source.anchor(start - 1).await?;

        let began = Instant::now();
        let batch = detect_batch(
            &params,
            &keys,
            &TransparentWatch::default(),
            &NullifierSnapshot::default(),
            &anchor,
            &new_blocks,
        )?;
        db.put_batch(&params, &batch)?;
        began.elapsed()
    };
    let rss_after_new = peak_rss();

    println!("\n--- detect + store, same blocks ---");
    println!(
        "fork      {:>7.2}s   ({:.0} blocks/s)",
        fork_elapsed.as_secs_f64(),
        count as f64 / fork_elapsed.as_secs_f64()
    );
    println!(
        "new core  {:>7.2}s   ({:.0} blocks/s)",
        new_elapsed.as_secs_f64(),
        count as f64 / new_elapsed.as_secs_f64()
    );
    println!(
        "ratio     {:>7.2}x   {}",
        fork_elapsed.as_secs_f64() / new_elapsed.as_secs_f64(),
        if new_elapsed < fork_elapsed { "faster" } else { "SLOWER" }
    );
    println!(
        "\npeak RSS  fork {:.0} MiB, new core {:.0} MiB",
        (rss_after_fork - rss_before_fork) as f64 / (1024.0 * 1024.0),
        (rss_after_new.saturating_sub(rss_after_fork)) as f64 / (1024.0 * 1024.0),
    );

    Ok(())
}
