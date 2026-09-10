//! The catalogue: one chain carrying every wallet history M3 requires, and
//! the helpers that publish, serve and check it.
#![allow(dead_code)]

use transparent_filter::ScriptBytes;
use transparent_shard::layout::{Geometry, RECENT_4K, RECENT_8K};
use zakura_wallet_core::{AccountId, KeyScope};
use zakura_wallet_store::{GapLimits, WalletDb};
use zakura_wallet_sync::TransparentCompletion;

use super::blocks::*;
use super::*;

/// The wallet's scripts as the catalogue pays them.
pub struct Cast {
    /// External addresses 0 through 12; 10 and above exist only once the
    /// window has been widened by a payment at index 9.
    pub ext: Vec<ScriptBytes>,
    pub int: Vec<ScriptBytes>,
    pub imported: ScriptBytes,
    /// Every script the reducer is asked about.
    pub all: Vec<ScriptBytes>,
}

pub fn imported_script() -> ScriptBytes {
    let mut bytes = vec![0x76, 0xa9, 0x14];
    bytes.extend_from_slice(&[0x4d; 20]);
    bytes.extend_from_slice(&[0x88, 0xac]);
    ScriptBytes::new(bytes)
}

/// Two tiers: the first two shards use the narrower table geometry, as the
/// archive tier differs from the recent tier in table shape.
pub fn tiers(shard: u64) -> &'static Geometry {
    if shard < 2 { &RECENT_4K } else { &RECENT_8K }
}

/// Builds the catalogue chain against `db`'s account, importing its script.
pub fn catalogue(db: &mut WalletDb, account: AccountId) -> (Chain, Cast) {
    let ext: Vec<ScriptBytes> = (0..=12)
        .map(|i| derived(db, account, KeyScope::External, i).1)
        .collect();
    let int: Vec<ScriptBytes> = (0..5)
        .map(|i| derived(db, account, KeyScope::Internal, i).1)
        .collect();
    let imported = imported_script();
    db.import_transparent_script(
        account,
        "t1M3ImportedScriptForTheCatalogue",
        imported.as_slice(),
    )
    .unwrap();
    let mut all = ext.clone();
    all.extend(int.iter().cloned());
    all.push(imported.clone());

    let decoy = |tag: u32| script(tag);
    let f = FIRST;
    let s = SPAN;
    let mut chain = Chain::synthetic(DEFAULT_LAYOUT).with_decoys();

    // Receive in the archive tier, spend in the recent tier.
    let o0 = chain.pay(f + 5, ext[0].clone(), 50_000);
    chain.spend(f + 2 * s + 10, &[o0], &[(decoy(1), 49_000)]);

    // A coinbase output. Recovered and counted; whether it is spendable is
    // the wallet's maturity rule, not the ledger's.
    chain.coinbase(f + s + 1, ext[1].clone(), 312_500_000);

    // A self-transfer: one wallet output paid to a change address and an
    // external address of the same wallet.
    let o2 = chain.pay(f + s + 40, ext[2].clone(), 20_000);
    chain.spend(
        f + 2 * s + 60,
        &[o2],
        &[(int[0].clone(), 15_000), (ext[3].clone(), 4_000)],
    );

    // One script with a history long enough to need pages, in two tiers.
    chain.pay(f + s + 3, ext[4].clone(), 7_000);
    chain.pay(f + 3 * s + 7, ext[4].clone(), 7_001);
    for i in 0..long_history() {
        chain.pay(f + s + 20 + i % 100, ext[4].clone(), 11);
    }

    // An old receive spent recently, across the tier boundary, into the
    // provisional tail.
    let o5 = chain.pay(f + 2, ext[5].clone(), 9_000);
    chain.spend(f + 3 * s + 150, &[o5], &[(decoy(2), 8_900)]);

    // Received and spent while the wallet was away, both in the tail.
    let o6 = chain.pay(f + 3 * s + 20, ext[6].clone(), 3_000);
    chain.spend(f + 3 * s + 40, &[o6], &[(decoy(3), 2_900)]);

    // A history that ends at zero.
    let o7 = chain.pay(f + s + 70, ext[7].clone(), 1_000);
    chain.spend(f + s + 90, &[o7], &[(decoy(4), 900)]);

    // ext[8] and int[1..] are never paid.

    // The imported script: history from the first covered height.
    let oi = chain.pay(f + 3, imported.clone(), 2_500);
    chain.spend(f + 2 * s + 5, &[oi], &[(decoy(5), 2_400)]);

    // A payment at the edge of the window, and one at an address only a
    // widened window derives, back in a shard already read.
    let gap = GapLimits::default().external as usize;
    assert_eq!(gap, 10, "the catalogue assumes the window is ten wide");
    chain.pay(f + 3 * s + 30, ext[gap - 1].clone(), 300);
    chain.pay(f + s + 90, ext[12].clone(), 400);

    (
        chain,
        Cast {
            ext,
            int,
            imported,
            all,
        },
    )
}

/// Publishes the catalogue and serves it, recording every request.
pub async fn served(
    chain: &Chain,
    dir: &std::path::Path,
) -> (
    transparent_filter::ShardMap,
    String,
    std::sync::Arc<std::sync::Mutex<Faults>>,
) {
    let map = publish_layout(
        dir,
        &extract(chain),
        DEFAULT_LAYOUT,
        tiers,
        0,
        "",
        chain.hash_fn(),
    );
    let (base, faults) = serve_traced(dir).await;
    (map, base, faults)
}

pub fn complete(progress: &zakura_wallet_sync::TransparentProgress) {
    assert_eq!(
        progress.completion,
        TransparentCompletion::Complete,
        "{progress:?}"
    );
}

pub fn check_requests(
    db: &WalletDb,
    account: AccountId,
    chain: &Chain,
    faults: &std::sync::Mutex<Faults>,
) {
    let requests = faults.lock().unwrap().requests.clone();
    let needles = Needles::of(db, account, &extract(chain));
    assert!(!needles.text.is_empty());
    assert_no_plaintext(&requests, &needles);
}
