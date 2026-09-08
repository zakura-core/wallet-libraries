//! The wallet's database meets the library's store contract.
//!
//! The suite is the library's own, run over its two reference stores upstream;
//! running it here is what says the wallet's store cannot drift from the ones
//! the sync is tested against. The scripts the suite uses are synthetic, so
//! they are registered as the wallet's own before the store is handed over.

use std::collections::BTreeMap;

use transparent_wallet::testing;
use zakura_wallet_core::{AccountId, KeyScope};
use zakura_wallet_store::{WalletDb, testing::test_db};
use zakura_wallet_transparent::PirStore;
use zcash_protocol::consensus::{BlockHeight, Network};

/// A wallet that owns every script the suite will name.
fn wallet() -> (WalletDb, BTreeMap<Vec<u8>, AccountId>) {
    let mut db = test_db().unwrap();
    let account = db
        .create_account(
            &Network::MainNetwork,
            &[3u8; 32],
            zip32::AccountId::try_from(0).unwrap(),
            BlockHeight::from_u32(0),
        )
        .unwrap();
    let mut owners = BTreeMap::new();
    for tag in 0..=255u8 {
        let script = testing::script(tag);
        // A synthetic address row, so the projection of a receive at this
        // script has an owner to credit.
        db.record_transparent_address(
            account,
            KeyScope::External,
            1_000 + u32::from(tag),
            &format!("t1suite{tag:03}"),
            &script,
        )
        .unwrap();
        owners.insert(script, account);
    }
    (db, owners)
}

#[test]
fn the_wallet_store_meets_the_contract() {
    // The suite asks for a fresh store per case; each gets a fresh wallet.
    let make = || {
        // Leaked deliberately: the suite's `make` returns an owned store, and
        // the store borrows a wallet that has to outlive it. Tests end when
        // the process does.
        let (db, owners): (&'static mut WalletDb, _) = {
            let (db, owners) = wallet();
            (Box::leak(Box::new(db)), owners)
        };
        PirStore::new(db, owners)
    };
    testing::suite(make);
}

#[test]
fn clipped_coverage_and_page_progress_keep_both_anchors() {
    use transparent_wallet::{Anchor, WalletStore};
    let (mut db, owners) = wallet();
    let mut store = PirStore::new(&mut db, owners);
    store.bind_set(&testing::identity()).unwrap();
    let target = Anchor {
        height: 150,
        hash: format!("{:064x}", 150),
    };
    let source = Anchor {
        height: 200,
        hash: format!("{:064x}", 200),
    };
    let script = testing::script(1);
    let mut commit = testing::commit(
        1,
        "revision",
        false,
        (100, 150),
        vec![],
        vec![script.clone()],
    );
    commit.terminal_block_hash = target.hash.clone();
    commit.source_anchor = Some(source.clone());
    let mut pending = testing::pending(1, "revision");
    pending.target_anchor = Some(target.clone());
    pending.validated_events = 4;
    pending.next_ordinal = 1;
    commit.pending_upsert.push(pending);
    store.commit_shard(commit).unwrap();
    let held = store.coverage(&script).unwrap();
    assert_eq!(held[0].source_anchor, Some(source.clone()));
    assert_eq!(held[0].terminal_block_hash, target.hash);
    let mut pending = store.pending().unwrap().remove(0);
    assert_eq!(pending.validated_events, 4);
    assert_eq!(pending.target_anchor, Some(target.clone()));
    pending.validated_events = 7;
    pending.next_ordinal = 2;
    let mut page = testing::commit(1, "revision", false, (100, 150), vec![], vec![]);
    page.source_anchor = Some(source);
    page.pending_upsert.push(pending);
    store.commit_shard(page).unwrap();
    assert_eq!(store.pending().unwrap()[0].validated_events, 7);
    store.commit_anchor(&target, 99, 150).unwrap();
    let ancestor = Anchor {
        height: 125,
        hash: format!("{:064x}", 125),
    };
    store.rollback_above(&ancestor, "reorg").unwrap();
    assert_eq!(store.anchor().unwrap(), Some(ancestor.clone()));
    assert_eq!(
        store.coverage(&script).unwrap()[0].terminal_block_hash,
        ancestor.hash
    );
    assert!(store.pending().unwrap().is_empty());
}

#[test]
fn protocol_heights_cannot_silently_saturate() {
    use transparent_wallet::{Anchor, WalletStore};
    let (mut db, owners) = wallet();
    let mut store = PirStore::new(&mut db, owners);
    store.bind_set(&testing::identity()).unwrap();
    let anchor = Anchor {
        height: u64::from(u32::MAX) + 1,
        hash: "00".repeat(32),
    };
    assert!(store.commit_anchor(&anchor, 0, anchor.height).is_err());
    assert!(store.anchor().unwrap().is_none());
}
