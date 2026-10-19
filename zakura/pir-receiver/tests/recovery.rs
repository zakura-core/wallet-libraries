//! Continuous recovery end to end: restored SQLite wallets follow a receiver directory's
//! catalog, paid buckets, cumulative snapshots and seen set, served in process with real
//! PIR, and import what they find only after checking it against their own chain.

mod common;

use common::*;
use orchard::keys::FullViewingKey;
use receiver_directory::paid::BUCKET_BLOCKS;
use zakura_pir_receiver::{Delay, DirectoryError, Recovered, Transport, check_history, recover};
use zakura_receiver_crypto::Record;
use zcash_client_backend::{
    data_api::{
        Account as _, AccountBirthday, WalletWrite as _,
        one_time_ivk::coverage::OneTimeIvkCoverageRead as _, transparent_ledger::ChainPoint,
    },
    keys::UnifiedSpendingKey,
};
use zcash_client_sqlite::{
    AccountUuid,
    error::SqliteClientError,
    testing::db::TestDbFactory,
    wallet::one_time_ivk::{KeyId, Purpose},
};
use zcash_protocol::consensus::BlockHeight;

/// A day, in seconds.
const DAY: i64 = 24 * 60 * 60;

/// A restored wallet scanned through its first block, with no one-time key payments yet.
struct World {
    st: State,
    account: AccountUuid,
    /// Every payment to a one-time key, in chain order, as the directory lists it.
    records: Vec<Record>,
}

impl World {
    /// A fresh world.
    fn new() -> Self {
        let mut st = ironwood_wallet_in(TestDbFactory::default());
        let account = st.test_account().unwrap().id();
        st.generate_and_scan_empty_blocks_with_one_time_ivks(1);
        Self {
            st,
            account,
            records: Vec::new(),
        }
    }

    /// Pays `key` of the test account in a new block, which the wallet scans without
    /// knowing the key, and returns the block's height.
    fn pay(&mut self, key: KeyId) -> u32 {
        let parent = parent(&self.st);
        let position = self.records.len() as u64;
        let record = pay_key_unscanned(&mut self.st, &parent, key, position);
        let height = record.payment.height;
        self.st
            .scan_cached_blocks_with_one_time_ivks(BlockHeight::from(height), 1);
        self.records.push(record);
        height
    }

    /// Generates and scans empty blocks until the tip reaches `height`.
    fn advance(&mut self, height: u32) {
        let tip = u32::from(tip(&self.st).height);
        if height > tip {
            let blocks = (height - tip) as usize;
            self.st
                .generate_and_scan_empty_blocks_with_one_time_ivks(blocks);
        }
    }

    /// The directory publishing every payment through the wallet's tip, as `history` says.
    fn directory(&self, history: &History) -> Directory {
        self.directory_of(&self.records, history)
    }

    /// [`Self::directory`] publishing only `records`.
    fn directory_of(&self, records: &[Record], history: &History) -> Directory {
        let all = commitments(&self.records);
        recovering(&self.st, records, &all, tip(&self.st), history)
    }

    /// Runs recovery at `now`, expecting no failed key.
    async fn recover_at(
        &mut self,
        directory: impl Transport,
        now: i64,
    ) -> Recovered<SqliteClientError> {
        let network = *self.st.network();
        let db = self.st.wallet_mut().db_mut();
        let run = recover(
            db,
            &network,
            self.account,
            GENESIS,
            ORIGIN,
            directory,
            &NoLock,
            now,
        );
        let recovered = run.await.unwrap();
        assert!(recovered.failed.is_empty(), "{:?}", recovered.failed);
        recovered
    }

    /// [`Self::recover_at`] at [`NOW`].
    async fn recover(&mut self, directory: impl Transport) -> Recovered<SqliteClientError> {
        self.recover_at(directory, NOW).await
    }

    /// Runs "Check swap history" at [`NOW`], `deeper` indices past each window.
    async fn check_history(
        &mut self,
        directory: impl Transport,
        deeper: u32,
    ) -> Recovered<SqliteClientError> {
        let network = *self.st.network();
        let db = self.st.wallet_mut().db_mut();
        let account = self.account;
        let run = check_history(
            db, &network, account, GENESIS, ORIGIN, directory, &NoLock, deeper, NOW,
        );
        let recovered = run.await.unwrap();
        assert!(recovered.failed.is_empty(), "{:?}", recovered.failed);
        recovered
    }
}

/// A directory that cannot be reached.
struct Unreachable;

impl Transport for Unreachable {
    async fn get(&self, _: &str, _: usize) -> Result<Vec<u8>, DirectoryError> {
        Err(DirectoryError::Transport("connection refused".into()))
    }

    async fn post(&self, _: &str, _: Vec<u8>, _: usize) -> Result<Vec<u8>, DirectoryError> {
        Err(DirectoryError::Transport("connection refused".into()))
    }
}

/// An incoming key.
fn incoming(index: u64) -> KeyId {
    KeyId::new(Purpose::Receive, index)
}

/// A refund key.
fn refund(index: u64) -> KeyId {
    KeyId::new(Purpose::Refund, index)
}

/// The end of the closed bucket holding `height`.
fn bucket_end(height: u32) -> u32 {
    (height - 1) / BUCKET_BLOCKS * BUCKET_BLOCKS + BUCKET_BLOCKS
}

/// Whether a run requested a route starting with `prefix`.
fn requested(directory: &Directory, prefix: &str) -> bool {
    let path = format!("GET /v1/receiver/{prefix}");
    directory.requests().iter().any(|r| r.starts_with(&path))
}

/// A restore bootstraps its frontier from the cumulative snapshot, which ends inside a
/// bucket, then tests the bucket holding the block after it and each closed bucket after
/// that. Every payment is found and admitted, and an idle run looks nothing up.
#[tokio::test]
async fn a_restore_bootstraps_then_follows_buckets() {
    let mut w = World::new();
    w.pay(incoming(0));
    w.pay(incoming(3));
    let cutoff = w.pay(incoming(3)) + 2;
    w.advance(cutoff + 10);
    w.pay(refund(7));
    w.advance(bucket_end(cutoff + 60) + 3);
    let history = History {
        cutoff: Some(cutoff),
        ..History::default()
    };
    let directory = w.directory(&history);
    let found = w.recover(&directory).await;
    assert!(found.delay.is_none(), "{:?}", found.delay);
    let status = found.status.unwrap();
    assert!(status.complete, "{status:?}");
    assert_eq!(status.seen_checked_at, Some(NOW));
    assert_eq!(balance(&w.st), 4 * VALUE);
    assert_eq!(registered(&w.st, Purpose::Receive), [0, 3]);
    assert_eq!(registered(&w.st, Purpose::Refund), [7]);
    assert_eq!(lookups(&directory), 4);

    let before = lookups(&directory);
    let again = w.recover(&directory).await;
    assert!(again.status.unwrap().complete);
    assert_eq!(lookups(&directory), before, "an idle run looks nothing up");
}

/// A cumulative snapshot ending before the birthday needs no block the wallet stores, and
/// the bucket after it, which starts before the birthday too, is tested by its last block
/// alone.
#[tokio::test]
async fn a_bucket_starting_before_the_birthday_is_consumed() {
    let mut w = World::new();
    let paid = w.pay(incoming(1));
    w.advance(bucket_end(paid) + 1);
    let history = History {
        cutoff: Some(ACTIVATION - 1),
        ..History::default()
    };
    assert!(history.oldest_start < ACTIVATION);
    let directory = w.directory(&history);
    let found = w.recover(&directory).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), VALUE);
}

/// A snapshot pinned while the wallet's scan was short of its last block stays pinned
/// while the directory serves it, even after it publishes a newer one. Once the directory
/// no longer serves it, the frontier starts from the newer snapshot instead, without a
/// hole.
#[tokio::test]
async fn a_pinned_snapshot_gives_way_once_it_is_no_longer_served() {
    for retained in [true, false] {
        let mut w = World::new();
        w.pay(incoming(2));
        let scanned = u32::from(tip(&w.st).height);
        // Blocks the wallet has not scanned yet.
        for _ in 0..100 {
            w.st.generate_empty_block();
        }
        let ahead = scanned + 100;
        let end = ChainPoint {
            height: BlockHeight::from(ahead),
            hash: zcash_primitives::block::BlockHash(block_hash(&w.st, ahead)),
        };
        let first = History {
            cutoff: Some(ahead - 5),
            ..History::default()
        };
        let directory = recovering(&w.st, &w.records, &commitments(&w.records), end, &first);
        let waiting = w.recover(&directory).await;
        assert_eq!(waiting.status.unwrap().frontier, None);
        let pinned = w.st.wallet().db().one_time_coverage(w.account).unwrap();
        assert!(pinned.unwrap().bootstrap.is_some());

        w.st.scan_cached_blocks_with_one_time_ivks(BlockHeight::from(scanned + 1), 100);
        let newer = History {
            cutoff: Some(ahead - 2),
            ..first.clone()
        };
        let records = paged(&w.records);
        let commitments = commitments(&records);
        let (catalog, mut objects) = recovery_objects(&w.st, &records, ahead, &newer);
        if retained {
            let (_, old) = recovery_objects(&w.st, &records, ahead, &first);
            objects.extend(
                old.into_iter()
                    .filter(|(route, _)| route.starts_with("paid/")),
            );
        }
        let routes = publish_with(
            &records,
            &commitments,
            end,
            &provider(&[]),
            (catalog, objects),
        );
        let directory = Directory::new(routes);
        let found = w.recover(&directory).await;
        let status = found.status.unwrap();
        assert!(status.complete, "{status:?}");
        let expected = if retained { ahead - 5 } else { ahead - 2 };
        let frontier = status.frontier.unwrap();
        assert!(
            frontier == BlockHeight::from(expected),
            "{retained}: {frontier:?}"
        );
        assert_eq!(balance(&w.st), VALUE);
    }
}

/// A window that grows from the seen set, here for an incoming address another device
/// issued past it and was paid before the frontier, owes its new receivers that history:
/// they test the current cumulative snapshot, older than the frontier, then bridge every
/// bucket from the one holding the block after it.
#[tokio::test]
async fn window_growth_bridges_an_older_cumulative_snapshot() {
    let mut w = World::new();
    let cutoff = u32::from(tip(&w.st).height) + 5;
    w.advance(cutoff + 5);
    w.pay(incoming(140));
    w.advance(bucket_end(cutoff + 60) + 1);
    let history = History {
        cutoff: Some(cutoff),
        ..History::default()
    };
    let found = w.recover(&w.directory(&history)).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), 0, "index 140 is past the window");

    let seen = History {
        seen: [95, 120, 140].map(|i| receiver(&w.st, i)).to_vec(),
        ..history
    };
    let directory = w.directory(&seen);
    let found = w.recover_at(&directory, NOW + DAY).await;
    let status = found.status.unwrap();
    assert!(status.complete, "{status:?}");
    assert_eq!(balance(&w.st), VALUE);
    assert!(requested(&directory, "seen/"));
    assert!(requested(&directory, "paid/"));
}

/// An incoming address another device issued past the window after this wallet's restore
/// is found once the seen set grows the window: the bucket that holds its payment, after
/// the frontier, is tested against the grown set.
#[tokio::test]
async fn an_incoming_address_issued_on_another_device_after_restore() {
    let mut w = World::new();
    w.advance(bucket_end(ACTIVATION + 1) + 1);
    let found = w.recover(&w.directory(&History::default())).await;
    assert!(found.status.unwrap().complete);

    let paid = w.pay(incoming(120));
    w.advance(bucket_end(paid) + 1);
    let without = w
        .recover_at(&w.directory(&History::default()), NOW + 1)
        .await;
    assert!(without.status.unwrap().complete);
    assert_eq!(balance(&w.st), 0);
    let seen = History {
        seen: [95, 120].map(|i| receiver(&w.st, i)).to_vec(),
        ..History::default()
    };
    // The next daily seen check finds it.
    let found = w.recover_at(&w.directory(&seen), NOW + DAY).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), VALUE);
}

/// A seen hit grows the window and blocks the index from issuance, but looks nothing up
/// by itself.
#[tokio::test]
async fn a_seen_hit_looks_nothing_up() {
    let mut w = World::new();
    w.advance(bucket_end(ACTIVATION + 1) + 1);
    let seen = History {
        seen: vec![receiver(&w.st, 90)],
        ..History::default()
    };
    let directory = w.directory(&seen);
    let found = w.recover(&directory).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(registered(&w.st, Purpose::Receive), [90]);
    assert_eq!(lookups(&directory), 0);
    let coverage =
        w.st.wallet()
            .db()
            .one_time_coverage(w.account)
            .unwrap()
            .unwrap();
    let receive = coverage
        .windows
        .iter()
        .find(|w| w.purpose == Purpose::Receive);
    assert_eq!(receive.unwrap().end, 90 + 31);
}

/// An account with nothing to recover at its first run finds a payment another device
/// later receives to its window, from the bucket that holds it.
#[tokio::test]
async fn a_fresh_account_receives_another_devices_payment_after_recovery() {
    let mut w = World::new();
    w.advance(bucket_end(ACTIVATION + 1) + 1);
    let found = w.recover(&w.directory(&History::default())).await;
    assert!(found.status.unwrap().complete);
    let paid = w.pay(incoming(4));
    w.advance(bucket_end(paid) + 1);
    let directory = w.directory(&History::default());
    let found = w.recover(&directory).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), VALUE);
    assert!(requested(&directory, "bucket/"));
    assert!(
        !requested(&directory, "paid/"),
        "no snapshot after bootstrap"
    );
}

/// A refund paid in two parts in different buckets, and an incoming index two devices
/// both issued and both had paid, are each found in full.
#[tokio::test]
async fn split_refunds_and_reused_indices_are_found_in_full() {
    let mut w = World::new();
    let first = w.pay(refund(2));
    w.pay(incoming(5));
    w.advance(bucket_end(first) + 2);
    w.pay(refund(2));
    let last = w.pay(incoming(5));
    w.advance(bucket_end(last) + 1);
    let history = History {
        cutoff: Some(first + 2),
        ..History::default()
    };
    let found = w.recover(&w.directory(&history)).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), 4 * VALUE);
}

/// A payment the directory left out of history older than its retained buckets, which a
/// later epoch corrects, is found: the new epoch drops coverage, so the whole set is
/// bootstrapped again from the corrected cumulative snapshot.
#[tokio::test]
async fn a_correction_older_than_retention_is_found_in_the_new_epoch() {
    let mut w = World::new();
    w.pay(incoming(9));
    w.pay(incoming(1));
    w.advance(ACTIVATION + 3 * BUCKET_BLOCKS);
    let retained = History {
        oldest_start: bucket_end(ACTIVATION + 1) + BUCKET_BLOCKS,
        ..History::default()
    };
    let missing = w.records[1..].to_vec();
    let found = w.recover(&w.directory_of(&missing, &retained)).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), VALUE);

    let corrected = History {
        epoch: 2,
        ..retained
    };
    let found = w.recover(&w.directory(&corrected)).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), 2 * VALUE);
}

/// A new epoch with the same payments restarts every lookup from page zero, which finds
/// the same notes again and credits nothing twice.
#[tokio::test]
async fn a_same_height_correction_with_unchanged_membership_changes_nothing() {
    let mut w = World::new();
    let paid = w.pay(incoming(6));
    w.advance(bucket_end(paid) + 1);
    let directory = w.directory(&History::default());
    assert!(w.recover(&directory).await.status.unwrap().complete);
    assert_eq!(balance(&w.st), VALUE);
    let before = lookups(&directory);

    let corrected = History {
        epoch: 2,
        ..History::default()
    };
    let directory = w.directory(&corrected);
    let found = w.recover(&directory).await;
    assert!(found.status.unwrap().complete);
    assert!(lookups(&directory) > 0, "lookups restart");
    assert_eq!(balance(&w.st), VALUE);
    assert!(before > 0);
}

/// While the directory is down longer than it retains buckets, chain sync goes on. The
/// buckets adjoining the frontier have then expired, so the frontier bootstraps again from
/// the newer cumulative snapshot, which holds a payment made during the outage.
#[tokio::test]
async fn a_directory_down_longer_than_retention_bootstraps_again() {
    let mut w = World::new();
    w.advance(bucket_end(ACTIVATION + 1) + 1);
    let found = w.recover(&w.directory(&History::default())).await;
    let frontier = u32::from(found.status.unwrap().frontier.unwrap());

    let down = w.recover(Unreachable).await;
    assert!(
        matches!(down.delay, Some(Delay::Unavailable(_))),
        "{:?}",
        down.delay
    );
    let paid = w.pay(incoming(8));
    w.advance(frontier + 5 * BUCKET_BLOCKS);
    let expired = History {
        oldest_start: bucket_end(paid) + BUCKET_BLOCKS,
        ..History::default()
    };
    let directory = w.directory(&expired);
    let found = w.recover(&directory).await;
    let status = found.status.unwrap();
    assert!(status.complete, "{status:?}");
    assert!(requested(&directory, "paid/"));
    assert_eq!(balance(&w.st), VALUE);
}

/// A directory whose closed buckets end far below the wallet's chain tip, or whose epoch
/// went back, delays recovery.
#[tokio::test]
async fn a_directory_behind_the_wallet_delays_recovery() {
    let mut w = World::new();
    let stale_end = bucket_end(ACTIVATION + 1) + 1;
    w.advance(stale_end);
    let end = tip(&w.st);
    let newer = History {
        epoch: 2,
        ..History::default()
    };
    let found = w.recover(&w.directory(&newer)).await;
    assert!(found.delay.is_none());
    let older = w.recover(&w.directory(&History::default())).await;
    assert!(
        matches!(older.delay, Some(Delay::Behind)),
        "{:?}",
        older.delay
    );

    w.advance(stale_end + 5 * BUCKET_BLOCKS);
    let behind = recovering(&w.st, &w.records, &commitments(&w.records), end, &newer);
    let found = w.recover(&behind).await;
    assert!(
        matches!(found.delay, Some(Delay::Behind)),
        "{:?}",
        found.delay
    );
}

/// A late payment's scan hint, which the scan skipped because it scanned without the
/// key, as a scanner with a stale key snapshot does, becomes a late candidate and is
/// admitted with its inclusion path.
#[tokio::test]
async fn a_hint_a_stale_scanner_skipped_is_admitted_late() {
    let mut w = World::new();
    let parent = parent(&w.st);
    let record = pay_key_unscanned(&mut w.st, &parent, incoming(3), 0);
    let height = BlockHeight::from(record.payment.height);
    w.records.push(record);
    w.st.wallet_mut().update_chain_tip(height).unwrap();
    let end = ChainPoint {
        height,
        hash: zcash_primitives::block::BlockHash(block_hash(&w.st, height.into())),
    };
    // Check swap history looks the key up while the scan is short of its payment.
    let directory = recovering(
        &w.st,
        &w.records,
        &commitments(&w.records),
        end,
        &History::default(),
    );
    let checked = w.check_history(&directory, 0).await;
    assert!(!checked.status.unwrap().complete);
    // The scan stores the block without one-time keys.
    w.st.scan_cached_blocks(height, 1);
    assert_eq!(one_time_value(&w.st), 0);
    w.advance(bucket_end(height.into()) + 1);
    let found = w.recover(&w.directory(&History::default())).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), VALUE);
}

/// Check swap history reads every window receiver's history whatever the filters say, so
/// it finds a payment the paid sets left out, and reads `deeper` indices past the window
/// too.
#[tokio::test]
async fn check_history_bypasses_the_filters() {
    let mut w = World::new();
    w.pay(incoming(11));
    let paid = w.pay(incoming(150));
    w.advance(bucket_end(paid) + 1);
    let records = paged(&w.records);
    let commitments = commitments(&records);
    // The paid sets leave both payments out.
    let objects = recovery_objects(
        &w.st,
        &[],
        u32::from(tip(&w.st).height),
        &History::default(),
    );
    let end = tip(&w.st);
    let routes = publish_with(&records, &commitments, end, &provider(&[]), objects);
    let directory = Directory::new(routes);
    let found = w.recover(&directory).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(balance(&w.st), 0);

    let shallow = w.check_history(&directory, 0).await;
    assert!(shallow.status.unwrap().complete);
    assert_eq!(balance(&w.st), VALUE);
    let deep = w.check_history(&directory, 60).await;
    assert!(deep.status.unwrap().complete);
    assert_eq!(balance(&w.st), 2 * VALUE);
}

/// Lowering an account's birthday below a payment it already recovered as before its
/// birthday rewinds the frontier below the new birthday, so the whole receiver set is
/// tested against that history again, and restarts its lookups from page zero, so the
/// payment is credited.
#[tokio::test]
async fn lowering_the_birthday_credits_a_newly_eligible_payment() {
    let mut w = World::new();
    w.advance(ACTIVATION + 10);
    let low = w.st.latest_cached_block().unwrap().chain_state().clone();
    let seed = secrecy::SecretVec::new(vec![3; 32]);
    let network = *w.st.network();
    let usk = UnifiedSpendingKey::from_seed(&network, &[3; 32], 0u32.try_into().unwrap()).unwrap();
    let other = FullViewingKey::from(usk.orchard());
    let position = w.records.len() as u64;
    let record = pay_key_unscanned(&mut w.st, &other, incoming(2), position);
    let paid = BlockHeight::from(record.payment.height);
    w.st.scan_cached_blocks_with_one_time_ivks(paid, 1);
    w.records.push(record);
    w.advance(ACTIVATION + 60);
    let high = w.st.latest_cached_block().unwrap().chain_state().clone();
    let birthday = AccountBirthday::from_parts(high, None);
    let (account, _) =
        w.st.wallet_mut()
            .create_account("other", &seed, &birthday, None)
            .unwrap();
    w.advance(bucket_end(ACTIVATION + 61) + 1);
    w.account = account;
    let found = w.recover(&w.directory(&History::default())).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(w.st.get_total_balance(account).into_u64(), 0);

    w.st.wallet_mut()
        .rewind_to_chain_state(low, [account].into_iter().collect())
        .unwrap();
    let lowered = u32::from(paid) - 1;
    w.st.scan_cached_blocks_with_one_time_ivks(BlockHeight::from(lowered + 1), 200);
    let found = w.recover(&w.directory(&History::default())).await;
    assert!(found.status.unwrap().complete);
    assert_eq!(w.st.get_total_balance(account).into_u64(), VALUE);
}
