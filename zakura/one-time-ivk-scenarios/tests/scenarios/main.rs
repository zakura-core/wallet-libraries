//! End-to-end PIR-only stories with independent chain accounting and real encrypted queries.
mod harness;
use harness::{
    chain::{ACTIVATION, Chain, GENESIS, Payer},
    device::Device,
    directory::{Directory, ORIGIN},
};
use orchard::keys::Scope;
use zakura_one_time_ivk::{KeyId, Purpose};
use zakura_pir_client::receiver::transport::Inventories;
use zcash_client_backend::{
    data_api::{
        WalletRead as _, WalletWrite as _,
        one_time_ivk::restore::{FilterOutcome, FilterSpan},
        transparent_ledger::ChainPoint,
    },
    wallet::OvkPolicy,
};
use zcash_primitives::block::BlockHash;

/// Runs deterministic async network steps without giving the future a database lock.
fn run(future: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future);
}

/// New seed recovery stops at four empty histories, then recycles the lowest unused hole.
#[test]
fn seed_gap_and_recycled_hole() {
    run(async {
        let mut chain = Chain::new();
        let mut desktop = Device::new(&mut chain, [1; 32], ACTIVATION.into());
        for index in [0, 3, 3, 40] {
            chain.pay(
                &[(desktop.key(Purpose::Receive, index), 100_000)],
                Payer::Near,
            );
        }
        chain.mine(12);
        desktop.scan(&chain);
        assert_eq!(desktop.unspent_one_time_value(), 0);
        let directory = Directory::publish(&chain, 0, 0, 256, 0);
        desktop.recover(&chain, &directory).await;
        assert_eq!(desktop.unspent_one_time_value(), 300_000);
        assert_eq!(desktop.status(&chain).restore_next, 8);
        // One directory query for each of the eight keys, then one companion query per
        // recovered payment.
        assert_eq!(directory.counts().0, 11);
        desktop.reopen();
        let next = desktop
            .db
            .prepare_receive_reservation(desktop.account, chain.now(), chain.tip())
            .unwrap()
            .unwrap();
        assert_eq!(next.key_id().index(), 1);
        let client = desktop.connect(&directory).await;
        desktop
            .db
            .check_one_time_history(
                desktop.account,
                zakura_pir_client::receiver::publication(client.inventory()),
                Some(42),
            )
            .unwrap();
        desktop.drain(&chain, &client).await;
        assert_eq!(desktop.unspent_one_time_value(), 400_000);
    });
}

/// Filters stay optional for sync, negatives make no PIR query, positives use PIR only.
#[test]
fn live_filters_and_late_publication() {
    run(async {
        let mut chain = Chain::new();
        let mut desktop = Device::new(&mut chain, [2; 32], ACTIVATION.into());
        desktop.scan(&chain);
        let initial = Directory::publish(&chain, 0, 0, 256, 0);
        desktop.recover(&chain, &initial).await;
        let floor = chain.tip();
        chain.mine(2);
        desktop.scan(&chain);
        let empty = Directory::publish(&chain, 0, 0, 256, 0);
        hints(&mut desktop, &empty).await;
        assert_eq!(empty.counts().0, 0);
        let payment = chain
            .pay(&[(desktop.key(Purpose::Receive, 0), 100_000)], Payer::Near)
            .remove(0);
        desktop.scan(&chain);
        assert_eq!(desktop.unspent_one_time_value(), 0);
        let lagged = Directory::publish(&chain, 2, 0, 256, 0);
        hints(&mut desktop, &lagged).await;
        let work = desktop.status(&chain).lookups[0].clone();
        assert!(work.through >= payment.height);
        let client = desktop.connect(&lagged).await;
        assert!(
            zakura_pir_client::receiver::lookup(&client, &work)
                .await
                .is_err()
        );
        assert_eq!(lagged.counts().0, 0);
        chain.mine(4);
        desktop.scan(&chain);
        desktop.reopen();
        let current = Directory::publish(&chain, 0, 0, 256, 0);
        let client = desktop.connect(&current).await;
        desktop.drain(&chain, &client).await;
        assert_eq!(desktop.unspent_one_time_value(), 100_000);
        assert!(current.counts().0 > 0);
        assert!(
            desktop
                .db
                .block_fully_scanned()
                .unwrap()
                .unwrap()
                .block_height()
                > floor
        );
    });
}

/// Downloads real GCS bodies from the account's frontier and commits the span with its
/// locally matched receivers.
async fn hints(device: &mut Device, directory: &Directory) {
    let head = Inventories::block_head(ORIGIN, &directory, &GENESIS)
        .await
        .unwrap();
    let state = device
        .db
        .one_time_recovery(device.account, 0, None)
        .unwrap();
    let from = state
        .filter_frontier
        .map_or(ACTIVATION, |p| u32::from(p.height) + 1);
    let (token, receivers) = device.db.one_time_receivers(device.account).unwrap();
    let range = Inventories::block_range(ORIGIN, &directory, &head, from, 256)
        .await
        .unwrap();
    let bytes: Vec<_> = receivers.iter().map(|r| r.receiver).collect();
    let hits: Vec<_> = range
        .matches(&GENESIS, &bytes)
        .into_iter()
        .map(|(height, index)| (height.into(), receivers[index].key))
        .collect();
    let end = range.end();
    let span = FilterSpan {
        revision: head.revision,
        from: range.from().into(),
        parent: BlockHash(range.parent()),
        end: ChainPoint {
            height: end.height.into(),
            hash: BlockHash(end.hash),
        },
    };
    assert_eq!(
        device
            .db
            .record_one_time_filter_span(device.account, token, &span, &hits)
            .unwrap(),
        FilterOutcome::Committed
    );
    device.assert_no_stall();
}

/// Commits filters from the frontier, then runs the lookups that queued, as a wallet round
/// would.
async fn filter_round(device: &mut Device, chain: &Chain, directory: &Directory) {
    hints(device, directory).await;
    let client = device.connect(directory).await;
    device.drain(chain, &client).await;
}

/// A complete check after time offline reads paid keys too, so it finds a repeat payment to
/// a paid address without the explicit settings action.
#[test]
fn offline_repeat_found_by_complete_check() {
    run(async {
        let mut chain = Chain::new();
        let mut phone = Device::new(&mut chain, [3; 32], ACTIVATION.into());
        chain.pay(&[(phone.key(Purpose::Receive, 0), 100_000)], Payer::Near);
        chain.mine(12);
        phone.scan(&chain);
        phone
            .recover(&chain, &Directory::publish(&chain, 0, 0, 256, 0))
            .await;
        chain.pay(
            &[
                (phone.key(Purpose::Receive, 0), 200_000),
                (phone.key(Purpose::Receive, 1), 300_000),
            ],
            Payer::Near,
        );
        chain.mine(20);
        phone.scan(&chain);
        phone.reopen();
        let directory = Directory::publish(&chain, 0, 0, 4, 0);
        phone.recover(&chain, &directory).await;
        assert_eq!(phone.unspent_one_time_value(), 600_000);
        let client = phone.connect(&directory).await;
        phone
            .db
            .check_one_time_history(
                phone.account,
                zakura_pir_client::receiver::publication(client.inventory()),
                None,
            )
            .unwrap();
        phone.drain(&chain, &client).await;
        assert_eq!(phone.unspent_one_time_value(), 600_000);
    });
}

/// The second device learns a funded refund from its own memo and can spend its recovered receipt.
#[test]
fn funded_refund_cross_device_and_spend() {
    run(async {
        let mut chain = Chain::new();
        let mut phone = Device::new(&mut chain, [4; 32], ACTIVATION.into());
        let mut desktop = Device::new(&mut chain, [4; 32], ACTIVATION.into());
        chain.pay(&[(phone.fvk.clone(), 100_000_000)], Payer::Wallet);
        chain.mine(12);
        phone.scan(&chain);
        let swap = phone.quote_refund(&chain).await;
        let funding = phone.fund_refund(&swap, 20_000_000);
        assert!(chain.accepts(&funding).is_ok());
        chain.mine_tx(&funding);
        chain.mine(12);
        desktop.scan(&chain);
        let directory = Directory::publish(&chain, 0, 0, 256, 0);
        desktop.recover(&chain, &directory).await;
        assert!(desktop.status(&chain).lookups.is_empty());
        chain.pay(
            &[(phone.key(Purpose::Refund, swap.index), 1_000_000)],
            Payer::Near,
        );
        chain.mine(12);
        desktop.scan(&chain);
        desktop
            .recover(&chain, &Directory::publish(&chain, 0, 0, 256, 0))
            .await;
        assert_eq!(desktop.unspent_one_time_value(), 1_000_000);
        let destination = phone
            .key(Purpose::Receive, 50)
            .address_at(0u32, Scope::External);
        let spend = desktop.send_to(destination, 500_000, OvkPolicy::Sender);
        let accepted = chain
            .accepts(&spend)
            .expect("independent proof and signature verification");
        assert!(accepted.actions > 0 && accepted.anchor_height >= ACTIVATION.into());
        chain.mine_tx(&spend);
        phone.scan(&chain);
        phone
            .recover(&chain, &Directory::publish(&chain, 0, 0, 256, 0))
            .await;
        assert_eq!(phone.unspent_one_time_value(), 0);
    });
}

/// A refund after the birthday still needs its earlier funding memo, recovered by an ordinary rescan.
#[test]
fn refund_after_birthday_requires_earlier_funding_memo() {
    run(async {
        use std::collections::HashSet;
        let mut chain = Chain::new();
        let mut phone = Device::new(&mut chain, [10; 32], ACTIVATION.into());
        chain.pay(&[(phone.fvk.clone(), 100_000_000)], Payer::Wallet);
        chain.mine(12);
        phone.scan(&chain);
        let swap = phone.quote_refund(&chain).await;
        let funding = phone.fund_refund(&swap, 20_000_000);
        chain.accepts(&funding).unwrap();
        chain.mine_tx(&funding);
        chain.mine(12);
        let birthday = chain.tip();
        let mut desktop = Device::new(&mut chain, [10; 32], birthday);
        let refund = chain.pay(
            &[(phone.key(Purpose::Refund, swap.index), 100_000)],
            Payer::Near,
        );
        chain.mine(12);
        desktop.scan(&chain);
        let directory = Directory::publish(&chain, 0, 0, 256, 0);
        desktop.recover(&chain, &directory).await;
        assert_receipts(&desktop, &[]);

        // Receive-index history cannot substitute for the missing refund memo.
        let client = desktop.connect(&directory).await;
        assert!(
            desktop
                .db
                .check_one_time_history(
                    desktop.account,
                    zakura_pir_client::receiver::publication(client.inventory()),
                    None
                )
                .unwrap()
        );
        desktop.drain(&chain, &client).await;
        assert_receipts(&desktop, &[]);

        desktop
            .db
            .rewind_to_chain_state(
                chain.state_below(ACTIVATION.into()),
                HashSet::from([desktop.account]),
            )
            .unwrap();
        desktop.reopen();
        desktop.scan(&chain);
        assert_receipts(&desktop, &[]);
        desktop.recover(&chain, &directory).await;
        assert_receipts(&desktop, &refund);
    });
}

/// Separate accounts in one database keep their keys, cursors, and feature settings isolated.
#[test]
fn multiple_accounts_sync_independently() {
    run(async {
        use secrecy::SecretVec;
        use zcash_client_backend::data_api::AccountBirthday;
        let mut chain = Chain::new();
        let mut wallet = Device::new(&mut chain, [5; 32], ACTIVATION.into());
        let first = wallet.account;
        let (second, usk) = wallet
            .db
            .create_account(
                "second",
                &SecretVec::new(vec![5; 32]),
                &AccountBirthday::from_parts(chain.state_below(ACTIVATION.into()), None),
                None,
            )
            .unwrap();
        let parent = orchard::keys::FullViewingKey::from(usk.orchard());
        let second_key = KeyId::new(Purpose::Receive, 0).derive(&parent).unwrap();
        chain.pay(
            &[
                (wallet.key(Purpose::Receive, 0), 100_000),
                (second_key, 200_000),
            ],
            Payer::Near,
        );
        chain.mine(12);
        wallet.scan(&chain);
        let directory = Directory::publish(&chain, 0, 0, 256, 0);
        wallet.recover(&chain, &directory).await;
        assert_eq!(wallet.unspent_one_time_value(), 100_000);
        let second_state = wallet
            .db
            .one_time_recovery(second, chain.now(), None)
            .unwrap();
        assert!(!second_state.enabled && second_state.lookups.is_empty());
        wallet.db.enable_one_time_recovery(second).unwrap();
        wallet.account = second;
        wallet.recover(&chain, &directory).await;
        assert_eq!(wallet.unspent_one_time_value(), 300_000);
        assert_eq!(
            wallet
                .db
                .one_time_recovery(first, chain.now(), None)
                .unwrap()
                .restore_next,
            5
        );
        assert_eq!(wallet.status(&chain).restore_next, 5);
    });
}

/// A payment before the birthday is ignored, neither credited nor extending seed discovery,
/// until the user lowers the birthday.
#[test]
fn lowering_birthday_recovers_an_excluded_payment_after_restart() {
    run(async {
        use std::collections::HashSet;
        let mut chain = Chain::new();
        let phone = Device::new(&mut chain, [6; 32], ACTIVATION.into());
        chain.pay(&[(phone.key(Purpose::Receive, 0), 100_000)], Payer::Near);
        chain.mine(12);
        let birthday = chain.tip();
        let mut desktop = Device::new(&mut chain, [6; 32], birthday);
        desktop.scan(&chain);
        let directory = Directory::publish(&chain, 0, 0, 256, 0);
        desktop.recover(&chain, &directory).await;
        assert_eq!(desktop.unspent_one_time_value(), 0);
        assert_eq!(desktop.status(&chain).restore_next, 4);
        desktop
            .db
            .rewind_to_chain_state(
                chain.state_below(ACTIVATION.into()),
                HashSet::from([desktop.account]),
            )
            .unwrap();
        desktop.reopen();
        desktop.scan(&chain);
        assert_eq!(desktop.unspent_one_time_value(), 0);
        desktop.recover(&chain, &directory).await;
        assert_eq!(desktop.unspent_one_time_value(), 100_000);
    });
}

/// The documented boundary: the wallet ignores payments before the birthday, so I0 paid in a
/// sealed shard before it doesn't extend the seed walk, which sees I0 to I3 empty and stops
/// before I4, paid afterwards. Complete recovery needs a birthday before the first use.
#[test]
fn a_pre_birthday_payment_leaves_a_later_i4_unfound() {
    run(async {
        let mut chain = Chain::new();
        let phone = Device::new(&mut chain, [8; 32], ACTIVATION.into());
        chain.pay(&[(phone.key(Purpose::Receive, 0), 100_000)], Payer::Near);
        chain.mine(2 * harness::directory::SEAL_BLOCKS);
        let birthday = chain.tip();
        chain.pay(&[(phone.key(Purpose::Receive, 4), 70_000)], Payer::Near);
        chain.mine(12);
        let mut desktop = Device::new(&mut chain, [8; 32], birthday);
        desktop.scan(&chain);
        let directory = Directory::publish(&chain, 0, 0, 256, 0);
        desktop.recover(&chain, &directory).await;
        assert_eq!(desktop.unspent_one_time_value(), 0);
        let status = desktop.status(&chain);
        assert!(status.restore_complete);
        assert_eq!(status.restore_next, 4);
    });
}

/// Errors and canceled work never become successful empty pages or silently resume manual ranges.
#[test]
fn failures_and_manual_cancellation_survive_restart() {
    run(async {
        use std::sync::atomic::Ordering;
        let mut chain = Chain::new();
        let mut wallet = Device::new(&mut chain, [8; 32], ACTIVATION.into());
        chain.pay(&[(wallet.key(Purpose::Receive, 8), 100_000)], Payer::Near);
        chain.mine(12);
        wallet.scan(&chain);
        let directory = Directory::publish(&chain, 0, 0, 256, 0);
        wallet.recover(&chain, &directory).await;
        assert_eq!(wallet.unspent_one_time_value(), 0);
        let client = wallet.connect(&directory).await;
        let publication = zakura_pir_client::receiver::publication(client.inventory());
        wallet
            .db
            .check_one_time_history(wallet.account, publication, Some(10))
            .unwrap();
        let held = wallet.status(&chain).lookups[0].clone();
        directory.unavailable.store(true, Ordering::SeqCst);
        assert!(
            zakura_pir_client::receiver::lookup(&client, &held)
                .await
                .is_err()
        );
        assert_eq!(wallet.status(&chain).manual.unwrap().next, 4);
        directory.unavailable.store(false, Ordering::SeqCst);
        let answer = zakura_pir_client::receiver::lookup(&client, &held)
            .await
            .unwrap();
        wallet.db.cancel_one_time_history(wallet.account).unwrap();
        wallet.reopen();
        assert!(
            !wallet
                .db
                .record_one_time_lookup(wallet.account, &held, &answer, chain.now())
                .unwrap()
        );
        assert!(!wallet.status(&chain).manual.unwrap().active);
        assert!(wallet.status(&chain).lookups.is_empty());
        wallet
            .db
            .check_one_time_history(wallet.account, publication, None)
            .unwrap();
        wallet.drain(&chain, &client).await;
        assert_eq!(wallet.unspent_one_time_value(), 100_000);
        assert_eq!(wallet.status(&chain).manual.unwrap().next, 10);
    });
}

/// A real receipt re-mined at a new position is repaired, without crediting it twice.
#[test]
fn known_receipt_reorg_repairs_position() {
    run(async {
        let mut chain = Chain::new();
        let mut payer = Device::new(&mut chain, [9; 32], ACTIVATION.into());
        let mut receiver = Device::new(&mut chain, [10; 32], ACTIVATION.into());
        chain.pay(&[(payer.fvk.clone(), 10_000_000)], Payer::Wallet);
        chain.mine(12);
        payer.scan(&chain);
        let key = receiver.key(Purpose::Receive, 0);
        let transaction = payer.send_to(
            key.address_at(0u32, Scope::External),
            1_000_000,
            OvkPolicy::custom_from_common_bytes(&[0; 32]),
        );
        let fork = chain.tip();
        let height = chain.mine_tx(&transaction);
        let original = chain.record_payment(height, &key, 1_000_000, Payer::Near);
        chain.mine(12);
        receiver.scan(&chain);
        receiver
            .recover(&chain, &Directory::publish(&chain, 0, 0, 256, 0))
            .await;
        assert_eq!(receiver.unspent_one_time_value(), original.value);
        chain.rewind(fork);
        chain.mine(11);
        let height = chain.mine_tx(&transaction);
        let replacement = chain.record_payment(height, &key, 1_000_000, Payer::Near);
        assert_eq!(original.id(), replacement.id());
        assert_eq!(original.nullifier, replacement.nullifier);
        assert_eq!(original.receiver, replacement.receiver);
        assert_eq!(original.payer, Payer::Near);
        assert_ne!(original.position, replacement.position);
        chain.mine(12);
        receiver.db.truncate_to_height(fork).unwrap();
        receiver.scan(&chain);
        receiver.reopen();
        receiver
            .recover(&chain, &Directory::publish(&chain, 0, 0, 256, 0))
            .await;
        let position: u64 = receiver
            .conn()
            .query_row(
                "SELECT commitment_tree_position FROM ironwood_received_notes n
        JOIN transactions t ON t.id_tx=n.transaction_id WHERE t.txid=?1 AND n.action_index=?2",
                rusqlite::params![replacement.id().0, replacement.action_index],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(position, replacement.position);
        assert_eq!(receiver.unspent_one_time_value(), 1_000_000);
    });
}

/// Compares persisted note identities and amounts with only the independently mined outputs.
fn assert_receipts(device: &Device, expected: &[harness::chain::Mined]) {
    use std::collections::BTreeMap;
    let conn = device.conn();
    let mut statement = conn
        .prepare(
            "SELECT t.txid, n.action_index, n.value FROM ironwood_received_notes n
         JOIN transactions t ON t.id_tx = n.transaction_id
         WHERE n.one_time_key_id IS NOT NULL AND t.mined_height IS NOT NULL",
        )
        .unwrap();
    let actual: BTreeMap<([u8; 32], u32), u64> = statement
        .query_map([], |row| {
            let txid: Vec<u8> = row.get(0)?;
            Ok((
                (txid.try_into().expect("transaction ID"), row.get(1)?),
                row.get(2)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|output| (output.id(), output.value))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        device.unspent_one_time_value(),
        expected.values().sum::<u64>()
    );
}

/// Random payment identities, amounts, holes and repeats: filters find each round's
/// payments live, and complete checks find repeats offline.
#[test]
fn randomized_cross_device_payment_oracle() {
    use rand_core::TryRng as _;
    use zcash_client_backend::data_api::testing::TestRng;
    run(async {
        for scenario in 0..3u8 {
            let seed = [40 + scenario; 32];
            let mut rng = TestRng::seed_from_u64(70 + u64::from(scenario));
            let mut chain = Chain::new();
            let mut phone = Device::new(&mut chain, seed, ACTIVATION.into());
            let mut desktop = Device::new(&mut chain, seed, ACTIVATION.into());
            phone.scan(&chain);
            desktop.scan(&chain);
            let initial = Directory::publish(&chain, 0, 0, 256, 0);
            phone.recover(&chain, &initial).await;
            desktop.recover(&chain, &initial).await;
            let mut payments = Vec::new();
            let mut desktop_receipts = Vec::new();
            let mut highest = None::<u64>;
            for round in 0..12 {
                // Issuance is bounded by independently paid and confirmed prior rounds.
                let upper = highest.map_or(4, |h| h + 5);
                for _ in 0..1 + rng.try_next_u64().unwrap() % 3 {
                    let index = if round % 4 == 0 {
                        0
                    } else {
                        rng.try_next_u64().unwrap() % upper
                    };
                    let value = 100_000 + rng.try_next_u64().unwrap() % 100_000;
                    let payment = chain
                        .pay(&[(phone.key(Purpose::Receive, index), value)], Payer::Near)
                        .remove(0);
                    payments.push((index, payment));
                    highest = Some(highest.map_or(index, |h| h.max(index)));
                }
                chain.mine(12 + (rng.try_next_u64().unwrap() % 4) as u32);
                phone.scan(&chain);
                let directory = Directory::publish(&chain, 0, 0, 256, 0);
                filter_round(&mut phone, &chain, &directory).await;
                assert_receipts(
                    &phone,
                    &payments.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(),
                );
                phone.assert_no_stall();
                if rng.try_next_u64().unwrap() % 2 == 0 {
                    phone.reopen();
                    phone.assert_no_stall();
                }
                if round % 3 == 2 {
                    // A complete check reads every watched key, paid or not, so the
                    // offline desktop finds every payment so far, repeats included.
                    desktop_receipts = payments.iter().map(|(_, p)| p.clone()).collect();
                    desktop.reopen();
                    desktop.scan(&chain);
                    desktop.recover(&chain, &directory).await;
                    desktop.assert_no_stall();
                    assert_receipts(&desktop, &desktop_receipts);
                }
            }
            let all: Vec<_> = payments.iter().map(|(_, p)| p.clone()).collect();
            assert_eq!(
                desktop_receipts.len(),
                all.len(),
                "the last round was a complete check"
            );
            let directory = Directory::publish(&chain, 0, 0, 256, 0);
            let client = desktop.connect(&directory).await;
            assert!(
                desktop
                    .db
                    .check_one_time_history(
                        desktop.account,
                        zakura_pir_client::receiver::publication(client.inventory()),
                        None
                    )
                    .unwrap()
            );
            desktop.assert_no_stall();
            desktop.drain(&chain, &client).await;
            desktop.assert_no_stall();
            assert_receipts(&desktop, &all);
            // Complete more receive histories than one progress step's budget, then rewind
            // so part of that coverage survives, and search it again against a publication
            // from the surviving chain.
            let wide = highest.unwrap_or(0) + 70;
            let client = desktop.connect(&directory).await;
            assert!(
                desktop
                    .db
                    .check_one_time_history(
                        desktop.account,
                        zakura_pir_client::receiver::publication(client.inventory()),
                        Some(wide)
                    )
                    .unwrap()
            );
            desktop.drain(&chain, &client).await;
            desktop.assert_no_stall();
            let depth = 1 + (rng.try_next_u64().unwrap() % 4) as u32;
            desktop.db.truncate_to_height(chain.tip() - depth).unwrap();
            desktop.assert_no_stall();
            // The wallet may truncate further, to its nearest retained checkpoint.
            let kept = desktop
                .db
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height();
            let surviving = Directory::publish(&chain, u32::from(chain.tip() - kept), 0, 256, 0);
            let client = desktop.connect(&surviving).await;
            assert!(
                desktop
                    .db
                    .check_one_time_history(
                        desktop.account,
                        zakura_pir_client::receiver::publication(client.inventory()),
                        Some(wide)
                    )
                    .unwrap()
            );
            desktop.assert_no_stall();
            // Older work may wait for a later publication; answer what this one covers.
            for _ in 0..512 {
                let Some(work) = desktop
                    .status(&chain)
                    .lookups
                    .into_iter()
                    .find(|w| w.through <= kept)
                else {
                    break;
                };
                let page = zakura_pir_client::receiver::lookup(&client, &work)
                    .await
                    .unwrap();
                assert!(
                    desktop
                        .db
                        .record_one_time_lookup(desktop.account, &work, &page, chain.now())
                        .unwrap()
                );
                desktop.assert_no_stall();
            }
            desktop.scan(&chain);
            desktop.recover(&chain, &directory).await;
            desktop.assert_no_stall();
            assert_receipts(&desktop, &all);
            // A birthday-lowering restart reopens every known history.
            desktop
                .db
                .rewind_to_chain_state(
                    chain.state_below(ACTIVATION.into()),
                    std::collections::HashSet::from([desktop.account]),
                )
                .unwrap();
            desktop.reopen();
            desktop.assert_no_stall();
            desktop.scan(&chain);
            desktop.recover(&chain, &directory).await;
            desktop.assert_no_stall();
            assert_receipts(&desktop, &all);
            let mut restored = Device::new(&mut chain, seed, ACTIVATION.into());
            restored.scan(&chain);
            restored.recover(&chain, &directory).await;
            restored.assert_no_stall();
            assert_receipts(&restored, &all);
        }
    });
}
