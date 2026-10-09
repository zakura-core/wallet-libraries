//! Seedless upgrades of representative wallets written before the ledger schema existed,
//! followed by recovery, qualification, and promotion.
//!
//! Each fixture is created at the migration state before the ledger schema, with real keys
//! and addresses, and its transparent history is written the way older builds wrote it. The
//! upgrade gets no seed, so imported-only and hardware-first wallets must upgrade too.

use std::collections::BTreeMap;

use secrecy::SecretVec;
use tempfile::NamedTempFile;
use transparent::{
    address::Script,
    keys::{IncomingViewingKey as _, NonHardenedChildIndex},
};
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, chain::ChainState, testing::TestRng,
};
use zcash_keys::{
    encoding::AddressCodec as _,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_protocol::consensus::Network;

use super::*;
use crate::{
    WalletDb,
    testing::db::{test_clock, test_rng},
    util::testing::FixedClock,
    wallet::init::{WalletMigrator, migrations::tests::BEFORE_TRANSPARENT_LEDGER},
};

type Db = WalletDb<Connection, Network, FixedClock, TestRng>;

const NETWORK: Network = Network::TestNetwork;

fn block_hash(height: BlockHeight) -> BlockHash {
    let mut hash = [0xb1; 32];
    hash[..4].copy_from_slice(&u32::from(height).to_le_bytes());
    BlockHash(hash)
}

/// A wallet at the migration state before the ledger schema.
struct PreLedgerWallet {
    file: NamedTempFile,
    db: Db,
    birthday: BlockHeight,
    tip: BlockHeight,
    keys: BTreeMap<AccountUuid, UnifiedFullViewingKey>,
}

impl PreLedgerWallet {
    fn new() -> Self {
        let file = NamedTempFile::new().unwrap();
        let mut db = WalletDb::for_path(file.path(), NETWORK, test_clock(), test_rng()).unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, BEFORE_TRANSPARENT_LEDGER)
            .unwrap();
        let birthday = BlockHeight::from_u32(300_000);
        PreLedgerWallet {
            file,
            db,
            birthday,
            tip: birthday + 19,
            keys: BTreeMap::new(),
        }
    }

    fn account_birthday(&self) -> AccountBirthday {
        AccountBirthday::from_parts(
            ChainState::empty(self.birthday - 1, BlockHash([0; 32])),
            None,
        )
    }

    /// Creates an account derived from `seed`.
    fn derived(&mut self, seed: u8) -> AccountUuid {
        let (account, usk) = self
            .db
            .create_account(
                &format!("derived {seed}"),
                &SecretVec::new(vec![seed; 32]),
                &self.account_birthday(),
                None,
            )
            .unwrap();
        self.keys.insert(account, usk.to_unified_full_viewing_key());
        account
    }

    /// Imports an account from its viewing key, with or without its spending key held elsewhere.
    fn imported(&mut self, seed: u8, spending: bool) -> AccountUuid {
        let ufvk = UnifiedSpendingKey::from_seed(&NETWORK, &[seed; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        let purpose = if spending {
            AccountPurpose::Spending { derivation: None }
        } else {
            AccountPurpose::ViewOnly
        };
        let account = self
            .db
            .import_account_ufvk(
                &format!("imported {seed}"),
                &ufvk,
                &self.account_birthday(),
                purpose,
                None,
            )
            .unwrap()
            .id();
        self.keys.insert(account, ufvk);
        account
    }

    fn external(&self, account: AccountUuid) -> TransparentAddress {
        self.keys[&account]
            .transparent()
            .unwrap()
            .derive_external_ivk()
            .unwrap()
            .derive_address(NonHardenedChildIndex::ZERO)
            .unwrap()
    }

    /// Records the chain from the birthday through the tip as scanned.
    fn scanned(&self) {
        for height in u32::from(self.birthday)..=u32::from(self.tip) {
            let height = BlockHeight::from_u32(height);
            self.db
                .conn
                .execute(
                    "INSERT INTO blocks (height, hash, time, sapling_tree)
                     VALUES (?1, ?2, 0, X'00')",
                    rusqlite::params![u32::from(height), block_hash(height).0],
                )
                .unwrap();
        }
        self.db
            .conn
            .execute(
                "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                 VALUES (?1, ?2, 10)",
                rusqlite::params![u32::from(self.birthday), u32::from(self.tip) + 1],
            )
            .unwrap();
    }

    /// Records a transaction mined at `mined`, or unmined, returning its row.
    fn transaction(&self, txid: [u8; 32], mined: Option<BlockHeight>, coinbase: bool) -> i64 {
        let mined = mined.map(u32::from);
        self.db
            .conn
            .execute(
                "INSERT INTO transactions (txid, block, mined_height, tx_index, min_observed_height)
                 VALUES (?1, ?2, ?2, ?3, ?4)
                 ON CONFLICT (txid) DO NOTHING",
                rusqlite::params![
                    txid,
                    mined,
                    mined.map(|_| if coinbase { 0 } else { 1 }),
                    mined.unwrap_or(u32::from(self.birthday) + 7),
                ],
            )
            .unwrap();
        self.db
            .conn
            .query_row(
                "SELECT id_tx FROM transactions WHERE txid = ?1",
                [txid],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Records an output of `account` at its external address, as public discovery did.
    fn output(
        &self,
        account: AccountUuid,
        txid: [u8; 32],
        value: u64,
        mined: Option<BlockHeight>,
        coinbase: bool,
    ) -> OutPoint {
        let tx = self.transaction(txid, mined, coinbase);
        let address = self.external(account);
        let encoded = address.encode(&NETWORK);
        self.db
            .conn
            .execute(
                "INSERT INTO transparent_received_outputs (transaction_id, output_index,
                     account_id, address, script, value_zat, max_observed_unspent_height,
                     address_id)
                 SELECT ?1, 0, a.id, ?2, ?3, ?4, ?5, ad.id
                 FROM accounts a
                 JOIN addresses ad ON ad.account_id = a.id
                     AND ad.cached_transparent_receiver_address = ?2
                 WHERE a.uuid = ?6",
                rusqlite::params![
                    tx,
                    encoded,
                    Script::from(address.script()).0.0,
                    value,
                    mined.map(u32::from),
                    account.0,
                ],
            )
            .map(|rows| assert_eq!(rows, 1))
            .unwrap();
        OutPoint::new(txid, 0)
    }

    /// Records that `spending` spent `output`.
    fn spend(&self, output: &OutPoint, spending: i64) {
        let rows = self
            .db
            .conn
            .execute(
                "INSERT INTO transparent_received_output_spends
                     (transparent_received_output_id, transaction_id)
                 SELECT o.id, ?1 FROM transparent_received_outputs o
                 JOIN transactions t ON t.id_tx = o.transaction_id
                 WHERE t.txid = ?2 AND o.output_index = ?3",
                rusqlite::params![spending, output.hash(), output.n()],
            )
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// Records a send this wallet created that is not mined yet, spending `input`.
    fn local_send(&self, account: AccountUuid, txid: [u8; 32], input: &OutPoint) {
        self.db
            .conn
            .execute(
                "INSERT INTO transactions (txid, created, expiry_height, raw, fee, target_height,
                     min_observed_height)
                 VALUES (?1, '2026-01-01T00:00:00Z', ?2, X'00', 1000, ?3, ?4)",
                rusqlite::params![
                    txid,
                    u32::from(self.tip) + 40,
                    u32::from(self.tip) + 1,
                    u32::from(self.tip)
                ],
            )
            .unwrap();
        let tx = self.transaction(txid, None, false);
        self.spend(input, tx);
        self.db
            .conn
            .execute(
                "INSERT INTO sent_notes (transaction_id, output_pool, output_index,
                     from_account_id, to_address, value)
                 SELECT ?1, 0, 0, id, 't-external', 15000 FROM accounts WHERE uuid = ?2",
                rusqlite::params![tx, account.0],
            )
            .unwrap();
    }

    /// Reserves `output` for a proposal under construction.
    fn lock(&self, output: &OutPoint) {
        self.db
            .conn
            .execute(
                "UPDATE transparent_received_outputs SET lock_expiry_height = ?1, lock_owner = X'AA'
                 WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?2)
                 AND output_index = ?3",
                rusqlite::params![u32::from(self.tip) + 10, output.hash(), output.n()],
            )
            .unwrap();
    }

    fn receive(
        &self,
        account: AccountUuid,
        outpoint: &OutPoint,
        value: u64,
        mined: BlockHeight,
        coinbase: bool,
    ) -> ReceiveEvent {
        ReceiveEvent {
            metadata: None,
            outpoint: outpoint.clone(),
            address: self.external(account),
            value: Zatoshis::const_from_u64(value),
            coinbase,
            mined_height: mined,
        }
    }

    /// Upgrades without a seed, then recovers every account from its `events` under
    /// `PrivateRequired`, qualifies the revision, and promotes every account.
    fn upgrade_and_activate(
        mut self,
        events: BTreeMap<AccountUuid, (Vec<ReceiveEvent>, Vec<SpendEvent>)>,
    ) -> Upgraded {
        let wallet_rows = |conn: &Connection| {
            production_dump(conn)
                .into_iter()
                .filter(|(table, _)| {
                    table != "schemer_migrations" && table != "tx_reconfirmation_receipts"
                })
                // Txid enhancement tables are added empty: no wallet here has ledger-origin or
                // route-2 transactions before the upgrade.
                .filter(|(table, rows)| {
                    !(table.starts_with("transparent_detail_work")
                        || table.starts_with("transparent_tx_display"))
                        || {
                            assert!(rows.is_empty(), "{table} is not empty");
                            false
                        }
                })
                .collect::<Vec<_>>()
        };
        let before = wallet_rows(&self.db.conn);
        WalletMigrator::new().init_or_migrate(&mut self.db).unwrap();
        // The upgrade changes nothing the wallet already held. Later migrations may add status
        // observations to the retrieval queue, keeping every row queued before.
        let split = |rows: Vec<(String, Vec<String>)>| {
            let (queue, rest): (Vec<_>, Vec<_>) = rows
                .into_iter()
                .partition(|(table, _)| table == "tx_retrieval_queue");
            (
                queue.into_iter().flat_map(|(_, r)| r).collect::<Vec<_>>(),
                rest,
            )
        };
        let (queued_before, before) = split(before);
        let (queued_after, after) = split(wallet_rows(&self.db.conn));
        assert_eq!(after, before);
        assert!(queued_before.iter().all(|row| queued_after.contains(row)));
        assert_eq!(
            super::super::super::super::records_without_origin(&self.db.conn),
            0
        );

        let db = &mut self.db;
        db.set_transparent_ledger_mode(PrivateRequired);
        db.apply_transparent_policy(PrivateRequired).unwrap();
        let fixture = revision(1, true);
        for account in self.keys.keys() {
            let (receives, spends) = events.get(account).cloned().unwrap_or_default();
            loop {
                let ws = db.transparent_watch_set(*account).unwrap();
                assert_eq!(ws.target.unwrap().height, self.tip);
                let mut c = commit(&ws);
                c.revision = fixture.clone();
                c.receives = receives.clone();
                c.spends = spends.clone();
                c.coverage = full_coverage(&ws);
                if !db.apply_transparent_ledger_commit(c).unwrap().window_grew {
                    break;
                }
            }
        }
        db.qualify_transparent_revision(&fixture).unwrap();
        db.apply_transparent_policy(PrivateRequired).unwrap();
        db.set_transparent_ledger_mode(PrivateRequired);
        for account in self.keys.keys() {
            db.promote_transparent_account(*account).unwrap();
        }
        Upgraded {
            _file: self.file,
            db: self.db,
        }
    }
}

struct Upgraded {
    _file: NamedTempFile,
    db: Db,
}

impl Upgraded {
    fn spendable(&self, account: AccountUuid) -> Zatoshis {
        let s = self
            .db
            .transparent_ledger_snapshot(account, ConfirmationsPolicy::MIN)
            .unwrap();
        assert_eq!(s.authority, TransparentAuthority::Private);
        assert_eq!(
            self.db.transparent_watch_set(account).unwrap().lifecycle,
            AccountLifecycle::Active
        );
        s.authorized.unwrap().regular.spendable_value()
    }

    fn origins(&self, outpoint: &OutPoint) -> Vec<i64> {
        super::super::super::super::output_origins(&self.db.conn, outpoint)
    }
}

#[test]
fn a_fresh_wallet_upgrades_and_activates() {
    let mut w = PreLedgerWallet::new();
    let account = w.derived(1);
    w.scanned();
    let upgraded = w.upgrade_and_activate(BTreeMap::new());
    assert_eq!(upgraded.spendable(account), Zatoshis::ZERO);
}

type LocalSend = (
    Option<String>,
    Vec<u8>,
    Option<i64>,
    Option<u32>,
    Option<u32>,
);

#[test]
fn a_long_lived_wallet_upgrades_and_activates_keeping_its_local_history() {
    let mut w = PreLedgerWallet::new();
    let account = w.derived(1);
    w.scanned();
    let b = w.birthday;
    // Public discovery found these outputs over the wallet's life.
    let reserved = w.output(account, [0x11; 32], 50_000, Some(b + 2), false);
    let spent = w.output(account, [0x12; 32], 30_000, Some(b + 3), false);
    let spending = w.transaction([0x22; 32], Some(b + 5), false);
    w.spend(&spent, spending);
    let coinbase = w.output(account, [0x13; 32], 60_000, Some(b + 4), true);
    let sending = w.output(account, [0x14; 32], 20_000, Some(b + 6), false);
    // An earlier rewind un-mined this one; it is mined again later.
    let rewound = w.output(account, [0x15; 32], 10_000, None, false);
    // A send in flight, and an output reserved for a proposal.
    w.local_send(account, [0x24; 32], &sending);
    w.lock(&reserved);

    // Its creation time, raw bytes, fee, target, and placement.
    let local_send = |db: &Db| -> LocalSend {
        db.conn
            .query_row(
                "SELECT created, raw, fee, target_height, mined_height
                 FROM transactions WHERE txid = ?1",
                [[0x24u8; 32]],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap()
    };
    let lock = |db: &Db| -> (Option<u32>, Option<Vec<u8>>) {
        db.conn
            .query_row(
                "SELECT lock_expiry_height, lock_owner FROM transparent_received_outputs o
                 JOIN transactions t ON t.id_tx = o.transaction_id WHERE t.txid = ?1",
                [[0x11u8; 32]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    };
    let (send_before, lock_before) = (local_send(&w.db), lock(&w.db));

    let events = BTreeMap::from([(
        account,
        (
            vec![
                w.receive(account, &reserved, 50_000, b + 2, false),
                w.receive(account, &spent, 30_000, b + 3, false),
                w.receive(account, &coinbase, 60_000, b + 4, true),
                w.receive(account, &sending, 20_000, b + 6, false),
                w.receive(account, &rewound, 10_000, b + 9, false),
            ],
            vec![SpendEvent {
                metadata: None,
                spending_txid: TxId::from_bytes([0x22; 32]),
                input_index: 0,
                prevout: spent.clone(),
                prevout_address: w.external(account),
                mined_height: b + 5,
            }],
        ),
    )]);
    let upgraded = w.upgrade_and_activate(events);

    // Only the output mined again after the rewind is spendable: the reserved one stays
    // locked, the one in flight stays spent, and the coinbase output is immature.
    assert_eq!(
        upgraded.spendable(account),
        Zatoshis::const_from_u64(10_000)
    );
    assert_eq!(local_send(&upgraded.db), send_before);
    assert_eq!(lock(&upgraded.db), lock_before);
    assert_eq!(
        upgraded
            .db
            .get_tx_height(TxId::from_bytes([0x15; 32]))
            .unwrap(),
        Some(b + 9)
    );
    for outpoint in [&reserved, &spent, &coinbase, &sending, &rewound] {
        assert_eq!(upgraded.origins(outpoint), vec![0, 2]);
    }
}

#[test]
fn a_multi_seed_wallet_with_a_cross_account_transfer_upgrades_and_activates() {
    let mut w = PreLedgerWallet::new();
    let (payer, payee) = (w.derived(1), w.derived(2));
    w.scanned();
    let b = w.birthday;
    let funding = w.output(payer, [0x31; 32], 40_000, Some(b + 2), false);
    // One transaction spends the payer's output and pays the payee.
    let transfer = w.output(payee, [0x32; 32], 35_000, Some(b + 4), false);
    let transfer_tx = w.transaction([0x32; 32], Some(b + 4), false);
    w.spend(&funding, transfer_tx);

    let events = BTreeMap::from([
        (
            payer,
            (
                vec![w.receive(payer, &funding, 40_000, b + 2, false)],
                vec![SpendEvent {
                    metadata: None,
                    spending_txid: TxId::from_bytes([0x32; 32]),
                    input_index: 0,
                    prevout: funding.clone(),
                    prevout_address: w.external(payer),
                    mined_height: b + 4,
                }],
            ),
        ),
        (
            payee,
            (
                vec![w.receive(payee, &transfer, 35_000, b + 4, false)],
                vec![],
            ),
        ),
    ]);
    let upgraded = w.upgrade_and_activate(events);
    assert_eq!(upgraded.spendable(payer), Zatoshis::ZERO);
    assert_eq!(upgraded.spendable(payee), Zatoshis::const_from_u64(35_000));
}

#[test]
fn an_imported_only_wallet_upgrades_and_activates() {
    let mut w = PreLedgerWallet::new();
    let account = w.imported(3, true);
    w.scanned();
    let b = w.birthday;
    let received = w.output(account, [0x41; 32], 25_000, Some(b + 3), false);
    let events = BTreeMap::from([(
        account,
        (
            vec![w.receive(account, &received, 25_000, b + 3, false)],
            vec![],
        ),
    )]);
    let upgraded = w.upgrade_and_activate(events);
    assert_eq!(
        upgraded.spendable(account),
        Zatoshis::const_from_u64(25_000)
    );
}

#[test]
fn a_hardware_first_wallet_upgrades_and_activates() {
    let mut w = PreLedgerWallet::new();
    // The first account's spending key lives on a device.
    let device = w.imported(4, false);
    let later = w.derived(5);
    w.scanned();
    let b = w.birthday;
    let received = w.output(device, [0x51; 32], 45_000, Some(b + 1), false);
    let spent = w.output(device, [0x52; 32], 5_000, Some(b + 2), false);
    let spending = w.transaction([0x53; 32], Some(b + 8), false);
    w.spend(&spent, spending);
    let events = BTreeMap::from([(
        device,
        (
            vec![
                w.receive(device, &received, 45_000, b + 1, false),
                w.receive(device, &spent, 5_000, b + 2, false),
            ],
            vec![SpendEvent {
                metadata: None,
                spending_txid: TxId::from_bytes([0x53; 32]),
                input_index: 0,
                prevout: spent.clone(),
                prevout_address: w.external(device),
                mined_height: b + 8,
            }],
        ),
    )]);
    let upgraded = w.upgrade_and_activate(events);
    assert_eq!(upgraded.spendable(device), Zatoshis::const_from_u64(45_000));
    assert_eq!(upgraded.spendable(later), Zatoshis::ZERO);
}
