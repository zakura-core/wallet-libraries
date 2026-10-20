//! Real wallet databases sharing only an independent chain and public directory.
use super::{
    chain::{ACTIVATION, Chain, GENESIS, network},
    directory::{Directory, ORIGIN},
};
use orchard::keys::FullViewingKey;
use receiver_pir::{AcceptedCoverage, transport::DirectoryClient};
use rusqlite::Connection;
use sapling::prover::mock::{MockOutputProver, MockSpendProver};
use secrecy::SecretVec;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use zakura_one_time_ivk::{KeyId, Purpose};
use zakura_pir_receiver::{DirectoryError, lookup, publication, witness};
use zcash_client_backend::{
    data_api::{
        AccountBirthday, TransactionStatus, WalletCommitmentTrees, WalletRead as _,
        WalletWrite as _,
        chain::scan_cached_blocks,
        enhance_pir::{EnhancePirRead as _, EnhancementMode, TransactionEnhancementWork},
        one_time_ivk::restore::RecoveryStatus,
        scanning::ScanPriority,
        status::{TransactionStatusMode, TransactionStatusRead as _},
        testing::TestRng,
        transparent_ledger::TransparentLedgerMode,
        wallet::{
            ConfirmationsPolicy, SpendingKeys, create_proposed_transactions,
            decrypt_and_store_transaction,
            input_selection::{GreedyInputSelector, NoteSelection, SpendPolicy},
            propose_transfer,
        },
    },
    fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{
    AccountUuid, WalletDb,
    util::testing::FixedClock,
    wallet::{init::init_wallet_db, one_time_ivk::swap::verify_refund_funding_proposal},
};
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    ShieldedPool, consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
};

type Wallet = WalletDb<Connection, LocalNetwork, FixedClock, TestRng>;

/// A locally recorded refund operation, before funding.
pub struct RefundSwap {
    pub index: u64,
    pub deposit: String,
}

/// A persistent wallet handle. No key or cursor state is shared between devices.
pub struct Device {
    pub db: Wallet,
    pub account: AccountUuid,
    pub fvk: FullViewingKey,
    usk: UnifiedSpendingKey,
    path: PathBuf,
    _file: NamedTempFile,
    clock: FixedClock,
}

impl Device {
    /// Creates an ordinary wallet account at an explicit birthday and enables private recovery.
    pub fn new(chain: &mut Chain, seed: [u8; 32], birthday: BlockHeight) -> Self {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        let clock = chain.clock(0);
        let mut db = open(&path, &clock);
        init_wallet_db(&mut db, Some(SecretVec::new(seed.to_vec()))).unwrap();
        let birthday = AccountBirthday::from_parts(chain.state_below(birthday), None);
        let (account, usk) = db
            .create_account("scenario", &SecretVec::new(seed.to_vec()), &birthday, None)
            .unwrap();
        db.set_one_time_recovery_enabled(account, true).unwrap();
        Self {
            db,
            account,
            fvk: FullViewingKey::from(usk.orchard()),
            usk,
            path,
            _file: file,
            clock,
        }
    }

    /// Opens a read-only inspection connection to this wallet's persisted data.
    pub fn conn(&self) -> Connection {
        Connection::open_with_flags(&self.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    }

    /// Drops all in-memory wallet state while keeping the database and clock.
    pub fn reopen(&mut self) {
        self.db = open(&self.path, &self.clock);
    }

    /// Derives an oracle receiver without registering it in the wallet.
    pub fn key(&self, purpose: Purpose, index: u64) -> FullViewingKey {
        KeyId::new(purpose, index).derive(&self.fvk).unwrap()
    }

    /// Completes ordinary scanning without consulting filters or PIR.
    pub fn scan(&mut self, chain: &Chain) {
        self.db.update_chain_tip(chain.tip()).unwrap();
        for _ in 0..256 {
            let next = self
                .db
                .suggest_scan_ranges()
                .unwrap()
                .into_iter()
                .find(|r| r.priority() > ScanPriority::Scanned);
            let Some(range) = next else {
                self.enhance(chain);
                return;
            };
            let start = range.block_range().start;
            let limit = (range.block_range().end - start).min(1000) as usize;
            scan_cached_blocks(
                &network(),
                chain.block_source(),
                &mut self.db,
                start,
                &chain.state_below(start),
                limit,
            )
            .unwrap();
        }
        panic!("ordinary scan did not converge");
    }

    /// Reads the durable queue without initiating network traffic.
    pub fn status(&self, chain: &Chain) -> RecoveryStatus {
        self.db
            .one_time_recovery(self.account, chain.now())
            .unwrap()
    }

    /// Asserts the no-stall invariant that the wallet's own restore fixtures also check:
    /// recovery is complete, exposes a lookup or witness, or waits only on time (a backoff,
    /// made due here by a far-future clock), a publication or ordinary sync, or the user
    /// (feature or manual search paused, which leaves a cancelled search's lookups without
    /// a reason).
    pub fn assert_no_stall(&self) {
        let state = self.db.one_time_recovery(self.account, i64::MAX).unwrap();
        if !state.enabled || !state.lookups.is_empty() || !state.witnesses.is_empty() {
            return;
        }
        let (unstarted, syncing, hidden): (bool, bool, bool) = self
            .conn()
            .query_row(
                "SELECT r.restore_height IS NULL,
                    EXISTS(SELECT 1 FROM ironwood_one_time_payment_recovery p
                        JOIN ironwood_one_time_keys k ON k.id = p.one_time_key_id
                        WHERE k.account_id = r.account_id AND p.witness IS NOT NULL),
                    EXISTS(SELECT 1 FROM ironwood_one_time_lookups l
                        JOIN ironwood_one_time_keys k ON k.id = l.one_time_key_id
                        WHERE k.account_id = r.account_id
                          AND l.target_height IS NOT NULL AND l.read_complete = 0 AND l.reasons != 0)
                 FROM ironwood_one_time_recovery r JOIN accounts a ON a.id = r.account_id
                 WHERE a.uuid = ?1",
                [self.account.expose_uuid()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let manual = state.manual.is_some_and(|m| m.active);
        let complete = state.restore_complete && !manual && !hidden;
        assert!(
            complete || syncing || (unstarted && !manual && !hidden),
            "recovery stalled with no runnable work: restore_next {}, restore_gap {}, \
             manual {:?}, hidden lookups {hidden}",
            state.restore_next,
            state.restore_gap,
            state.manual,
        );
    }

    /// Opens an exact publication checked against this wallet's already scanned chain.
    pub async fn connect<'a>(&self, directory: &'a Directory) -> DirectoryClient<&'a Directory> {
        let manifest = DirectoryClient::fetch_manifest(ORIGIN, &directory)
            .await
            .unwrap();
        let end = manifest.payments.directory.end_height.into();
        let hash = self.db.get_block_hash(end).unwrap().unwrap();
        DirectoryClient::connect_manifest(
            ORIGIN,
            directory,
            AcceptedCoverage {
                genesis: GENESIS,
                required_start: ACTIVATION,
                height: end.into(),
                hash: hash.0,
            },
            manifest,
        )
        .await
        .unwrap()
    }

    /// Completes the real encrypted lookup and witness pipeline, preserving database
    /// boundaries. A witness bound to another session is read again under this one.
    pub async fn drain(&mut self, chain: &Chain, client: &DirectoryClient<&Directory>) {
        for _ in 0..256 {
            self.assert_no_stall();
            let state = self.status(chain);
            if let Some(work) = state.lookups.first() {
                let page = lookup(client, work).await.unwrap();
                assert!(
                    self.db
                        .record_one_time_lookup(self.account, work, &page, chain.now())
                        .unwrap()
                );
            } else if let Some(request) = state.witnesses.first() {
                match witness(client, request).await {
                    Ok(answer) => assert!(
                        self.db
                            .record_one_time_witness(
                                self.account,
                                state.token,
                                *request,
                                &answer,
                                chain.now()
                            )
                            .unwrap()
                    ),
                    Err(DirectoryError::Revision) => assert!(
                        self.db
                            .refresh_one_time_witness(self.account, state.token, *request)
                            .unwrap()
                    ),
                    Err(e) => panic!("witness query failed: {e}"),
                }
            } else {
                return;
            }
        }
        panic!("private recovery did not converge");
    }

    /// Captures direct catch-up obligations and runs them against one compatible session.
    pub async fn recover(&mut self, chain: &Chain, directory: &Directory) {
        let client = self.connect(directory).await;
        let publication = publication(client.publication()).unwrap();
        assert!(
            self.db
                .begin_one_time_recovery(self.account, publication, true)
                .unwrap()
        );
        self.drain(chain, &client).await;
    }

    /// Records a canonical transparent refund operation with no global provider feed.
    pub fn quote_refund(&mut self, chain: &Chain) -> RefundSwap {
        let key = self
            .db
            .reserve_refund_key(self.account, chain.tip())
            .unwrap()
            .unwrap();
        let deposit = Address::Transparent(
            transparent::address::TransparentAddress::PublicKeyHash([23; 20]),
        )
        .encode(&network());
        let index = key.key_id().index();
        self.db
            .record_refund_operation(
                self.account,
                index,
                &deposit,
                chain.now() + 3600,
                chain.now(),
            )
            .unwrap();
        RefundSwap { index, deposit }
    }

    /// Serves ordinary status and full transaction requests using the independent chain.
    fn enhance(&mut self, chain: &Chain) {
        let status_work = self.db.transaction_status_work().expect("status work");
        for item in status_work {
            let txid = item.txid();
            self.db
                .set_transaction_status(txid, chain.status(&txid))
                .expect("the status records");
        }
        for _ in 0..4 {
            let work = self
                .db
                .transaction_enhancement_work()
                .expect("enhancement work");
            let mut served = 0;
            for item in work {
                let TransactionEnhancementWork::Public(request) = item else {
                    continue;
                };
                let Some((tx, height)) = chain.transaction(&request.txid()) else {
                    // GetTransaction's NotFound for a transaction a reorg removed. A fake
                    // output still on the chain has no raw form to serve, so it waits.
                    if let TransactionStatus::TxidNotRecognized = chain.status(&request.txid()) {
                        self.db
                            .set_transaction_status(
                                request.txid(),
                                TransactionStatus::TxidNotRecognized,
                            )
                            .expect("the status records");
                    }
                    continue;
                };
                decrypt_and_store_transaction(&network(), &mut self.db, &tx, Some(height))
                    .expect("the transaction decrypts and stores");
                served += 1;
            }
            if served == 0 {
                break;
            }
        }
    }

    /// Builds a real funding transaction carrying the authenticated refund-index memo.
    pub fn fund_refund(&mut self, swap: &RefundSwap, amount: u64) -> Transaction {
        let memo = self
            .db
            .refund_funding_memo(self.account, swap.index, &swap.deposit)
            .expect("the refund memo");
        let to = Address::decode(&network(), &swap.deposit)
            .expect("the deposit address decodes")
            .to_zcash_address(&network());
        let payment = zip321::Payment::new(
            to,
            Some(Zatoshis::const_from_u64(amount)),
            None,
            None,
            None,
            vec![],
        )
        .expect("a payment");
        let request = zip321::TransactionRequest::new(vec![payment]).expect("a request");
        let strategy = SingleOutputChangeStrategy::<Wallet>::new(
            StandardFeeRule::Zip317,
            Some(memo.clone()),
            ShieldedPool::Ironwood,
            DustOutputPolicy::default(),
        );
        let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
            .with_note_selection(NoteSelection::PreferConsolidation);
        let proposal = propose_transfer::<_, _, _, _, <Wallet as WalletCommitmentTrees>::Error>(
            &mut self.db,
            &network(),
            self.account,
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
            None,
            None,
        )
        .expect("the funding proposal");
        verify_refund_funding_proposal(&proposal, &memo, &swap.deposit)
            .expect("the funding proposal carries the refund memo");
        let txids = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            &mut self.db,
            &network(),
            &MockSpendProver,
            &MockOutputProver,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .expect("the funding transaction builds");
        self.db
            .get_transaction(*txids.first())
            .expect("the stored transaction")
            .expect("the wallet stored its transaction")
    }

    /// Builds a real spend with the wallet's retained one-time-note ownership keys.
    pub fn send_to(&mut self, to: orchard::Address, value: u64, ovk: OvkPolicy) -> Transaction {
        let to = Address::Unified(
            zcash_keys::address::UnifiedAddress::from_receivers(Some(to), None, None)
                .expect("a unified address"),
        )
        .to_zcash_address(&network());
        let payment = zip321::Payment::new(
            to,
            Some(Zatoshis::const_from_u64(value)),
            None,
            None,
            None,
            vec![],
        )
        .expect("a payment");
        let request = zip321::TransactionRequest::new(vec![payment]).expect("a request");
        let strategy = SingleOutputChangeStrategy::<Wallet>::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Ironwood,
            DustOutputPolicy::default(),
        );
        let policy = SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
            .with_note_selection(NoteSelection::PreferConsolidation);
        let proposal = propose_transfer::<_, _, _, _, <Wallet as WalletCommitmentTrees>::Error>(
            &mut self.db,
            &network(),
            self.account,
            &GreedyInputSelector::new(),
            &strategy,
            request,
            ConfirmationsPolicy::MIN,
            &policy,
            None,
            None,
        )
        .expect("the payment proposal");
        let txids = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            &mut self.db,
            &network(),
            &MockSpendProver,
            &MockOutputProver,
            &SpendingKeys::from_unified_spending_key(self.usk.clone()),
            ovk,
            &proposal,
            None,
        )
        .expect("the payment builds");
        self.db
            .get_transaction(*txids.first())
            .expect("the stored transaction")
            .expect("the wallet stored its transaction")
    }

    /// Returns mined unspent private receiver value from persisted accounting.
    pub fn unspent_one_time_value(&self) -> u64 {
        let conn = self.conn();
        conn.query_row(
            "SELECT COALESCE(SUM(n.value), 0) FROM ironwood_received_notes n
             JOIN transactions r ON r.id_tx = n.transaction_id
             WHERE n.one_time_key_id IS NOT NULL AND r.mined_height IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM ironwood_received_note_spends s
                               JOIN transactions t ON t.id_tx = s.transaction_id
                               WHERE s.ironwood_received_note_id = n.id
                                 AND (t.mined_height IS NOT NULL
                                      OR t.expiry_height = 0
                                      OR t.expiry_height > (SELECT MAX(height) FROM blocks)))",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| u64::try_from(v).unwrap_or(0))
        .expect("one-time value")
    }
}

/// Opens the ordinary wallet transport modes used by this isolated simulator.
fn open(path: &std::path::Path, clock: &FixedClock) -> Wallet {
    let mut db =
        WalletDb::for_path(path, network(), clock.clone(), TestRng::seed_from_u64(7)).unwrap();
    db.set_enhancement_mode(EnhancementMode::Standard);
    db.set_transparent_ledger_mode(TransparentLedgerMode::Public);
    db.set_status_mode(TransactionStatusMode::Public);
    db
}
