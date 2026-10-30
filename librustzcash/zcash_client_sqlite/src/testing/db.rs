//! An in-memory [`WalletDb`]-backed data store and [`DataStoreFactory`] for the
//! `zcash_client_backend` testing framework.

use rusqlite::Connection;
use std::num::NonZeroU32;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    time::SystemTime,
};
use uuid::Uuid;

use tempfile::NamedTempFile;

use rusqlite::{self};
use secrecy::SecretVec;
use shardtree::{ShardTree, error::ShardTreeError};

use zcash_client_backend::{
    data_api::{
        TargetValue,
        anchor_retention::AnchorRetentionInterval,
        chain::{ChainState, CommitmentTreeRoot},
        enhance_pir::{
            EnhancePirRead, EnhancePirSnapshotAnchor, EnhancePirSnapshotStatus,
            TransactionEnhancementWork,
        },
        error::{LockError, RewindError},
        scanning::{ScanPriority, ScanRange},
        status::{TransactionStatusMode, TransactionStatusRead, TransactionStatusWork},
        testing::{DataStoreFactory, Reset, TestRng, TestState},
        wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
        *,
    },
    wallet::{LockOwner, Note, NoteId, OutputRef, ReceivedNote, WalletTransparentOutput},
};
use zcash_keys::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
    ShieldedPool, consensus, consensus::BlockHeight, local_consensus::LocalNetwork, memo::Memo,
    value::Zatoshis,
};
use zip32::DiversifierIndex;

use crate::{
    AccountUuid, WalletDb, error::SqliteClientError, util::testing::FixedClock,
    wallet::init::WalletMigrator,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::TransparentAddressMetadata,
    ::transparent::{address::TransparentAddress, bundle::OutPoint, keys::NonHardenedChildIndex},
    core::ops::Range,
    zcash_client_backend::fees::StandardFeeRule,
    zcash_keys::keys::transparent::gap_limits::GapLimits,
};

/// Tuesday, 25 February 2025 00:00:00Z (the day the clock code was added).
const TEST_EPOCH_SECONDS_OFFSET: Duration = Duration::from_secs(1740441600);

pub(crate) fn test_clock() -> FixedClock {
    FixedClock::new(SystemTime::UNIX_EPOCH + TEST_EPOCH_SECONDS_OFFSET)
}

pub(crate) fn test_rng() -> TestRng {
    TestRng::seed_from_u64(0)
}

/// A [`WalletDb`] wrapped as a testing-framework data store: it delegates the wallet traits to the
/// inner database and owns the temporary file backing it.
pub struct TestDb {
    wallet_db: InnerDb,
    data_file: Option<NamedTempFile>,
}

impl TestDb {
    fn from_parts(
        wallet_db: WalletDb<Connection, LocalNetwork, FixedClock, TestRng>,
        data_file: Option<NamedTempFile>,
    ) -> Self {
        Self {
            wallet_db: wallet_db
                .with_status_mode(TransactionStatusMode::Public)
                .with_transparent_ledger_mode(
                zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode::Public,
            ),
            data_file,
        }
    }

    /// The wrapped wallet database.
    pub fn db(&self) -> &WalletDb<Connection, LocalNetwork, FixedClock, TestRng> {
        &self.wallet_db
    }

    /// The wrapped wallet database, mutably.
    pub fn db_mut(&mut self) -> &mut WalletDb<Connection, LocalNetwork, FixedClock, TestRng> {
        &mut self.wallet_db
    }

    /// Runs a fixture operation against the transaction-bound wallet, committing on
    /// success and rolling back on error just like the public wallet operations.
    #[cfg(all(test, feature = "transparent-inputs"))]
    pub(crate) fn with_wallet_transaction<T>(
        &mut self,
        operation: impl FnOnce(
            &mut WalletDb<crate::SqlTransaction<'_>, &LocalNetwork, &FixedClock, &mut TestRng>,
        ) -> Result<T, crate::error::SqliteClientError>,
    ) -> Result<T, crate::error::SqliteClientError> {
        self.wallet_db.transactionally(operation)
    }

    /// Injects a reader compatibility requirement without debugger manipulation.
    #[cfg(all(test, feature = "transparent-inputs"))]
    pub(crate) fn set_transparent_reader_version(&self, version: i64) {
        assert_eq!(
            self.conn()
                .execute(
                    "UPDATE tpir_meta SET min_reader_version = ?1 WHERE id = 0",
                    [version]
                )
                .unwrap(),
            1,
        );
    }

    /// The wallet database's own SQLite connection.
    pub fn conn(&self) -> &Connection {
        &self.wallet_db.conn
    }

    /// The wallet database's own SQLite connection, mutably. See [`Self::conn`].
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.wallet_db.conn
    }

    pub(crate) fn take_data_file(self) -> Option<NamedTempFile> {
        self.data_file
    }

    #[allow(dead_code)]
    pub(crate) fn data_file_path(&self) -> &std::path::Path {
        self.data_file
            .as_ref()
            .expect("this test requires a file-backed TestDbFactory")
            .path()
    }

    /// Dump the schema and contents of the given database table, in
    /// sqlite3 ".dump" format. The name of the table must be a static
    /// string. This assumes that `sqlite3` is on your path and that it
    /// invokes a compatible version of sqlite3.
    ///
    /// # Panics
    ///
    /// Panics if `name` contains characters outside `[a-zA-Z_]`.
    #[allow(dead_code)]
    #[cfg(feature = "unstable")]
    pub(crate) fn dump_table(&self, name: &'static str) {
        assert!(name.chars().all(|c| c.is_ascii_alphabetic() || c == '_'));
        unsafe {
            run_sqlite3(self.data_file_path(), &format!(r#".dump "{name}""#));
        }
    }

    /// Print the results of an arbitrary sqlite3 command (with "-safe"
    /// and "-readonly" flags) to stderr. This is completely insecure and
    /// should not be exposed in production. Use of the "-safe" and
    /// "-readonly" flags is intended only to limit *accidental* misuse.
    /// The output is unfiltered, and control codes could mess up your
    /// terminal. This assumes that `sqlite3` is on your path and that it
    /// invokes a compatible version of sqlite3.
    #[allow(dead_code)]
    #[cfg(feature = "unstable")]
    pub(crate) unsafe fn run_sqlite3(&self, command: &str) {
        unsafe { run_sqlite3(self.data_file_path(), command) }
    }
}

#[cfg(feature = "unstable")]
use std::{ffi::OsStr, process::Command};

// See the doc comment for `TestState::run_sqlite3` above.
//
// - `db_path` is the path to the database file.
// - `command` may contain newlines.
#[allow(dead_code)]
#[cfg(feature = "unstable")]
unsafe fn run_sqlite3<S: AsRef<OsStr>>(db_path: S, command: &str) {
    let output = Command::new("sqlite3")
        .arg(db_path)
        .arg("-safe")
        .arg("-readonly")
        .arg(command)
        .output()
        .expect("failed to execute sqlite3 process");

    eprintln!(
        "{}\n------\n{}",
        command,
        String::from_utf8_lossy(&output.stdout)
    );
    if !output.stderr.is_empty() {
        eprintln!(
            "------ stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    eprintln!("------");
}

type InnerDb = WalletDb<Connection, LocalNetwork, FixedClock, TestRng>;

// The wallet traits are forwarded method by method, including those with default bodies, so that
// `TestDb` always behaves exactly like the wrapped `WalletDb` rather than the trait defaults.

impl InputSource for TestDb {
    type Error = <InnerDb as InputSource>::Error;
    type AccountId = <InnerDb as InputSource>::AccountId;
    type NoteRef = <InnerDb as InputSource>::NoteRef;

    fn anchor_retention_interval(&self) -> anchor_retention::AnchorRetentionInterval {
        self.wallet_db.anchor_retention_interval()
    }

    fn get_spendable_note(
        &self,
        txid: &TxId,
        protocol: ShieldedPool,
        index: u32,
        target_height: TargetHeight,
        lock_filter: LockFilter<'_>,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        self.wallet_db
            .get_spendable_note(txid, protocol, index, target_height, lock_filter)
    }

    #[allow(clippy::too_many_arguments)]
    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        self.wallet_db.select_spendable_notes(
            account,
            target_value,
            sources,
            target_height,
            confirmations_policy,
            exclude,
            lock_filter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn select_spendable_notes_for_consolidation(
        &self,
        account: Self::AccountId,
        value: Zatoshis,
        source: ShieldedPool,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
        max_additional_notes: usize,
    ) -> Result<ConsolidationNotes<Self::NoteRef>, Self::Error> {
        self.wallet_db.select_spendable_notes_for_consolidation(
            account,
            value,
            source,
            target_height,
            confirmations_policy,
            exclude,
            lock_filter,
            max_additional_notes,
        )
    }

    fn select_unspent_notes(
        &self,
        account: Self::AccountId,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        self.wallet_db
            .select_unspent_notes(account, sources, target_height, exclude, lock_filter)
    }

    fn get_account_metadata(
        &self,
        account: Self::AccountId,
        selector: &NoteFilter,
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<AccountMeta, Self::Error> {
        self.wallet_db
            .get_account_metadata(account, selector, target_height, exclude, lock_filter)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
    ) -> Result<Option<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.wallet_db
            .get_unspent_transparent_output(outpoint, target_height)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_spendable_transparent_outputs(
        &self,
        address: &TransparentAddress,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.wallet_db.get_spendable_transparent_outputs(
            address,
            target_height,
            confirmations_policy,
            output_filter,
            lock_filter,
        )
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_spendable_transparent_outputs_for_addresses(
        &self,
        addresses: &[TransparentAddress],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.wallet_db
            .get_spendable_transparent_outputs_for_addresses(
                addresses,
                target_height,
                confirmations_policy,
                output_filter,
                lock_filter,
            )
    }

    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::too_many_arguments)]
    fn select_spendable_transparent_outputs(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        address_allow_list: Option<&[TransparentAddress]>,
        target_value: TargetValue,
        max_inputs: usize,
        fee_rule: &StandardFeeRule,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.wallet_db.select_spendable_transparent_outputs(
            account,
            target_height,
            confirmations_policy,
            output_filter,
            address_allow_list,
            target_value,
            max_inputs,
            fee_rule,
            lock_filter,
        )
    }
}

impl WalletRead for TestDb {
    type Error = <InnerDb as WalletRead>::Error;
    type AccountId = <InnerDb as WalletRead>::AccountId;
    type Account = <InnerDb as WalletRead>::Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        self.wallet_db.get_account_ids()
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.wallet_db.get_account(account_id)
    }

    fn get_derived_account(
        &self,
        derivation: &Zip32Derivation,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.wallet_db.get_derived_account(derivation)
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        self.wallet_db.validate_seed(account_id, seed)
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        self.wallet_db.seed_relevance_to_derived_accounts(seed)
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.wallet_db.get_account_for_ufvk(ufvk)
    }

    fn list_addresses(&self, account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        self.wallet_db.list_addresses(account)
    }

    fn find_account_for_address<P: consensus::Parameters>(
        &self,
        params: &P,
        address: &zcash_keys::address::Address,
    ) -> Result<Option<Self::AccountId>, error::FindAccountForAddressError<Self::Error>> {
        self.wallet_db.find_account_for_address(params, address)
    }

    fn get_last_generated_address_matching(
        &self,
        account: Self::AccountId,
        address_filter: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.wallet_db
            .get_last_generated_address_matching(account, address_filter)
    }

    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.wallet_db.get_account_birthday(account)
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.wallet_db.get_wallet_birthday()
    }

    fn get_wallet_recover_until(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.wallet_db.get_wallet_recover_until()
    }

    fn get_wallet_summary(
        &self,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        self.wallet_db.get_wallet_summary(confirmations_policy)
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.wallet_db.chain_height()
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        self.wallet_db.get_block_hash(block_height)
    }

    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        self.wallet_db.block_metadata(height)
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        self.wallet_db.block_fully_scanned()
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        self.wallet_db.get_max_height_hash()
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        self.wallet_db.block_max_scanned()
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        self.wallet_db.suggest_scan_ranges()
    }

    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> {
        self.wallet_db
            .get_target_and_anchor_heights(min_confirmations)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        self.wallet_db.get_tx_height(txid)
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        self.wallet_db.get_unified_full_viewing_keys()
    }

    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error> {
        self.wallet_db.get_memo(note_id)
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        self.wallet_db.get_transaction(txid)
    }

    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        self.wallet_db.get_sapling_nullifiers(query)
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        self.wallet_db.get_orchard_nullifiers(query)
    }

    #[cfg(feature = "orchard")]
    fn get_ironwood_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        self.wallet_db.get_ironwood_nullifiers(query)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        account: Self::AccountId,
        include_change: bool,
        include_standalone: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.wallet_db
            .get_transparent_receivers(account, include_change, include_standalone)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_ephemeral_transparent_receivers(
        &self,
        account: Self::AccountId,
        exposure_depth: u32,
        exclude_used: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.wallet_db
            .get_ephemeral_transparent_receivers(account, exposure_depth, exclude_used)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<TransparentBalances, Self::Error> {
        self.wallet_db
            .get_transparent_balances(account, target_height, confirmations_policy)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_address_metadata(
        &self,
        account: Self::AccountId,
        address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        self.wallet_db
            .get_transparent_address_metadata(account, address)
    }

    #[cfg(feature = "transparent-inputs")]
    fn utxo_query_height(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.wallet_db.utxo_query_height(account)
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        self.wallet_db.transaction_data_requests()
    }

    fn get_received_outputs(
        &self,
        txid: TxId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> {
        self.wallet_db
            .get_received_outputs(txid, target_height, confirmations_policy)
    }
}

impl WalletTest for TestDb {
    fn get_tx_history(
        &self,
    ) -> Result<
        Vec<testing::TransactionSummary<<Self as WalletRead>::AccountId>>,
        <Self as WalletRead>::Error,
    > {
        self.wallet_db.get_tx_history()
    }

    fn get_sent_note_ids(
        &self,
        txid: &TxId,
        protocol: ShieldedPool,
    ) -> Result<Vec<NoteId>, <Self as WalletRead>::Error> {
        self.wallet_db.get_sent_note_ids(txid, protocol)
    }

    #[allow(clippy::type_complexity)]
    fn get_sent_outputs(
        &self,
        txid: &TxId,
    ) -> Result<Vec<OutputOfSentTx>, <Self as WalletRead>::Error> {
        self.wallet_db.get_sent_outputs(txid)
    }

    #[allow(clippy::type_complexity)]
    fn get_checkpoint_history(
        &self,
        protocol: &ShieldedPool,
    ) -> Result<
        Vec<(BlockHeight, Option<incrementalmerkletree::Position>)>,
        <Self as WalletRead>::Error,
    > {
        self.wallet_db.get_checkpoint_history(protocol)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_output(
        &self,
        outpoint: &OutPoint,
        spendable_as_of: Option<TargetHeight>,
    ) -> Result<
        Option<WalletTransparentOutput<<Self as WalletRead>::AccountId>>,
        <Self as InputSource>::Error,
    > {
        self.wallet_db
            .get_transparent_output(outpoint, spendable_as_of)
    }

    fn get_notes(
        &self,
        protocol: ShieldedPool,
    ) -> Result<Vec<ReceivedNote<Self::NoteRef, Note>>, <Self as InputSource>::Error> {
        self.wallet_db.get_notes(protocol)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_known_ephemeral_addresses(
        &self,
        account: <Self as WalletRead>::AccountId,
        index_range: Option<Range<NonHardenedChildIndex>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, <Self as WalletRead>::Error>
    {
        self.wallet_db
            .get_known_ephemeral_addresses(account, index_range)
    }

    #[cfg(feature = "transparent-inputs")]
    fn find_account_for_ephemeral_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<<Self as WalletRead>::AccountId>, <Self as WalletRead>::Error> {
        self.wallet_db.find_account_for_ephemeral_address(address)
    }

    fn finally(&self) {
        self.wallet_db.finally()
    }
}

impl OutputLockStore for TestDb {
    type Error = <InnerDb as OutputLockStore>::Error;
    type AccountId = <InnerDb as OutputLockStore>::AccountId;

    fn lock_outputs(
        &mut self,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<usize, LockError<Self::Error>> {
        self.wallet_db
            .lock_outputs(outputs, owner, lock_expiry_height)
    }

    fn unlock_output(&mut self, output: &OutputRef, owner: LockOwner) -> Result<bool, Self::Error> {
        self.wallet_db.unlock_output(output, owner)
    }

    fn clear_locked_outputs(&mut self, account: Self::AccountId) -> Result<usize, Self::Error> {
        self.wallet_db.clear_locked_outputs(account)
    }

    fn get_locked_outputs(&self, account: Self::AccountId) -> Result<Vec<OutputRef>, Self::Error> {
        self.wallet_db.get_locked_outputs(account)
    }
}

impl WalletWrite for TestDb {
    type UtxoRef = <InnerDb as WalletWrite>::UtxoRef;

    fn create_account(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(<Self as WalletRead>::AccountId, UnifiedSpendingKey), <Self as WalletRead>::Error>
    {
        self.wallet_db
            .create_account(account_name, seed, birthday, key_source)
    }

    fn import_account_hd(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), <Self as WalletRead>::Error> {
        self.wallet_db
            .import_account_hd(account_name, seed, account_index, birthday, key_source)
    }

    fn import_account_ufvk(
        &mut self,
        account_name: &str,
        unified_key: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: AccountPurpose,
        key_source: Option<&str>,
    ) -> Result<Self::Account, <Self as WalletRead>::Error> {
        self.wallet_db
            .import_account_ufvk(account_name, unified_key, birthday, purpose, key_source)
    }

    fn delete_account(
        &mut self,
        account: <Self as WalletRead>::AccountId,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.delete_account(account)
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_pubkey(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        pubkey: secp256k1::PublicKey,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db
            .import_standalone_transparent_pubkey(account, pubkey)
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_pubkeys(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        pubkeys: &[secp256k1::PublicKey],
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db
            .import_standalone_transparent_pubkeys(account, pubkeys)
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_script(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        script: zcash_script::script::Redeem,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db
            .import_standalone_transparent_script(account, script)
    }

    fn get_next_available_address(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, <Self as WalletRead>::Error> {
        self.wallet_db.get_next_available_address(account, request)
    }

    fn get_address_for_index(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        diversifier_index: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, <Self as WalletRead>::Error> {
        self.wallet_db
            .get_address_for_index(account, diversifier_index, request)
    }

    fn get_addresses_for_index_range(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        range: core::ops::Range<DiversifierIndex>,
        request: UnifiedAddressRequest,
    ) -> Result<Vec<(DiversifierIndex, UnifiedAddress)>, <Self as WalletRead>::Error> {
        self.wallet_db
            .get_addresses_for_index_range(account, range, request)
    }

    fn update_chain_tip(
        &mut self,
        tip_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.update_chain_tip(tip_height)
    }

    fn prune_scan_queue_below(
        &mut self,
        height: BlockHeight,
        retain_with_priority: Option<ScanPriority>,
    ) -> Result<u64, <Self as WalletRead>::Error> {
        self.wallet_db
            .prune_scan_queue_below(height, retain_with_priority)
    }

    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<<Self as WalletRead>::AccountId>>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.put_blocks(from_state, blocks)
    }

    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput<<Self as WalletRead>::AccountId>,
    ) -> Result<Self::UtxoRef, <Self as WalletRead>::Error> {
        self.wallet_db.put_received_transparent_utxo(output)
    }

    fn store_decrypted_tx(
        &mut self,
        received_tx: DecryptedTransaction<Transaction, <Self as WalletRead>::AccountId>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.store_decrypted_tx(received_tx)
    }

    fn set_tx_trust(
        &mut self,
        txid: TxId,
        trusted: bool,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.set_tx_trust(txid, trusted)
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<<Self as WalletRead>::AccountId>],
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.store_transactions_to_be_sent(transactions)
    }

    fn truncate_to_height(
        &mut self,
        max_height: BlockHeight,
    ) -> Result<BlockHeight, <Self as WalletRead>::Error> {
        self.wallet_db.truncate_to_height(max_height)
    }

    fn truncate_to_chain_state(
        &mut self,
        chain_state: ChainState,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.truncate_to_chain_state(chain_state)
    }

    fn rewind_to_chain_state(
        &mut self,
        chain_state: ChainState,
        reset_account_birthdays: HashSet<<Self as WalletRead>::AccountId>,
    ) -> Result<(), RewindError<<Self as WalletRead>::AccountId, <Self as WalletRead>::Error>> {
        self.wallet_db
            .rewind_to_chain_state(chain_state, reset_account_birthdays)
    }

    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        account_id: <Self as WalletRead>::AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, <Self as WalletRead>::Error>
    {
        self.wallet_db
            .reserve_next_n_ephemeral_addresses(account_id, n)
    }

    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_internal_addresses(
        &mut self,
        account_id: <Self as WalletRead>::AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, <Self as WalletRead>::Error>
    {
        self.wallet_db
            .reserve_next_n_internal_addresses(account_id, n)
    }

    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: TransactionStatus,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.set_transaction_status(txid, status)
    }

    fn notify_transaction_enhancement_not_found(
        &mut self,
        txid: TxId,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db
            .notify_transaction_enhancement_not_found(txid)
    }

    #[cfg(feature = "transparent-inputs")]
    fn schedule_next_check(
        &mut self,
        address: &TransparentAddress,
        offset_seconds: u32,
    ) -> Result<Option<SystemTime>, <Self as WalletRead>::Error> {
        self.wallet_db.schedule_next_check(address, offset_seconds)
    }

    #[cfg(feature = "transparent-inputs")]
    fn mark_transparent_addresses_exposed(
        &mut self,
        exposures: &[(TransparentAddress, BlockHeight)],
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.mark_transparent_addresses_exposed(exposures)
    }

    #[cfg(feature = "transparent-inputs")]
    fn notify_address_checked(
        &mut self,
        request: TransactionsInvolvingAddress,
        as_of_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db.notify_address_checked(request, as_of_height)
    }

    #[cfg(feature = "spend-index")]
    fn notify_output_verified_unspent(
        &mut self,
        outpoint: OutPoint,
        as_of_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.wallet_db
            .notify_output_verified_unspent(outpoint, as_of_height)
    }
}

impl WalletCommitmentTrees for TestDb {
    type Error = <InnerDb as WalletCommitmentTrees>::Error;
    type SaplingShardStore<'a> = <InnerDb as WalletCommitmentTrees>::SaplingShardStore<'a>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        self.wallet_db.with_sapling_tree_mut(callback)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.wallet_db.put_sapling_subtree_roots(start_index, roots)
    }

    fn get_sapling_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<sapling::Node>, ShardTreeError<Self::Error>> {
        self.wallet_db.get_sapling_subtree_root(index)
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = <InnerDb as WalletCommitmentTrees>::OrchardShardStore<'a>;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        self.wallet_db.with_orchard_tree_mut(callback)
    }

    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.wallet_db.put_orchard_subtree_roots(start_index, roots)
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        self.wallet_db.get_orchard_subtree_root(index)
    }

    #[cfg(feature = "orchard")]
    fn with_ironwood_tree_mut<F, A, E>(&mut self, callback: F) -> Result<Option<A>, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        self.wallet_db.with_ironwood_tree_mut(callback)
    }

    #[cfg(feature = "orchard")]
    fn put_ironwood_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.wallet_db
            .put_ironwood_subtree_roots(start_index, roots)
    }

    #[cfg(feature = "orchard")]
    fn get_ironwood_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        self.wallet_db.get_ironwood_subtree_root(index)
    }

    fn put_sapling_shards(
        &mut self,
        shards: &[shardtree::LocatedPrunableTree<sapling::Node>],
        cap: Option<&shardtree::PrunableTree<sapling::Node>>,
        checkpoints_remove: &[BlockHeight],
        checkpoints_add: &[(BlockHeight, shardtree::store::Checkpoint)],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.wallet_db
            .put_sapling_shards(shards, cap, checkpoints_remove, checkpoints_add)
    }

    #[cfg(feature = "orchard")]
    fn put_orchard_shards(
        &mut self,
        shards: &[shardtree::LocatedPrunableTree<orchard::tree::MerkleHashOrchard>],
        cap: Option<&shardtree::PrunableTree<orchard::tree::MerkleHashOrchard>>,
        checkpoints_remove: &[BlockHeight],
        checkpoints_add: &[(BlockHeight, shardtree::store::Checkpoint)],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.wallet_db
            .put_orchard_shards(shards, cap, checkpoints_remove, checkpoints_add)
    }

    #[cfg(feature = "orchard")]
    fn put_ironwood_shards(
        &mut self,
        shards: &[shardtree::LocatedPrunableTree<orchard::tree::MerkleHashOrchard>],
        cap: Option<&shardtree::PrunableTree<orchard::tree::MerkleHashOrchard>>,
        checkpoints_remove: &[BlockHeight],
        checkpoints_add: &[(BlockHeight, shardtree::store::Checkpoint)],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.wallet_db
            .put_ironwood_shards(shards, cap, checkpoints_remove, checkpoints_add)
    }

    fn remove_retained_checkpoints_below(
        &mut self,
        max_height: BlockHeight,
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.wallet_db.remove_retained_checkpoints_below(max_height)
    }
}

impl EnhancePirRead for TestDb {
    fn transaction_enhancement_work(&self) -> Result<Vec<TransactionEnhancementWork>, Self::Error> {
        self.wallet_db.transaction_enhancement_work()
    }

    fn enhance_pir_snapshot_status(
        &self,
        anchor: EnhancePirSnapshotAnchor,
    ) -> Result<EnhancePirSnapshotStatus, Self::Error> {
        self.wallet_db.enhance_pir_snapshot_status(anchor)
    }

    fn is_ironwood_enhancement_protected(&self, txid: TxId) -> Result<bool, Self::Error> {
        self.wallet_db.is_ironwood_enhancement_protected(txid)
    }
}

impl TransactionStatusRead for TestDb {
    fn transaction_status_work(&self) -> Result<Vec<TransactionStatusWork>, Self::Error> {
        self.wallet_db.transaction_status_work()
    }

    fn transaction_status_work_for(
        &self,
        txid: TxId,
    ) -> Result<TransactionStatusWork, Self::Error> {
        self.wallet_db.transaction_status_work_for(txid)
    }
}

/// A [`DataStoreFactory`] that builds fresh in-memory [`TestDb`] wallets, optionally migrated only
/// to a given set of migrations rather than all of them.
///
/// Tests that exercise reopening or multiple independent connections can opt into file-backed
/// storage with [`Self::file_backed`].
#[derive(Default)]
pub struct TestDbFactory {
    target_migrations: Option<Vec<Uuid>>,
    file_backed: bool,
}

impl TestDbFactory {
    /// Constructs a factory pinned to a historical wallet schema.
    #[cfg(all(test, feature = "orchard"))]
    pub(crate) fn at_migrations(migrations: &[Uuid]) -> Self {
        Self {
            target_migrations: Some(migrations.to_vec()),
            file_backed: false,
        }
    }

    /// Constructs a factory for tests that require a database file.
    pub fn file_backed() -> Self {
        Self {
            target_migrations: None,
            file_backed: true,
        }
    }
}

impl DataStoreFactory for TestDbFactory {
    type Error = ();
    type AccountId = AccountUuid;
    type Account = crate::wallet::Account;
    type DsError = SqliteClientError;
    type DataStore = TestDb;

    fn new_data_store(
        &self,
        network: LocalNetwork,
        anchor_retention_interval: Option<AnchorRetentionInterval>,
        #[cfg(feature = "transparent-inputs")] gap_limits: Option<GapLimits>,
    ) -> Result<Self::DataStore, Self::Error> {
        let (mut db_data, data_file) = if self.file_backed {
            let data_file = NamedTempFile::new().unwrap();
            let db_data =
                WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();
            (db_data, Some(data_file))
        } else {
            let conn = Connection::open_in_memory().unwrap();
            rusqlite::vtab::array::load_module(&conn).unwrap();
            (
                WalletDb::from_connection(conn, network, test_clock(), test_rng()),
                None,
            )
        };
        #[cfg(feature = "orchard")]
        db_data.set_enhancement_mode(
            zcash_client_backend::data_api::enhance_pir::EnhancementMode::Standard,
        );
        db_data.set_transparent_ledger_mode(
            zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode::Public,
        );
        if let Some(interval) = anchor_retention_interval {
            db_data = db_data.with_anchor_retention_interval(interval);
        }
        #[cfg(feature = "transparent-inputs")]
        if let Some(gap_limits) = gap_limits {
            db_data = db_data.with_gap_limits(gap_limits);
        }

        let migrator = WalletMigrator::new();
        if let Some(migrations) = &self.target_migrations {
            migrator
                .init_or_migrate_to(&mut db_data, migrations)
                .expect("wallet migration succeeds for test setup with target migrations");
        } else {
            migrator
                .init_or_migrate(&mut db_data)
                .expect("wallet migration succeeds for test setup with default migrations");
        }
        Ok(TestDb::from_parts(db_data, data_file))
    }
}

impl Reset for TestDb {
    type Handle = Option<NamedTempFile>;

    fn reset<C>(st: &mut TestState<C, Self, LocalNetwork>) -> Self::Handle {
        let network = *st.network();
        let anchor_retention_interval = st.wallet().db().anchor_retention_interval;
        #[cfg(feature = "transparent-inputs")]
        let gap_limits = st.wallet().db().gap_limits;
        let old_db = std::mem::replace(
            st.wallet_mut(),
            TestDbFactory::default()
                .new_data_store(
                    network,
                    Some(anchor_retention_interval),
                    #[cfg(feature = "transparent-inputs")]
                    Some(gap_limits),
                )
                .unwrap(),
        );
        old_db.take_data_file()
    }
}
