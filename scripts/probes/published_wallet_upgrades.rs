//! Runs only against disposable databases created by check-published-wallet-upgrades.py.
use std::path::PathBuf;
use zcash_client_backend::data_api::{
    DecryptedTransaction, WalletRead, WalletWrite, testing::TestRng,
};
use zcash_client_sqlite::{WalletDb, util::SystemClock, wallet::init::WalletMigrator};
use zcash_primitives::transaction::{Transaction, TransactionData};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mut db = WalletDb::for_path(
        PathBuf::from(&args[2]),
        Network::MainNetwork,
        SystemClock,
        TestRng::seed_from_u64(0),
    )
    .unwrap();
    // A library with explicit ledger modes stores transparent data only under a selected mode.
    #[cfg(feature = "ledger")]
    db.set_transparent_ledger_mode(
        zcash_client_backend::data_api::transparent_ledger::TransparentLedgerMode::Public,
    );
    match args[1].as_str() {
        #[cfg(feature = "ledger")]
        "refuse-old" => {
            use zcash_client_sqlite::wallet::init::WalletMigrationError;
            let error = WalletMigrator::new()
                .init_or_migrate(&mut db)
                .expect_err("older reader accepted unknown migrations");
            let cause = std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<WalletMigrationError>());
            assert!(
                matches!(cause, Some(WalletMigrationError::UnknownMigrations(ids)) if !ids.is_empty()),
                "older reader failed for an unrelated reason: {error:?}"
            );
        }
        "init" => {
            WalletMigrator::new().init_or_migrate(&mut db).unwrap();
            #[cfg(not(feature = "current"))]
            if db.get_account_ids().unwrap().is_empty() {
                use zcash_client_backend::data_api::{AccountBirthday, chain::ChainState};
                use zcash_primitives::block::BlockHash;
                // A one-time IVK writer issues keys only once scanning reaches the tip, so its
                // birthday is the fixture's tip (see `one_time_seed`).
                #[cfg(not(feature = "one-time"))]
                let parent = 1_200_000;
                #[cfg(feature = "one-time")]
                let parent = TIP - 1;
                db.create_account(
                    "old wallet fixture",
                    &secrecy::SecretVec::new(vec![7; 32]),
                    &AccountBirthday::from_parts(
                        ChainState::empty(BlockHeight::from_u32(parent), BlockHash([0; 32])),
                        None,
                    ),
                    None,
                )
                .unwrap();
            }
        }
        "ingest" => {
            // Ingest using the published schema before the current library upgrades it.
            WalletMigrator::new().init_or_migrate(&mut db).unwrap();
            db.update_chain_tip(BlockHeight::from_u32(TIP)).unwrap();
            let raw = hex::decode(std::fs::read_to_string(&args[3]).unwrap().trim()).unwrap();
            let branch =
                BranchId::try_from(u32::from_le_bytes(raw[8..12].try_into().unwrap())).unwrap();
            let parsed = Transaction::read(&raw[..], branch).unwrap();
            // Make wallet involvement unavoidable. The public fixture alone has no decryptable
            // output for this wallet, so its storage path would return successfully without
            // touching any rows. This synthetic fixture retains its Ironwood encoding and adds
            // a wallet-owned transparent output; it is an ingestion fixture, not a valid chain tx.
            let account = db.get_account_ids().unwrap()[0];
            let address = *db
                .get_transparent_receivers(account, false, false)
                .unwrap()
                .keys()
                .next()
                .unwrap();
            let tx = TransactionData::from_parts_v6(
                branch,
                parsed.lock_time(),
                parsed.expiry_height(),
                Some(transparent::bundle::Bundle {
                    vin: vec![],
                    vout: vec![transparent::bundle::TxOut::new(
                        zcash_protocol::value::Zatoshis::const_from_u64(5_000),
                        address.script().into(),
                    )],
                    authorization: transparent::bundle::Authorized,
                }),
                parsed.sapling_bundle().cloned(),
                parsed.orchard_bundle().cloned(),
                parsed.ironwood_bundle().cloned(),
            )
            .freeze()
            .unwrap();
            let decrypted = DecryptedTransaction::new(
                Some(BlockHeight::from_u32(TIP)),
                &tx,
                vec![],
                vec![],
                vec![],
            );
            db.store_decrypted_tx(decrypted).unwrap();
            assert!(db.get_transaction(tx.txid()).unwrap().is_some());
            // Repeat ingestion of the existing row, as sync/enhancement does.
            db.store_decrypted_tx(DecryptedTransaction::new(
                Some(BlockHeight::from_u32(TIP)),
                &tx,
                vec![],
                vec![],
                vec![],
            ))
            .unwrap();
            #[cfg(not(feature = "current"))]
            {
                use transparent::bundle::{OutPoint, TxOut};
                use zcash_client_backend::wallet::WalletTransparentOutput;
                use zcash_protocol::value::Zatoshis;
                let account = db.get_account_ids().unwrap()[0];
                let address = *db
                    .get_transparent_receivers(account, false, false)
                    .unwrap()
                    .keys()
                    .next()
                    .unwrap();
                let output = WalletTransparentOutput::from_parts(
                    OutPoint::new([7; 32], 0),
                    TxOut::new(Zatoshis::const_from_u64(50_000), address.script().into()),
                    Some(BlockHeight::from_u32(3_483_365)),
                    Some(account),
                    None,
                    None,
                )
                .unwrap();
                db.put_received_transparent_utxo(&output).unwrap();
            }
        }
        #[cfg(feature = "one-time")]
        "one-time" => {
            // Scans the empty tip block, then reserves and starts an incoming swap and
            // reserves a refund key bound to a deposit, using the published one-time IVK
            // API. Prints the request, refund deposit and refund index for "one-time-use".
            use zcash_client_backend::data_api::chain::{ChainState, scan_cached_blocks};
            use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactBlock};
            use zcash_client_sqlite::wallet::one_time_ivk::swap::{
                OperationOutcome, ReceiveDeposit,
            };
            use zcash_primitives::block::BlockHash;

            let now = unix_now();
            let tip = BlockHeight::from_u32(TIP);
            let block = CompactBlock {
                height: TIP.into(),
                hash: vec![1; 32],
                prev_hash: vec![0; 32],
                time: now as u32,
                chain_metadata: Some(ChainMetadata::default()),
                ..Default::default()
            };
            let parent = ChainState::empty(tip - 1, BlockHash([0; 32]));
            scan_cached_blocks(
                &Network::MainNetwork,
                &Blocks(vec![block]),
                &mut db,
                tip,
                &parent,
                1,
            )
            .unwrap();
            let account = db.get_account_ids().unwrap()[0];
            db.mark_one_time_account_fresh(account).unwrap();
            let key = db
                .prepare_receive_reservation(account, now, tip, None)
                .unwrap()
                .unwrap();
            let deadline = now + 86_400;
            let request = db
                .begin_receive_operation(account, key.key_id().index(), deadline, now)
                .unwrap()
                .unwrap();
            let deposit = ReceiveDeposit {
                address: INCOMING_DEPOSIT.to_owned(),
                memo: None,
                deadline,
            };
            db.finish_receive_operation(
                account,
                &request,
                &OperationOutcome::Accepted(deposit.clone()),
            )
            .unwrap();
            assert_eq!(
                db.start_receive_operation(account, &request, now)
                    .unwrap()
                    .unwrap(),
                deposit
            );
            let refund = db.reserve_refund_key(account, tip, None).unwrap().unwrap();
            let receiver = *db
                .get_transparent_receivers(account, false, false)
                .unwrap()
                .keys()
                .next()
                .unwrap();
            #[allow(deprecated)]
            let refund_deposit = zcash_client_backend::encoding::encode_transparent_address_p(
                &Network::MainNetwork,
                &receiver,
            );
            let refund = refund.key_id().index();
            db.record_refund_operation(account, refund, &refund_deposit, deadline, now)
                .unwrap();
            println!("{request} {refund_deposit} {refund}");
        }
        #[cfg(feature = "current")]
        "one-time-use" => {
            // Uses the state "one-time" left, after the current library upgraded it.
            use zcash_client_backend::data_api::one_time_ivk::coverage::OneTimeIvkCoverageRead;

            let (request, refund_deposit, refund) = (&args[4], &args[5], &args[6]);
            let now = unix_now();
            let account = db.get_account_ids().unwrap()[0];
            // The upgrade leaves recovery to start from nothing.
            let status = db.one_time_recovery_status(account).unwrap();
            assert!(status.is_none_or(|status| status.frontier.is_none()));
            let deposit = db
                .start_receive_operation(account, request, now)
                .unwrap()
                .unwrap();
            assert_eq!(deposit.address, INCOMING_DEPOSIT);
            db.refund_funding_memo(account, refund.parse().unwrap(), refund_deposit)
                .unwrap();
            // Both keys still have an operation in progress.
            let closed = db
                .close_finished_one_time_keys(account, now, BlockHeight::from_u32(TIP))
                .unwrap();
            assert_eq!(closed, 0);
        }
        _ => panic!("unexpected command"),
    }
}

/// The fixture's chain tip and mined height.
const TIP: u32 = 3_483_367;

/// The provider deposit address of the fixture's incoming swap.
#[cfg(any(feature = "one-time", feature = "current"))]
const INCOMING_DEPOSIT: &str = "incoming-deposit";

/// Seconds since the Unix epoch.
#[cfg(any(feature = "one-time", feature = "current"))]
fn unix_now() -> i64 {
    std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() as i64
}

/// Compact blocks held in memory.
#[cfg(feature = "one-time")]
struct Blocks(Vec<zcash_client_backend::proto::compact_formats::CompactBlock>);

#[cfg(feature = "one-time")]
impl zcash_client_backend::data_api::chain::BlockSource for Blocks {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(
            zcash_client_backend::proto::compact_formats::CompactBlock,
        ) -> Result<
            (),
            zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>,
        >,
    {
        let from = from_height.map_or(0, u64::from);
        self.0
            .iter()
            .filter(|block| block.height >= from)
            .take(limit.unwrap_or(usize::MAX))
            .try_for_each(|block| with_block(block.clone()))
    }
}
