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
                db.create_account(
                    "old wallet fixture",
                    &secrecy::SecretVec::new(vec![7; 32]),
                    &AccountBirthday::from_parts(
                        ChainState::empty(BlockHeight::from_u32(1_200_000), BlockHash([0; 32])),
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
            db.update_chain_tip(BlockHeight::from_u32(3_483_367))
                .unwrap();
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
                Some(BlockHeight::from_u32(3_483_367)),
                &tx,
                vec![],
                vec![],
                vec![],
            );
            db.store_decrypted_tx(decrypted).unwrap();
            assert!(db.get_transaction(tx.txid()).unwrap().is_some());
            // Repeat ingestion of the existing row, as sync/enhancement does.
            db.store_decrypted_tx(DecryptedTransaction::new(
                Some(BlockHeight::from_u32(3_483_367)),
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
        _ => panic!("unexpected command"),
    }
}
