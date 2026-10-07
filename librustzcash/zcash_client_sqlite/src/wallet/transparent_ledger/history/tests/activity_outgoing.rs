//! History must retain the accounting significance of pools disabled in this build.

use zcash_client_backend::data_api::{
    Account as _,
    testing::{AddressType, TestBuilder, pool::ShieldedPoolTester, sapling::SaplingPoolTester},
    transparent_ledger::TransparentLedgerRead as _,
};
use zcash_primitives::block::BlockHash;

use crate::testing::{BlockCache, db::TestDbFactory};

use super::*;

/// Read the production history API against migrated, compact-scanned state. The extra pool's
/// financial rows model amounts retained from a previous build with that pool enabled; no note
/// decryption is needed to read them, and their bytes are deliberately synthetic.
fn history_with_recorded_pool(
    prefix: &str,
    received: u64,
    spent: u64,
) -> TransactionHistoryDetails {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let account = st.test_account().unwrap().id();
    let fvk = SaplingPoolTester::test_account_fvk(&st);
    let (height, _, _) = st.generate_next_block(
        &fvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(100_000_000),
    );
    st.scan_cached_blocks(height, 1);
    let funding_note: i64 = st
        .wallet()
        .conn()
        .query_row("SELECT id FROM sapling_received_notes", [], |r| r.get(0))
        .unwrap();
    let funding_tx: i64 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT transaction_id FROM sapling_received_notes",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let (height, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, Zatoshis::ZERO);
    st.scan_cached_blocks(height, 1);
    let conn = st.wallet().conn();
    let (tx, txid, account_id): (i64, [u8; 32], i64) = conn
        .query_row(
            "SELECT n.transaction_id, t.txid, n.account_id FROM sapling_received_notes n
             JOIN transactions t ON t.id_tx = n.transaction_id WHERE t.mined_height = ?",
            [u32::from(height)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO sapling_received_note_spends VALUES (?1, ?2)",
        [funding_note, tx],
    )
    .unwrap();
    conn.execute("UPDATE transactions SET fee = 15000 WHERE id_tx = ?", [tx])
        .unwrap();
    conn.execute(
        "INSERT INTO ironwood_enhance_routing (
             transaction_id, route, has_transparent_outputs, has_transparent_outputs_height
         )
         SELECT id_tx, 1, 1, mined_height FROM transactions WHERE id_tx = ?1",
        [tx],
    )
    .unwrap();
    for (note_tx, value) in [(tx, received), (funding_tx, spent)] {
        conn.execute(
            &format!(
                "INSERT INTO {prefix}_received_notes (transaction_id, action_index, account_id,
                    diversifier, value, rho, rseed, is_change, note_version)
                 VALUES (?1, 0, ?2, zeroblob(11), ?3, zeroblob(32), zeroblob(32), 1, ?4)"
            ),
            rusqlite::params![
                note_tx,
                account_id,
                value,
                if prefix == "ironwood" { 3 } else { 2 }
            ],
        )
        .unwrap();
    }
    conn.execute(
        &format!(
            "INSERT INTO {prefix}_received_note_spends ({prefix}_received_note_id, transaction_id)
             SELECT id, ?1 FROM {prefix}_received_notes WHERE transaction_id = ?2"
        ),
        [tx, funding_tx],
    )
    .unwrap();
    let mut entries = st
        .wallet()
        .db()
        .transaction_history_details(account, &[TxId::from_bytes(txid)])
        .unwrap();
    assert_eq!(entries.len(), 1);
    entries.remove(0)
}

#[test]
fn recorded_pool_amounts_are_never_dropped_from_outgoing_inference() {
    for prefix in ["orchard", "ironwood"] {
        for (received, spent) in [(99_000_000, 0), (0, 99_000_000), (0, 0)] {
            let entry = history_with_recorded_pool(prefix, received, spent);
            assert_eq!(entry.whole_fee, Some(Zatoshis::const_from_u64(15_000)));
            assert_eq!(entry.account_movement.received, received);
            assert_eq!(entry.account_movement.spent, 100_000_000 + spent);
            let expected = (cfg!(feature = "orchard") || (received == 0 && spent == 0))
                .then(|| Zatoshis::const_from_u64(100_000_000 + spent - received - 15_000));
            assert_eq!(
                entry.inferred_outgoing, expected,
                "pool={prefix}, received={received}, spent={spent}"
            );
        }
    }
}
