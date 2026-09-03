//! SQLite storage for the DAG-sync pass: spend records, discovered notes,
//! and externally supplied witnesses.

use incrementalmerkletree::Position;
use rusqlite::{Connection, OptionalExtension, Transaction, named_params};
use uuid::Uuid;
use zcash_client_backend::{
    data_api::pir_dag::{DagNote, DiscoveredNote, PirWitnessRecord, SpendMeta},
    wallet::WalletIronwoodOutput,
};
use zcash_protocol::{ShieldedPool, consensus};

use crate::{AccountUuid, TxRef, error::SqliteClientError};

use super::orchard::put_received_note;

/// SQL for "this note has a durable witness": either the local shard tree
/// stabilized it or a verified PIR witness is stored. Only the Ironwood table
/// has the latter.
pub(crate) fn stabilized_expr(table_prefix: &str) -> String {
    if table_prefix == "ironwood" {
        "(rn.witness_stabilized OR EXISTS (
            SELECT 1 FROM ironwood_pir_witnesses w WHERE w.received_note_id = rn.id
        ))"
        .to_string()
    } else {
        "rn.witness_stabilized".to_string()
    }
}

pub(crate) fn dag_notes(conn: &Connection) -> Result<Vec<DagNote<AccountUuid>>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid, rn.commitment_tree_position, rn.nf,
                EXISTS (SELECT 1 FROM ironwood_pir_witnesses w WHERE w.received_note_id = rn.id)
         FROM ironwood_received_notes rn
         JOIN accounts a ON a.id = rn.account_id
         JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE rn.nf IS NOT NULL
           AND rn.commitment_tree_position IS NOT NULL
           AND t.mined_height IS NOT NULL
           AND rn.id NOT IN (
               SELECT s.ironwood_received_note_id
               FROM ironwood_received_note_spends s
               JOIN transactions st ON st.id_tx = s.transaction_id
               WHERE st.mined_height IS NOT NULL OR st.expiry_height = 0
           )
         ORDER BY rn.commitment_tree_position ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        let uuid: Uuid = row.get(0)?;
        let position: i64 = row.get(1)?;
        let nf: [u8; 32] = row.get(2)?;
        let has_witness: bool = row.get(3)?;
        Ok((uuid, position, nf, has_witness))
    })?;
    rows.map(|row| {
        let (uuid, position, nullifier, has_witness) = row?;
        let position = u64::try_from(position).map_err(|_| {
            SqliteClientError::CorruptedData("Ironwood note has an invalid position".to_owned())
        })?;
        Ok(DagNote {
            account_id: AccountUuid(uuid),
            position: Position::from(position),
            nullifier,
            has_witness,
        })
    })
    .collect()
}

fn note_id_at(conn: &Connection, position: Position) -> Result<Option<i64>, SqliteClientError> {
    conn.query_row(
        "SELECT rn.id
         FROM ironwood_received_notes rn
         JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE rn.commitment_tree_position = :position
           AND t.mined_height IS NOT NULL
         ORDER BY rn.id DESC
         LIMIT 1",
        named_params![":position": u64::from(position)],
        |row| row.get(0),
    )
    .optional()
    .map_err(SqliteClientError::from)
}

pub(crate) fn put_witness(
    conn: &Transaction,
    witness: &PirWitnessRecord,
) -> Result<bool, SqliteClientError> {
    let Some(note_id) = note_id_at(conn, witness.position)? else {
        return Ok(false);
    };
    let siblings: Vec<u8> = witness.siblings.iter().flatten().copied().collect();
    conn.execute(
        "INSERT INTO ironwood_pir_witnesses
            (received_note_id, anchor_height, anchor_root, leaf, siblings)
         VALUES (:id, :height, :root, :leaf, :siblings)
         ON CONFLICT (received_note_id) DO UPDATE
         SET anchor_height = :height, anchor_root = :root, leaf = :leaf, siblings = :siblings",
        named_params![
            ":id": note_id,
            ":height": u32::from(witness.anchor_height),
            ":root": &witness.anchor_root[..],
            ":leaf": &witness.leaf[..],
            ":siblings": siblings,
        ],
    )?;
    Ok(true)
}

/// Returns the stored witness for the note at `position`, if any.
pub(crate) fn witness_at(
    conn: &Connection,
    position: Position,
) -> Result<Option<PirWitnessRecord>, SqliteClientError> {
    let Some(note_id) = note_id_at(conn, position)? else {
        return Ok(None);
    };
    conn.query_row(
        "SELECT anchor_height, anchor_root, leaf, siblings
         FROM ironwood_pir_witnesses WHERE received_note_id = :id",
        named_params![":id": note_id],
        |row| {
            let anchor_height: u32 = row.get(0)?;
            let anchor_root: [u8; 32] = row.get(1)?;
            let leaf: [u8; 32] = row.get(2)?;
            let siblings: Vec<u8> = row.get(3)?;
            Ok((anchor_height, anchor_root, leaf, siblings))
        },
    )
    .optional()?
    .map(|(anchor_height, anchor_root, leaf, siblings)| {
        let mut out = [[0u8; 32]; 32];
        for (level, chunk) in siblings.chunks_exact(32).enumerate().take(32) {
            out[level].copy_from_slice(chunk);
        }
        Ok(PirWitnessRecord {
            position,
            leaf,
            siblings: out,
            anchor_height: consensus::BlockHeight::from(anchor_height),
            anchor_root,
        })
    })
    .transpose()
}

/// The stored witness for the note at `position` as the transaction builder
/// consumes it, if one exists and its bytes decode as tree nodes.
pub(crate) fn external_witness(
    conn: &Connection,
    position: Position,
) -> Result<
    Option<zcash_client_backend::data_api::ExternalIronwoodWitness>,
    super::commitment_tree::Error,
> {
    external_witness_inner(conn, position).map_err(|error| match error {
        SqliteClientError::DbError(error) => super::commitment_tree::Error::Query(error),
        other => super::commitment_tree::Error::Serialization(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            other.to_string(),
        )),
    })
}

fn external_witness_inner(
    conn: &Connection,
    position: Position,
) -> Result<Option<zcash_client_backend::data_api::ExternalIronwoodWitness>, SqliteClientError> {
    use incrementalmerkletree::Hashable as _;
    use orchard::tree::MerkleHashOrchard;

    let Some(record) = witness_at(conn, position)? else {
        return Ok(None);
    };
    let anchor =
        Option::from(orchard::Anchor::from_bytes(record.anchor_root)).ok_or_else(|| {
            SqliteClientError::CorruptedData("stored PIR witness anchor is not a tree root".into())
        })?;
    let mut auth_path = [MerkleHashOrchard::empty_leaf(); 32];
    for (level, sibling) in record.siblings.iter().enumerate() {
        auth_path[level] =
            Option::from(MerkleHashOrchard::from_bytes(sibling)).ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "stored PIR witness sibling is not a tree node".into(),
                )
            })?;
    }
    let position = u32::try_from(u64::from(position)).map_err(|_| {
        SqliteClientError::CorruptedData("stored PIR witness position exceeds u32".into())
    })?;
    Ok(Some(
        zcash_client_backend::data_api::ExternalIronwoodWitness {
            anchor,
            merkle_path: orchard::tree::MerklePath::from_parts(position, auth_path),
        },
    ))
}

/// A transaction row for a txid the wallet learned of through PIR. `block`
/// stays NULL (it references scanned blocks) while `mined_height` records
/// where it was mined; scanning fills `block` in when it reaches the height.
fn ensure_pir_transaction(
    conn: &Transaction,
    txid: &[u8; 32],
    height: consensus::BlockHeight,
) -> Result<TxRef, SqliteClientError> {
    conn.query_row(
        "INSERT INTO transactions (txid, mined_height, min_observed_height)
         VALUES (:txid, :height, :height)
         ON CONFLICT (txid) DO UPDATE
         SET mined_height = IFNULL(mined_height, :height),
             min_observed_height = MIN(min_observed_height, :height),
             confirmed_unmined_at_height = NULL
         RETURNING id_tx",
        named_params![":txid": &txid[..], ":height": u32::from(height)],
        |row| row.get::<_, i64>(0).map(TxRef),
    )
    .map_err(SqliteClientError::from)
}

pub(crate) fn record_spend(
    conn: &Transaction,
    position: Position,
    meta: SpendMeta,
    txid: [u8; 32],
) -> Result<bool, SqliteClientError> {
    let Some(note_id) = note_id_at(conn, position)? else {
        return Ok(false);
    };
    let tx_ref = ensure_pir_transaction(conn, &txid, meta.spend_height)?;
    conn.execute(
        "INSERT INTO ironwood_received_note_spends (ironwood_received_note_id, transaction_id)
         VALUES (:note_id, :tx)
         ON CONFLICT (ironwood_received_note_id, transaction_id) DO NOTHING",
        named_params![":note_id": note_id, ":tx": tx_ref.0],
    )?;
    Ok(true)
}

pub(crate) fn put_discovered_note<P: consensus::Parameters>(
    conn: &Transaction,
    params: &P,
    discovered: &DiscoveredNote<AccountUuid>,
) -> Result<(), SqliteClientError> {
    let tx_ref = ensure_pir_transaction(conn, &discovered.txid, discovered.height)?;
    let output: WalletIronwoodOutput<AccountUuid> = WalletIronwoodOutput::from_parts(
        discovered.action_index,
        discovered.ephemeral_key.clone(),
        (discovered.note, orchard::ValuePool::Ironwood),
        discovered.scope == zip32::Scope::Internal,
        discovered.position,
        discovered.nullifier,
        discovered.account_id,
        Some(discovered.scope),
    );
    put_received_note(
        conn,
        params,
        ShieldedPool::Ironwood,
        &output,
        tx_ref,
        Some(discovered.height),
        None,
    )?;
    super::memo_pir::put(conn, discovered.position, &discovered.memo)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use incrementalmerkletree::Position;
    use orchard::{
        note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use pasta_curves::{group::ff::PrimeField, pallas};
    use zcash_client_backend::data_api::{
        Account as _,
        pir_dag::{
            ActionRecordView, PirDagRead, PirDagWrite, PirWitnessRecord, SpendMeta, discover_change,
        },
        testing::TestBuilder,
    };
    use zcash_note_encryption::Domain;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::BlockHeight;
    use zip32::Scope;

    use crate::testing::db::TestDbFactory;

    /// Encrypts one change note to the test account's internal key, the way a
    /// spending transaction's ACTION record carries it.
    fn change_record(
        fvk: &orchard::keys::FullViewingKey,
        value: u64,
        txid: [u8; 32],
        height: BlockHeight,
    ) -> ActionRecordView {
        let nullifier =
            Nullifier::from_bytes(&pallas::Base::from(0x5eed_u64 + value).to_repr()).unwrap();
        let rho = Rho::from_bytes(&nullifier.to_bytes()).unwrap();
        let rseed = (0u8..=255)
            .find_map(|salt| Option::from(RandomSeed::from_bytes([salt; 32], &rho)))
            .expect("some fixed seed is valid");
        let note = Note::from_parts(
            fvk.address_at(0u32, Scope::Internal),
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let encryptor = IronwoodNoteEncryption::new(None, note, [5; 512]);
        ActionRecordView {
            nullifier: nullifier.to_bytes(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            ciphertext: encryptor.encrypt_note_plaintext(),
            cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
            txid,
            height,
        }
    }

    #[test]
    fn discovered_change_is_listed_witnessed_and_then_spent_by_position() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().cloned().unwrap();
        let fvk = account
            .account()
            .ufvk()
            .and_then(|ufvk| ufvk.orchard().cloned())
            .expect("Orchard key");

        // A change note in a transaction the wallet never scanned.
        let height = account.birthday().height() + 10;
        let record = change_record(&fvk, 7_000, [3; 32], height);
        let first_output_position = Position::from(1_000u64);
        assert_eq!(
            discover_change(
                st.wallet_mut().db_mut(),
                first_output_position,
                std::slice::from_ref(&record)
            )
            .unwrap(),
            1
        );
        // Re-running the same record is idempotent.
        assert_eq!(
            discover_change(st.wallet_mut().db_mut(), first_output_position, &[record]).unwrap(),
            1
        );

        let notes = st.wallet().db().dag_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].position, first_output_position);
        assert!(!notes[0].has_witness);
        assert_eq!(notes[0].account_id, account.id());

        let conn = st.wallet().conn();
        let (memo, stabilized, block, mined): (Vec<u8>, bool, Option<u32>, Option<u32>) = conn
            .query_row(
                "SELECT rn.memo, rn.witness_stabilized, t.block, t.mined_height
                 FROM ironwood_received_notes rn
                 JOIN transactions t ON t.id_tx = rn.transaction_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(memo, vec![5; 512], "memo stored from the record");
        assert!(!stabilized);
        assert_eq!(block, None, "no scanned block backs the transaction");
        assert_eq!(mined, Some(u32::from(height)));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM ironwood_memo_retrieval_queue",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "memo arrived with the record; nothing left to retrieve"
        );

        // The note gains an external witness.
        assert!(
            st.wallet()
                .db()
                .pir_witness(first_output_position)
                .unwrap()
                .is_none()
        );
        let witness = PirWitnessRecord {
            position: first_output_position,
            leaf: [1; 32],
            siblings: [[2; 32]; 32],
            anchor_height: height + 5,
            anchor_root: [4; 32],
        };
        assert!(st.wallet_mut().db_mut().put_pir_witness(&witness).unwrap());
        assert!(
            !st.wallet_mut()
                .db_mut()
                .put_pir_witness(&PirWitnessRecord {
                    position: Position::from(999u64),
                    ..witness.clone()
                })
                .unwrap()
        );
        assert_eq!(
            st.wallet().db().pir_witness(first_output_position).unwrap(),
            Some(witness)
        );
        assert!(st.wallet().db().dag_notes().unwrap()[0].has_witness);
        let conn = st.wallet().conn();
        let stabilized: bool = conn
            .query_row(
                &format!(
                    "SELECT {} FROM ironwood_received_notes rn",
                    super::stabilized_expr("ironwood")
                ),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stabilized, "an external witness makes the note spendable");

        // Then it is found spent.
        let meta = SpendMeta {
            spend_height: height + 20,
            first_output_position: Position::from(2_000u64),
            action_count: 2,
        };
        assert!(
            !st.wallet_mut()
                .db_mut()
                .record_pir_spend(Position::from(999u64), meta, [8; 32])
                .unwrap()
        );
        assert!(
            st.wallet_mut()
                .db_mut()
                .record_pir_spend(first_output_position, meta, [8; 32])
                .unwrap()
        );
        assert!(st.wallet().db().dag_notes().unwrap().is_empty());
        let conn = st.wallet().conn();
        let (spends, mined): (i64, u32) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM ironwood_received_note_spends), t.mined_height
                 FROM transactions t WHERE t.txid = ?",
                [&[8u8; 32][..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(spends, 1);
        assert_eq!(mined, u32::from(height + 20));
    }

    /// The stored siblings come back as a path whose root is the stored
    /// anchor, so the transaction builder's anchor check passes.
    #[test]
    fn stored_witness_converts_to_a_path_reaching_its_anchor() {
        use incrementalmerkletree::Hashable as _;
        use orchard::tree::MerkleHashOrchard;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().cloned().unwrap();
        let fvk = account
            .account()
            .ufvk()
            .and_then(|ufvk| ufvk.orchard().cloned())
            .expect("Orchard key");
        let height = account.birthday().height() + 10;
        let record = change_record(&fvk, 9_000, [6; 32], height);
        let cmx = ExtractedNoteCommitment::from_bytes(&record.cmx).unwrap();
        let position = Position::from(5u64);
        discover_change(
            st.wallet_mut().db_mut(),
            position,
            std::slice::from_ref(&record),
        )
        .unwrap();

        // A tree holding only this leaf at position 5: every sibling is an empty subtree.
        let mut siblings = [[0u8; 32]; 32];
        let mut node = MerkleHashOrchard::from_cmx(&cmx);
        let mut index = u64::from(position);
        for (level, sibling) in siblings.iter_mut().enumerate() {
            let empty = MerkleHashOrchard::empty_root((level as u8).into());
            *sibling = empty.to_bytes();
            node = if index & 1 == 1 {
                MerkleHashOrchard::combine((level as u8).into(), &empty, &node)
            } else {
                MerkleHashOrchard::combine((level as u8).into(), &node, &empty)
            };
            index >>= 1;
        }
        let witness = PirWitnessRecord {
            position,
            leaf: cmx.to_bytes(),
            siblings,
            anchor_height: height + 1,
            anchor_root: node.to_bytes(),
        };
        assert!(st.wallet_mut().db_mut().put_pir_witness(&witness).unwrap());

        let external = super::external_witness(st.wallet().conn(), position)
            .unwrap()
            .expect("stored");
        assert_eq!(external.merkle_path.root(cmx), external.anchor);
        assert_eq!(
            external.anchor,
            orchard::Anchor::from_bytes(node.to_bytes()).unwrap()
        );
        assert!(
            super::external_witness(st.wallet().conn(), Position::from(6u64))
                .unwrap()
                .is_none()
        );
    }
}
