//! Storage-neutral APIs for the DAG-sync pass: spend checks, change-note
//! discovery, and externally supplied Ironwood witnesses, all keyed by
//! commitment-tree position rather than transaction ID.
//!
//! The wallet obtains three things privately: whether a known note's
//! nullifier appears in the chain (with the spending transaction's place in
//! the tree), the full action records of that spending transaction (so change
//! notes can be trial-decrypted), and Merkle paths for unspent notes. This
//! module authenticates every input against wallet-owned keys before anything
//! is stored: a discovered note must decrypt under one of the wallet's
//! incoming viewing keys and reproduce the commitment the record carries.

use incrementalmerkletree::Position;
use orchard::{
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Note, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput};
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes};
use zip32::Scope;

use super::{Account, WalletRead, memo_pir::MemoPirWrite};

/// Where a nullifier's spending transaction sits, as the nullifier tables report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendMeta {
    /// Height of the block containing the spending transaction.
    pub spend_height: BlockHeight,
    /// Commitment-tree position of the spending transaction's first Ironwood output.
    pub first_output_position: Position,
    /// Number of Ironwood actions in the spending transaction.
    pub action_count: u8,
}

/// One unspent Ironwood note the pass may need to check or witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagNote<AccountId> {
    /// Account that received the note.
    pub account_id: AccountId,
    /// Commitment-tree position; the note's identity for every PIR table.
    pub position: Position,
    /// The note's nullifier under the wallet's key.
    pub nullifier: [u8; 32],
    /// Whether a verified external witness is stored for it.
    pub has_witness: bool,
    /// Whether the local shard tree can already witness it; such a note needs
    /// no external witness.
    pub witness_stabilized: bool,
}

/// A Merkle path for one note, reconstructed and verified by the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirWitnessRecord {
    /// Position the path authenticates.
    pub position: Position,
    /// Leaf (the note commitment) the path starts from.
    pub leaf: [u8; 32],
    /// Siblings, level 0 first.
    pub siblings: [[u8; 32]; 32],
    /// Block height of the anchor the path reaches.
    pub anchor_height: BlockHeight,
    /// Depth-32 tree root at the anchor.
    pub anchor_root: [u8; 32],
}

/// The fields of one action record that discovery needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRecordView {
    /// The action's spent nullifier: `rho` of its output note.
    pub nullifier: [u8; 32],
    /// Ephemeral key bytes.
    pub ephemeral_key: [u8; 32],
    /// Complete encrypted note ciphertext.
    pub ciphertext: [u8; 580],
    /// Extracted commitment of the output note.
    pub cmx: [u8; 32],
    /// Containing transaction's ID, internal byte order.
    pub txid: [u8; 32],
    /// Containing block height.
    pub height: BlockHeight,
}

/// A note the wallet did not know until trial decryption found it.
#[derive(Clone)]
pub struct DiscoveredNote<AccountId> {
    /// Account whose key decrypted it.
    pub account_id: AccountId,
    /// Key scope that decrypted it; change is `Internal`.
    pub scope: Scope,
    /// The decrypted note.
    pub note: Note,
    /// Its nullifier under the account's full viewing key, if available.
    pub nullifier: Option<Nullifier>,
    /// The memo, so no separate memo retrieval is needed.
    pub memo: MemoBytes,
    /// Ephemeral key from the record.
    pub ephemeral_key: EphemeralKeyBytes,
    /// Commitment-tree position.
    pub position: Position,
    /// Index of the action within its transaction.
    pub action_index: usize,
    /// Containing transaction's ID, internal byte order.
    pub txid: [u8; 32],
    /// Containing block height.
    pub height: BlockHeight,
}

/// Read interface for the DAG-sync pass.
pub trait PirDagRead: WalletRead {
    /// Returns every mined, unspent Ironwood note with a known nullifier and
    /// position, in ascending position order.
    fn dag_notes(&self) -> Result<Vec<DagNote<Self::AccountId>>, Self::Error>;

    /// Returns the stored external witness for the mined note at `position`,
    /// if one exists. The send path uses it in place of a locally generated
    /// path when the local shard tree cannot vouch for the note.
    fn pir_witness(&self, position: Position) -> Result<Option<PirWitnessRecord>, Self::Error>;
}

/// Write interface for the DAG-sync pass.
pub trait PirDagWrite: PirDagRead + MemoPirWrite {
    /// Stores a verified witness for the note at its position, replacing an
    /// older one. Returns `false` if no such note exists.
    fn put_pir_witness(&mut self, witness: &PirWitnessRecord) -> Result<bool, Self::Error>;

    /// Records that the note at `position` was spent in the transaction
    /// `txid` mined at `meta.spend_height`. The transaction row is created
    /// without a scanned block if the wallet has not scanned that height.
    /// Returns `false` if no such note exists.
    fn record_pir_spend(
        &mut self,
        position: Position,
        meta: SpendMeta,
        txid: [u8; 32],
    ) -> Result<bool, Self::Error>;

    /// Stores a discovered note (and its memo) under its transaction.
    fn put_discovered_note(
        &mut self,
        note: &DiscoveredNote<Self::AccountId>,
    ) -> Result<(), Self::Error>;
}

struct RecordOutput<'a>(&'a ActionRecordView);

impl ShieldedOutput<IronwoodDomain, 580> for RecordOutput<'_> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0.ephemeral_key)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.0.cmx
    }

    fn enc_ciphertext(&self) -> &[u8; 580] {
        &self.0.ciphertext
    }
}

/// Trial-decrypts one record under `ivk`. Authenticated by the standard note
/// decryption: the recovered note must recommit to the record's `cmx`.
pub fn decrypt_record(
    record: &ActionRecordView,
    ivk: &PreparedIncomingViewingKey,
) -> Option<(Note, MemoBytes)> {
    let nullifier = Option::from(Nullifier::from_bytes(&record.nullifier))?;
    let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&record.cmx))?;
    let compact = CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(record.ephemeral_key),
        record.ciphertext[..52]
            .try_into()
            .expect("fixed ciphertext size"),
    );
    let (note, _, memo) = zcash_note_encryption::try_note_decryption(
        &IronwoodDomain::for_compact_action(&compact),
        ivk,
        &RecordOutput(record),
    )?;
    Some((
        note,
        MemoBytes::from_bytes(&memo).expect("note decryption returns exactly 512 bytes"),
    ))
}

/// Trial-decrypts the action records of one transaction against every
/// account's internal then external Ironwood key, storing each note found.
/// `first_output_position` is the position of the record at index 0.
/// Returns the number of notes stored.
pub fn discover_change<DbT: PirDagWrite>(
    db: &mut DbT,
    first_output_position: Position,
    records: &[ActionRecordView],
) -> Result<usize, DbT::Error> {
    let mut keys = Vec::new();
    for account_id in db.get_account_ids()? {
        let Some(account) = db.get_account(account_id)? else {
            continue;
        };
        let Some(fvk) = account.ufvk().and_then(|ufvk| ufvk.orchard().cloned()) else {
            continue;
        };
        for scope in [Scope::Internal, Scope::External] {
            keys.push((account_id, scope, fvk.to_ivk(scope).prepare(), fvk.clone()));
        }
    }
    let mut stored = 0;
    for (index, record) in records.iter().enumerate() {
        for (account_id, scope, ivk, fvk) in &keys {
            let Some((note, memo)) = decrypt_record(record, ivk) else {
                continue;
            };
            let nullifier = note.nullifier(fvk);
            db.put_discovered_note(&DiscoveredNote {
                account_id: *account_id,
                scope: *scope,
                note,
                nullifier: Some(nullifier),
                memo,
                ephemeral_key: EphemeralKeyBytes(record.ephemeral_key),
                position: first_output_position + index as u64,
                action_index: index,
                txid: record.txid,
                height: record.height,
            })?;
            stored += 1;
            break;
        }
    }
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use orchard::{
        note::{Note, NoteVersion, Nullifier, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use pasta_curves::{
        group::ff::{Field, PrimeField},
        pallas,
    };
    use rand::{Rng as _, rand_core::UnwrapErr, rngs::SysRng};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_note_encryption::Domain;
    use zcash_protocol::consensus::Network;

    use super::*;

    #[allow(non_upper_case_globals)]
    const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

    #[test]
    fn a_record_decrypts_only_under_its_recipient_key_and_authenticates_cmx() {
        let usk =
            UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[1; 32], zip32::AccountId::ZERO)
                .expect("valid spending key");
        let fvk = usk
            .to_unified_full_viewing_key()
            .orchard()
            .expect("Orchard key")
            .clone();
        let mut rng = OsRng;
        let nullifier = Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr()).unwrap();
        let rho = Rho::from_bytes(&nullifier.to_bytes()).unwrap();
        let rseed = loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            if let Some(rseed) = Option::from(RandomSeed::from_bytes(bytes, &rho)) {
                break rseed;
            }
        };
        let note = Note::from_parts(
            fvk.address_at(0u32, Scope::Internal),
            NoteValue::from_raw(42),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let encryptor = IronwoodNoteEncryption::new(None, note, [9; 512]);
        let record = ActionRecordView {
            nullifier: nullifier.to_bytes(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            ciphertext: encryptor.encrypt_note_plaintext(),
            cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
            txid: [7; 32],
            height: BlockHeight::from_u32(3_428_200),
        };

        let internal = fvk.to_ivk(Scope::Internal).prepare();
        let (found, memo) = decrypt_record(&record, &internal).expect("change decrypts");
        assert_eq!(found, note);
        assert_eq!(memo.as_slice(), &[9; 512]);

        let external = fvk.to_ivk(Scope::External).prepare();
        assert!(decrypt_record(&record, &external).is_none());

        let mut tampered = record.clone();
        tampered.cmx[0] ^= 1;
        assert!(decrypt_record(&tampered, &internal).is_none());
    }
}
