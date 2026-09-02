//! Storage-neutral APIs for privately completing Ironwood memos.
//!
//! These APIs deliberately use note-commitment-tree positions rather than
//! transaction IDs. A response is accepted only after the complete ciphertext
//! decrypts under the recorded account and reproduces the already-scanned note.

use incrementalmerkletree::Position;
use orchard::{
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes};
use zip32::Scope;

use super::{Account, WalletRead};

/// One pending memo lookup, identified only by its Ironwood tree position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoPirRequest {
    position: Position,
}

impl MemoPirRequest {
    /// Constructs a request for `position`.
    pub fn from_position(position: Position) -> Self {
        Self { position }
    }

    /// Returns the Ironwood commitment-tree position to query.
    pub fn position(&self) -> Position {
        self.position
    }
}

/// The complete encrypted-note fields stored in one memo-PIR record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodMemoRecord {
    ephemeral_key: [u8; 32],
    ciphertext: [u8; 580],
}

impl IronwoodMemoRecord {
    /// Constructs a record from the fields of an Ironwood encrypted note.
    pub fn from_parts(ephemeral_key: [u8; 32], ciphertext: [u8; 580]) -> Self {
        Self {
            ephemeral_key,
            ciphertext,
        }
    }

    /// Returns the ephemeral key bytes.
    pub fn ephemeral_key(&self) -> &[u8; 32] {
        &self.ephemeral_key
    }

    /// Returns the complete encrypted note ciphertext.
    pub fn ciphertext(&self) -> &[u8; 580] {
        &self.ciphertext
    }
}

/// Chain state to which a PIR snapshot is anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoPirSnapshotAnchor {
    /// Snapshot block height.
    pub height: BlockHeight,
    /// Snapshot block hash.
    pub block_hash: BlockHash,
    /// Ironwood tree size at the end of the anchor block.
    pub ironwood_tree_size: u64,
}

/// Whether a snapshot anchor is safe to use with the wallet's scanned chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoPirSnapshotStatus {
    /// Height and Ironwood tree size match locally scanned state.
    Accepted,
    /// The wallet has not scanned the anchor height yet.
    NotYetScanned,
    /// Local chain state disagrees with the snapshot.
    Mismatch,
}

/// Result of authenticating and applying a PIR record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoPirStoreResult {
    /// The authenticated memo was stored and the queue entry removed.
    Stored,
    /// No unresolved note exists at this position.
    AlreadyResolved,
    /// The record did not authenticate against the wallet's recorded note and key.
    Rejected,
}

/// Wallet state needed to authenticate a memo-PIR response.
#[doc(hidden)]
pub struct PendingIronwoodMemo<AccountId> {
    /// Account that received the note.
    pub account_id: AccountId,
    /// Compact-scanned note whose commitment must be reproduced.
    pub note: Note,
    /// Key scope detected by compact trial decryption.
    pub scope: Scope,
}

/// Read interface for the independent position-keyed memo queue.
pub trait MemoPirRead: WalletRead {
    /// Returns unresolved Ironwood memo requests in ascending position order.
    fn memo_pir_requests(&self) -> Result<Vec<MemoPirRequest>, Self::Error>;

    /// Compares the snapshot anchor to locally scanned chain state.
    fn memo_pir_snapshot_status(
        &self,
        anchor: MemoPirSnapshotAnchor,
    ) -> Result<MemoPirSnapshotStatus, Self::Error>;

    /// Returns authentication context for an unresolved position.
    #[doc(hidden)]
    fn pending_ironwood_memo(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMemo<Self::AccountId>>, Self::Error>;
}

/// Atomic storage operation used after successful response authentication.
pub trait MemoPirWrite: MemoPirRead {
    /// Stores a memo iff the same position is still unresolved, and removes its queue entry.
    #[doc(hidden)]
    fn put_ironwood_memo(
        &mut self,
        position: Position,
        memo: &MemoBytes,
    ) -> Result<bool, Self::Error>;
}

struct FullOutput<'a> {
    cmx: [u8; 32],
    record: &'a IronwoodMemoRecord,
}

impl ShieldedOutput<IronwoodDomain, 580> for FullOutput<'_> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(*self.record.ephemeral_key())
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }

    fn enc_ciphertext(&self) -> &[u8; 580] {
        self.record.ciphertext()
    }
}

/// Authenticates a PIR record against wallet-owned compact scan state and, on
/// success, atomically stores only its memo.
///
/// Malformed, misaddressed, stale, or cryptographically invalid records leave
/// both the note and its queue entry unchanged.
pub fn decrypt_and_store_ironwood_memo<DbT: MemoPirWrite>(
    db: &mut DbT,
    request: MemoPirRequest,
    record: &IronwoodMemoRecord,
) -> Result<MemoPirStoreResult, DbT::Error> {
    let Some(pending) = db.pending_ironwood_memo(request.position())? else {
        return Ok(MemoPirStoreResult::AlreadyResolved);
    };
    if pending.note.version() != NoteVersion::V3 {
        return Ok(MemoPirStoreResult::Rejected);
    }
    let Some(account) = db.get_account(pending.account_id)? else {
        return Ok(MemoPirStoreResult::Rejected);
    };
    let ivk = match pending.scope {
        Scope::External => account.uivk().orchard().as_ref().map(|ivk| ivk.prepare()),
        Scope::Internal => account
            .ufvk()
            .and_then(|ufvk| ufvk.orchard())
            .map(|fvk| fvk.to_ivk(Scope::Internal).prepare()),
    };
    let Some(ivk): Option<PreparedIncomingViewingKey> = ivk else {
        return Ok(MemoPirStoreResult::Rejected);
    };

    let Some(memo) = decrypt_memo(&pending.note, &ivk, record) else {
        return Ok(MemoPirStoreResult::Rejected);
    };

    Ok(if db.put_ironwood_memo(request.position(), &memo)? {
        MemoPirStoreResult::Stored
    } else {
        MemoPirStoreResult::AlreadyResolved
    })
}

fn decrypt_memo(
    expected_note: &Note,
    ivk: &PreparedIncomingViewingKey,
    record: &IronwoodMemoRecord,
) -> Option<MemoBytes> {
    let nullifier = Nullifier::from_bytes(&expected_note.rho().to_bytes());
    let nullifier = Option::from(nullifier)?;
    let cmx = ExtractedNoteCommitment::from(expected_note.commitment());
    let compact = CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(*record.ephemeral_key()),
        record.ciphertext()[..52]
            .try_into()
            .expect("fixed ciphertext size"),
    );
    let output = FullOutput {
        cmx: cmx.to_bytes(),
        record,
    };
    let (note, _, memo) = zcash_note_encryption::try_note_decryption(
        &IronwoodDomain::for_compact_action(&compact),
        ivk,
        &output,
    )?;
    if note != *expected_note {
        return None;
    }

    Some(MemoBytes::from_bytes(&memo).expect("note decryption returns exactly 512 bytes"))
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

    fn encrypted_record() -> (Note, PreparedIncomingViewingKey, IronwoodMemoRecord) {
        let usk =
            UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[0; 32], zip32::AccountId::ZERO)
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
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(5),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let encryptor = IronwoodNoteEncryption::new(None, note, [7; 512]);
        let record = IronwoodMemoRecord::from_parts(
            IronwoodDomain::epk_bytes(encryptor.epk()).0,
            encryptor.encrypt_note_plaintext(),
        );
        (note, fvk.to_ivk(Scope::External).prepare(), record)
    }

    #[test]
    fn accepts_authentic_ciphertext_and_rejects_tampering() {
        let (note, ivk, record) = encrypted_record();
        assert_eq!(
            decrypt_memo(&note, &ivk, &record).unwrap().as_slice(),
            &[7; 512]
        );

        let mut ciphertext = *record.ciphertext();
        ciphertext[579] ^= 1;
        let tampered = IronwoodMemoRecord::from_parts(*record.ephemeral_key(), ciphertext);
        assert!(decrypt_memo(&note, &ivk, &tampered).is_none());

        let (_, _, another_note_record) = encrypted_record();
        assert!(decrypt_memo(&note, &ivk, &another_note_record).is_none());
    }
}
