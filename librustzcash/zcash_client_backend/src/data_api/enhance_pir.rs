//! Storage-neutral APIs for privately enhancing compact Ironwood actions.
//!
//! These APIs deliberately use note-commitment-tree positions rather than
//! transaction IDs. A response is accepted only after the complete ciphertext
//! decrypts under the recorded account and reproduces the already-scanned note.

use incrementalmerkletree::Position;
use orchard::{
    Address,
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
    value::ValueCommitment,
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, try_output_recovery_with_ovk};
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};
use zip32::Scope;

use super::{Account, WalletRead};

/// Selects how ordinary transaction enhancement interacts with private Ironwood enhancement.
///
/// Applications that expose a runtime PIR setting should always compile with
/// `zakura-pir-enhance`, and update this mode when the setting changes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnhancementMode {
    /// Exposes ordinary transaction-ID enhancement requests, including for Ironwood transactions.
    #[default]
    Standard,
    /// Suppresses transaction-ID enhancement for transactions protected by Enhance PIR.
    ///
    /// Protection is transaction-wide, but only pure-Ironwood compact transactions are eligible.
    /// Mixed-pool transactions remain on standard transaction-ID enhancement. Status requests and
    /// enhancement of other, unprotected transactions remain available.
    PrivateIronwood,
}

/// One pending memo lookup, identified only by its Ironwood tree position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnhancePirRequest {
    position: Position,
}

impl EnhancePirRequest {
    /// Constructs a request for `position`.
    pub fn from_position(position: Position) -> Self {
        Self { position }
    }

    /// Returns the Ironwood commitment-tree position to query.
    pub fn position(&self) -> Position {
        self.position
    }
}

/// Stable chain identity for an Ironwood action queued for private enhancement.
///
/// Tree positions may be reused after a reorg, so completion must compare this
/// identity in addition to the queried position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IronwoodEnhanceRequestId {
    txid: TxId,
    output_index: u32,
}

impl IronwoodEnhanceRequestId {
    /// Constructs an action identity.
    pub fn new(txid: TxId, output_index: u32) -> Self {
        Self { txid, output_index }
    }

    /// Returns the transaction containing the action.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// Returns the action index within the transaction's Ironwood bundle.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }
}

/// The complete encrypted-note fields stored in one Enhance PIR record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodEnhanceRecord {
    ephemeral_key: [u8; 32],
    ciphertext: [u8; 580],
    cv_net: [u8; 32],
    out_ciphertext: [u8; 80],
}

impl IronwoodEnhanceRecord {
    /// Constructs a record from the fields of an Ironwood encrypted note.
    pub fn from_parts(
        ephemeral_key: [u8; 32],
        ciphertext: [u8; 580],
        cv_net: [u8; 32],
        out_ciphertext: [u8; 80],
    ) -> Self {
        Self {
            ephemeral_key,
            ciphertext,
            cv_net,
            out_ciphertext,
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

    pub fn cv_net(&self) -> &[u8; 32] {
        &self.cv_net
    }

    pub fn out_ciphertext(&self) -> &[u8; 80] {
        &self.out_ciphertext
    }
}

/// Chain state to which a PIR snapshot is anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnhancePirSnapshotAnchor {
    /// Snapshot block height.
    pub height: BlockHeight,
    /// Snapshot block hash.
    pub block_hash: BlockHash,
    /// Ironwood tree size at the end of the anchor block.
    pub ironwood_tree_size: u64,
}

/// Whether a snapshot anchor is safe to use with the wallet's scanned chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirSnapshotStatus {
    /// Height and Ironwood tree size match locally scanned state.
    Accepted,
    /// The wallet has not scanned the anchor height yet.
    NotYetScanned,
    /// Local chain state disagrees with the snapshot.
    Mismatch,
}

/// Result of authenticating and applying a PIR record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirStoreResult {
    /// The authenticated memo was stored and the queue entry removed.
    Stored,
    /// No unresolved note exists at this position.
    AlreadyResolved,
    /// The record did not authenticate against the wallet's recorded note and key.
    Rejected,
}

/// Wallet state needed to authenticate a Enhance PIR response.
#[doc(hidden)]
pub struct PendingIronwoodMemo<AccountId> {
    /// Stable identity that must still match when the memo is stored.
    pub request_id: IronwoodEnhanceRequestId,
    /// Account that received the note.
    pub account_id: AccountId,
    /// Compact-scanned note whose commitment must be reproduced.
    pub note: Note,
    /// Key scope detected by compact trial decryption.
    pub scope: Scope,
}

/// Compact action and candidate senders retained for outgoing recovery.
#[doc(hidden)]
pub struct PendingIronwoodOutgoing<AccountId> {
    pub request_id: IronwoodEnhanceRequestId,
    pub account_ids: Vec<AccountId>,
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
}

/// Read interface for the independent position-keyed memo queue.
pub trait EnhancePirRead: WalletRead {
    /// Returns unresolved Ironwood memo requests in ascending position order.
    fn enhance_pir_requests(&self) -> Result<Vec<EnhancePirRequest>, Self::Error>;

    /// Compares the snapshot anchor to locally scanned chain state.
    fn enhance_pir_snapshot_status(
        &self,
        anchor: EnhancePirSnapshotAnchor,
    ) -> Result<EnhancePirSnapshotStatus, Self::Error>;

    /// Returns authentication context for an unresolved position.
    #[doc(hidden)]
    fn pending_ironwood_memo(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMemo<Self::AccountId>>, Self::Error>;

    #[doc(hidden)]
    fn pending_ironwood_outgoing(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodOutgoing<Self::AccountId>>, Self::Error>;

    /// Returns whether an Ironwood transaction is covered by transaction-wide txid protection.
    ///
    /// This is an informational API. Storage implementations must enforce the configured
    /// [`EnhancementMode`] in their ordinary transaction-data request path so that callers cannot
    /// accidentally dispatch a protected enhancement request.
    fn is_ironwood_enhancement_protected(&self, txid: TxId) -> Result<bool, Self::Error>;
}

/// Atomic storage operation used after successful response authentication.
pub trait EnhancePirWrite: EnhancePirRead {
    /// Stores a memo iff the same position is still unresolved, and removes its queue entry.
    #[doc(hidden)]
    fn put_ironwood_memo(
        &mut self,
        position: Position,
        request_id: IronwoodEnhanceRequestId,
        memo: &MemoBytes,
    ) -> Result<bool, Self::Error>;

    #[doc(hidden)]
    fn put_ironwood_sent_output(
        &mut self,
        position: Position,
        request_id: IronwoodEnhanceRequestId,
        from_account: Self::AccountId,
        recipient: Address,
        value: Zatoshis,
        memo: &MemoBytes,
    ) -> Result<bool, Self::Error>;
}

struct FullOutput<'a> {
    cmx: [u8; 32],
    record: &'a IronwoodEnhanceRecord,
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
pub fn decrypt_and_store_ironwood_memo<DbT: EnhancePirWrite>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &IronwoodEnhanceRecord,
) -> Result<EnhancePirStoreResult, DbT::Error> {
    let Some(pending) = db.pending_ironwood_memo(request.position())? else {
        return Ok(EnhancePirStoreResult::AlreadyResolved);
    };
    if pending.note.version() != NoteVersion::V3 {
        return Ok(EnhancePirStoreResult::Rejected);
    }
    let Some(account) = db.get_account(pending.account_id)? else {
        return Ok(EnhancePirStoreResult::Rejected);
    };
    let ivk = match pending.scope {
        Scope::External => account.uivk().orchard().as_ref().map(|ivk| ivk.prepare()),
        Scope::Internal => account
            .ufvk()
            .and_then(|ufvk| ufvk.orchard())
            .map(|fvk| fvk.to_ivk(Scope::Internal).prepare()),
    };
    let Some(ivk): Option<PreparedIncomingViewingKey> = ivk else {
        return Ok(EnhancePirStoreResult::Rejected);
    };

    let Some(memo) = decrypt_memo(&pending.note, &ivk, record) else {
        return Ok(EnhancePirStoreResult::Rejected);
    };

    Ok(if db.put_ironwood_memo(request.position(), pending.request_id, &memo)? {
        EnhancePirStoreResult::Stored
    } else {
        EnhancePirStoreResult::AlreadyResolved
    })
}

fn decrypt_memo(
    expected_note: &Note,
    ivk: &PreparedIncomingViewingKey,
    record: &IronwoodEnhanceRecord,
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

/// Authenticates and stores an outgoing Ironwood output recovered with a
/// funding account's external outgoing viewing key.
pub fn recover_and_store_ironwood_outgoing<DbT: EnhancePirWrite>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &IronwoodEnhanceRecord,
) -> Result<EnhancePirStoreResult, DbT::Error> {
    let Some(pending) = db.pending_ironwood_outgoing(request.position())? else {
        return Ok(EnhancePirStoreResult::AlreadyResolved);
    };
    let mut recovered = None;
    for account_id in pending.account_ids.iter().copied() {
        let Some(account) = db.get_account(account_id)? else {
            continue;
        };
        let Some(fvk) = account.ufvk().and_then(|ufvk| ufvk.orchard()) else {
            continue;
        };
        if let Some((note, recipient, memo)) = recover_outgoing(fvk, &pending, record) {
            if recovered.is_some() {
                return Ok(EnhancePirStoreResult::Rejected);
            }
            recovered = Some((account_id, note, recipient, memo));
        }
    }
    let Some((account_id, note, recipient, memo)) = recovered else {
        return Ok(EnhancePirStoreResult::Rejected);
    };
    let value = Zatoshis::from_u64(note.value().inner()).expect("note value is in range");
    let memo = MemoBytes::from_bytes(&memo).expect("note decryption returns exactly 512 bytes");
    Ok(
        if db.put_ironwood_sent_output(
            request.position(),
            pending.request_id,
            account_id,
            recipient,
            value,
            &memo,
        )? {
            EnhancePirStoreResult::Stored
        } else {
            EnhancePirStoreResult::AlreadyResolved
        },
    )
}

fn recover_outgoing<AccountId>(
    fvk: &orchard::keys::FullViewingKey,
    pending: &PendingIronwoodOutgoing<AccountId>,
    record: &IronwoodEnhanceRecord,
) -> Option<(Note, Address, [u8; 512])> {
    let nullifier = Option::from(Nullifier::from_bytes(&pending.nullifier))?;
    let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&pending.cmx))?;
    let cv_net = Option::from(ValueCommitment::from_bytes(record.cv_net()))?;
    let compact = CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(*record.ephemeral_key()),
        record.ciphertext()[..52].try_into().expect("fixed size"),
    );
    let output = FullOutput {
        cmx: pending.cmx,
        record,
    };
    try_output_recovery_with_ovk(
        &IronwoodDomain::for_compact_action(&compact),
        &fvk.to_ovk(Scope::External),
        &output,
        &cv_net,
        record.out_ciphertext(),
    )
}

#[cfg(test)]
mod tests {
    use orchard::{
        note::{Note, NoteVersion, Nullifier, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use pasta_curves::{
        group::{
            Group, GroupEncoding,
            ff::{Field, PrimeField},
        },
        pallas,
    };
    use rand::{Rng as _, rand_core::UnwrapErr, rngs::SysRng};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_note_encryption::Domain;
    use zcash_protocol::consensus::Network;

    use super::*;

    #[allow(non_upper_case_globals)]
    const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

    fn encrypted_record() -> (Note, PreparedIncomingViewingKey, IronwoodEnhanceRecord) {
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
        let record = IronwoodEnhanceRecord::from_parts(
            IronwoodDomain::epk_bytes(encryptor.epk()).0,
            encryptor.encrypt_note_plaintext(),
            [0; 32],
            [0; 80],
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
        let tampered = IronwoodEnhanceRecord::from_parts(
            *record.ephemeral_key(),
            ciphertext,
            *record.cv_net(),
            *record.out_ciphertext(),
        );
        assert!(decrypt_memo(&note, &ivk, &tampered).is_none());

        let (_, _, another_note_record) = encrypted_record();
        assert!(decrypt_memo(&note, &ivk, &another_note_record).is_none());
    }

    #[test]
    fn recovers_outgoing_fields_with_the_sender_ovk() {
        let usk =
            UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[9; 32], zip32::AccountId::ZERO)
                .unwrap();
        let fvk = usk.to_unified_full_viewing_key().orchard().unwrap().clone();
        let mut rng = OsRng;
        let nf = Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr()).unwrap();
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let rseed = loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            if let Some(rseed) = Option::from(RandomSeed::from_bytes(bytes, &rho)) {
                break rseed;
            }
        };
        let note = Note::from_parts(
            fvk.address_at(3u32, Scope::External),
            NoteValue::from_raw(123),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let encryptor =
            IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::External)), note, [4; 512]);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let cv_net = ValueCommitment::from_bytes(&pallas::Point::generator().to_bytes()).unwrap();
        let mut outgoing_rng = ChaCha20Rng::from_seed([7; 32]);
        let record = IronwoodEnhanceRecord::from_parts(
            IronwoodDomain::epk_bytes(encryptor.epk()).0,
            encryptor.encrypt_note_plaintext(),
            cv_net.to_bytes(),
            encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut outgoing_rng),
        );
        let pending = PendingIronwoodOutgoing {
            request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0),
            account_ids: vec![()],
            nullifier: nf.to_bytes(),
            cmx: cmx.to_bytes(),
        };

        let (recovered_note, recipient, memo) = recover_outgoing(&fvk, &pending, &record).unwrap();
        assert_eq!(recovered_note, note);
        assert_eq!(recipient, note.recipient());
        assert_eq!(memo, [4; 512]);

        let wrong_fvk =
            UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[8; 32], zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key()
                .orchard()
                .unwrap()
                .clone();
        assert!(recover_outgoing(&wrong_fvk, &pending, &record).is_none());
    }
}
