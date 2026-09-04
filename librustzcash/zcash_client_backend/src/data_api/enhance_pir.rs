//! Storage-neutral APIs for privately enhancing compact Ironwood actions.
//!
//! Network lookups use tree positions; transaction/action identities stay local to
//! reject stale responses after reorgs. Note plaintext is authenticated, but schema
//! v6 transparent-presence flags are trusted server metadata, not cryptographic evidence.

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
    ///
    /// A positive transparent-presence flag routes the whole transaction to LWD.
    /// Errors never trigger fallback. Disabling this mode exposes outstanding ordinary
    /// enhancement requests, including work suspended after outgoing non-recovery.
    PrivateIronwood,
}

/// A position-keyed lookup with a local identity that must not be sent to the PIR server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnhancePirRequest {
    position: Position,
    request_id: IronwoodEnhanceRequestId,
}

impl EnhancePirRequest {
    /// Captures the action identity when work is queued, before network I/O.
    pub fn new(position: Position, request_id: IronwoodEnhanceRequestId) -> Self {
        Self {
            position,
            request_id,
        }
    }

    /// Returns the local transaction/action identity.
    pub fn request_id(&self) -> IronwoodEnhanceRequestId {
        self.request_id
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
    has_transparent_inputs: bool,
    has_transparent_outputs: bool,
}

impl IronwoodEnhanceRecord {
    /// Constructs a record from the fields of an Ironwood encrypted note.
    pub fn from_parts(
        ephemeral_key: [u8; 32],
        ciphertext: [u8; 580],
        cv_net: [u8; 32],
        out_ciphertext: [u8; 80],
        has_transparent_inputs: bool,
        has_transparent_outputs: bool,
    ) -> Self {
        Self {
            ephemeral_key,
            ciphertext,
            cv_net,
            out_ciphertext,
            has_transparent_inputs,
            has_transparent_outputs,
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

    /// Returns the value commitment used for outgoing recovery.
    pub fn cv_net(&self) -> &[u8; 32] {
        &self.cv_net
    }

    /// Returns the outgoing ciphertext.
    pub fn out_ciphertext(&self) -> &[u8; 80] {
        &self.out_ciphertext
    }

    /// Whether either trusted schema-v6 flag reports transparent activity.
    ///
    /// These bits are not authenticated by note decryption.
    pub fn has_transparent(&self) -> bool {
        self.has_transparent_inputs || self.has_transparent_outputs
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

/// Result of validating and atomically applying one response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnhancePirStoreResult {
    /// All requested incoming/outgoing data at this action was stored.
    Stored,
    /// The request no longer matches pending work; nothing was changed.
    AlreadyResolved,
    /// Outgoing recovery failed. The row is suspended, not completed; the
    /// ordinary fallback remains withheld until private mode is disabled.
    NotRecoverable,
    /// The whole transaction now requires ordinary LWD enhancement.
    LwdRequired,
    /// Authentication or action binding failed; nothing was changed.
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
    pub ephemeral_key: [u8; 32],
    pub compact_ciphertext: [u8; 52],
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

/// Outgoing result carried inside a validated, action-bound application.
#[doc(hidden)]
pub enum IronwoodOutgoingResult<AccountId> {
    /// No outgoing work was queued at this action.
    NotRequested,
    /// An outgoing plaintext was recovered with exactly one candidate account.
    Recovered {
        from_account: AccountId,
        recipient: Address,
        value: Zatoshis,
        memo: MemoBytes,
    },
    /// Compact fields match, but outgoing recovery did not succeed.
    NotRecoverable,
}

/// One validated response, with a private constructor to protect the write boundary.
///
/// All fields, including the routing decision, must be applied in one storage
/// transaction after rechecking the captured position and action identity.
/// Transparent metadata is trusted, not authenticated; the *record* must still
/// be bound to pending wallet state before its metadata can change routing.
#[doc(hidden)]
pub struct ValidatedIronwoodEnhancement<AccountId> {
    request: EnhancePirRequest,
    has_transparent: bool,
    incoming: Option<MemoBytes>,
    outgoing: IronwoodOutgoingResult<AccountId>,
}

impl<AccountId> ValidatedIronwoodEnhancement<AccountId> {
    /// Unpacks a validated response for a storage implementation.
    pub fn into_parts(
        self,
    ) -> (
        EnhancePirRequest,
        bool,
        Option<MemoBytes>,
        IronwoodOutgoingResult<AccountId>,
    ) {
        (
            self.request,
            self.has_transparent,
            self.incoming,
            self.outgoing,
        )
    }

    /// Bypasses validation for storage tests only.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn for_testing(
        request: EnhancePirRequest,
        has_transparent: bool,
        incoming: Option<MemoBytes>,
        outgoing: IronwoodOutgoingResult<AccountId>,
    ) -> Self {
        Self {
            request,
            has_transparent,
            incoming,
            outgoing,
        }
    }
}

/// Atomic storage boundary for an action-bound response.
pub trait EnhancePirWrite: EnhancePirRead {
    /// Rechecks every expected queue identity and applies incoming data, outgoing
    /// recovery, and routing together, or changes nothing.
    ///
    /// Positive transparent flags set a sticky transaction-wide LWD decision,
    /// clear private work, and preserve ordinary enhancement. False flags can
    /// never undo it. A stale response cannot change routing or note data.
    fn apply_ironwood_enhancement(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<Self::AccountId>,
    ) -> Result<EnhancePirStoreResult, Self::Error>;
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

/// Validates one record and atomically applies all work captured by `request`.
///
/// Incoming ciphertext must decrypt to the scanned note; outgoing records must
/// match the scanned compact fields. Authentication/transport failures never
/// cause public fallback. Identity checks precede even a transparent-flag decision.
pub fn apply_ironwood_enhance_record<DbT: EnhancePirWrite>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &IronwoodEnhanceRecord,
) -> Result<EnhancePirStoreResult, DbT::Error> {
    let incoming = db.pending_ironwood_memo(request.position())?;
    let outgoing = db.pending_ironwood_outgoing(request.position())?;
    if (incoming.is_none() && outgoing.is_none())
        || incoming
            .as_ref()
            .is_some_and(|p| p.request_id != request.request_id())
        || outgoing
            .as_ref()
            .is_some_and(|p| p.request_id != request.request_id())
    {
        return Ok(EnhancePirStoreResult::AlreadyResolved);
    }

    let memo = if let Some(pending) = incoming {
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
                .and_then(|k| k.orchard())
                .map(|fvk| fvk.to_ivk(Scope::Internal).prepare()),
        };
        let Some(memo) = ivk.and_then(|ivk| decrypt_memo(&pending.note, &ivk, record)) else {
            return Ok(EnhancePirStoreResult::Rejected);
        };
        Some(memo)
    } else {
        None
    };

    let outgoing = if let Some(pending) = outgoing {
        if !record_matches_compact_action(&pending, record) {
            return Ok(EnhancePirStoreResult::Rejected);
        }
        // Mixed transactions need full data, not private outgoing recovery.
        // This variant records the expected queue; it is never written when
        // has_transparent is true.
        let mut recovered = None;
        if !record.has_transparent() {
            for account_id in pending.account_ids.iter().copied() {
                let Some(account) = db.get_account(account_id)? else {
                    continue;
                };
                let Some(fvk) = account.ufvk().and_then(|k| k.orchard()) else {
                    continue;
                };
                if let Some((note, recipient, memo)) = recover_outgoing(fvk, &pending, record) {
                    if recovered.is_some() {
                        return Ok(EnhancePirStoreResult::Rejected);
                    }
                    let Ok(value) = Zatoshis::from_u64(note.value().inner()) else {
                        return Ok(EnhancePirStoreResult::Rejected);
                    };
                    recovered = Some(IronwoodOutgoingResult::Recovered {
                        from_account: account_id,
                        recipient,
                        value,
                        memo: MemoBytes::from_bytes(&memo).expect("512-byte memo"),
                    });
                }
            }
        }
        recovered.unwrap_or(IronwoodOutgoingResult::NotRecoverable)
    } else {
        IronwoodOutgoingResult::NotRequested
    };

    db.apply_ironwood_enhancement(ValidatedIronwoodEnhancement {
        request,
        has_transparent: record.has_transparent(),
        incoming: memo,
        outgoing,
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

fn record_matches_compact_action<AccountId>(
    pending: &PendingIronwoodOutgoing<AccountId>,
    record: &IronwoodEnhanceRecord,
) -> bool {
    pending.ephemeral_key == *record.ephemeral_key()
        && pending.compact_ciphertext == record.ciphertext()[..52]
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
            false,
            false,
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
            false,
            false,
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
            false,
            false,
        );
        let pending = PendingIronwoodOutgoing {
            request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0),
            account_ids: vec![()],
            nullifier: nf.to_bytes(),
            cmx: cmx.to_bytes(),
            ephemeral_key: *record.ephemeral_key(),
            compact_ciphertext: record.ciphertext()[..52].try_into().unwrap(),
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

        assert!(record_matches_compact_action(&pending, &record));
        let mut wrong_ephemeral_key = *record.ephemeral_key();
        wrong_ephemeral_key[0] ^= 1;
        let wrong_ephemeral_key_record = IronwoodEnhanceRecord::from_parts(
            wrong_ephemeral_key,
            *record.ciphertext(),
            *record.cv_net(),
            *record.out_ciphertext(),
            false,
            false,
        );
        assert!(!record_matches_compact_action(
            &pending,
            &wrong_ephemeral_key_record
        ));

        let mut wrong_compact_ciphertext = *record.ciphertext();
        wrong_compact_ciphertext[0] ^= 1;
        let wrong_compact_ciphertext_record = IronwoodEnhanceRecord::from_parts(
            *record.ephemeral_key(),
            wrong_compact_ciphertext,
            *record.cv_net(),
            *record.out_ciphertext(),
            false,
            false,
        );
        assert!(!record_matches_compact_action(
            &pending,
            &wrong_compact_ciphertext_record
        ));
    }
}
