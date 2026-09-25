//! Storage implementation contracts for action-bound record validation.
//!
//! Implement this trait on a transaction-scoped adapter, not an application wallet handle.
//! Hold a consistent storage transaction across context reads, validation, and commit.
//! Applications call `EnhancePirWrite::apply_ironwood_enhance_record` instead.

use super::{
    EnhancePirRequest, EnhancePirStoreResult, EnhanceRecord, EnhanceTransactionMetadata,
    IronwoodEnhanceRequestId,
};
use crate::data_api::Account;
use incrementalmerkletree::Position;
use orchard::{
    Address,
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
    value::ValueCommitment,
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, try_output_recovery_with_ovk};
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};
use zip32::Scope;
/// Wallet state needed to authenticate a Enhance PIR response.
pub struct PendingIronwoodMemo<AccountId> {
    /// Stable identity that must still match when the memo is stored.
    pub request_id: IronwoodEnhanceRequestId,
    /// Account that received the note.
    pub account_id: AccountId,
    /// Compact-scanned note whose commitment must be reproduced.
    pub note: Note,
    /// Key scope detected by compact trial decryption.
    pub scope: Scope,
    /// Storage-resolved incoming key for a registered receiving key. It must belong
    /// to `account_id` and reconstruct `note`. Use `None` only for ordinary account
    /// keys. A missing or unsupported registration must return a storage error.
    pub receiving_ivk: Option<PreparedIncomingViewingKey>,
    /// Ephemeral key retained from the trusted compact scan.
    pub ephemeral_key: [u8; 32],
    /// First 52 ciphertext bytes retained from the same compact action.
    pub compact_ciphertext: [u8; 52],
}

impl<AccountId> PendingIronwoodMemo<AccountId> {
    fn incoming_key(&self, account: &impl Account) -> Option<PreparedIncomingViewingKey> {
        self.receiving_ivk.clone().or_else(|| match self.scope {
            Scope::External => account.uivk().orchard().as_ref().map(|ivk| ivk.prepare()),
            Scope::Internal => account
                .ufvk()
                .and_then(|key| key.orchard())
                .map(|fvk| fvk.to_ivk(Scope::Internal).prepare()),
        })
    }
}

/// Compact action and candidate senders retained for outgoing recovery.
pub struct PendingIronwoodOutgoing<AccountId> {
    pub request_id: IronwoodEnhanceRequestId,
    pub account_ids: Vec<AccountId>,
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub compact_ciphertext: [u8; 52],
}

/// Binding context for transaction metadata, independent of memo/OVK completion.
pub enum PendingIronwoodMetadata<AccountId> {
    Incoming(PendingIronwoodMemo<AccountId>),
    Compact(PendingIronwoodOutgoing<AccountId>),
}

impl<AccountId> PendingIronwoodMetadata<AccountId> {
    fn request_id(&self) -> IronwoodEnhanceRequestId {
        match self {
            Self::Incoming(p) => p.request_id,
            Self::Compact(p) => p.request_id,
        }
    }
}

/// Outgoing result carried inside a validated, action-bound application.
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
    /// The request identity matches, but outgoing recovery did not succeed.
    NotRecoverable,
}

/// Transaction-wide metadata already known to storage.
///
/// Each field is independently optional; `Some(0)` is known, not missing.
/// PIR enhancement treats every proposed expiry as untrusted for
/// persistence: see [`StoredIronwoodMetadata::filled_from`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoredIronwoodMetadata {
    /// Known transaction fee in zatoshis.
    pub fee_zatoshis: Option<u64>,
    /// Known expiry height, including zero for no expiry when authenticated
    /// (for example from raw transaction bytes). PIR responses do not persist
    /// a proposed expiry in this authoritative field; storage may retain a separate
    /// display-only assertion for history.
    pub expiry_height: Option<u32>,
}

impl StoredIronwoodMetadata {
    /// Whether a private response supplies a fee and agrees with every known field.
    pub fn agrees_with(self, proposed: EnhanceTransactionMetadata) -> bool {
        proposed.fee_zatoshis().is_some()
            && self
                .fee_zatoshis
                .is_none_or(|fee| Some(fee) == proposed.fee_zatoshis())
            && self
                .expiry_height
                .is_none_or(|expiry| expiry == proposed.expiry_height())
    }

    /// Fills an unknown fee from a private PIR response, preserving known expiry.
    ///
    /// Callers must first check [`Self::agrees_with`]; this helper does not validate
    /// the response. PIR expiry is not authenticated by note decryption, so it must
    /// never become authoritative for spendability. Both zero ("never expires") and
    /// a far-future height could otherwise pin spent notes after a reorg.
    pub fn filled_from(self, proposed: EnhanceTransactionMetadata) -> Self {
        Self {
            fee_zatoshis: self.fee_zatoshis.or(proposed.fee_zatoshis()),
            expiry_height: self.expiry_height,
        }
    }
}

/// One validated response, with a private constructor to protect the write boundary.
///
/// All fields, including the routing decision, must be applied in one storage
/// transaction after rechecking the captured position and action identity.
/// Transparent metadata and send-only server association are trusted. The request
/// identity must match pending wallet state before metadata can change routing.
pub struct ValidatedIronwoodEnhancement<AccountId> {
    request: EnhancePirRequest,
    has_transparent: bool,
    metadata: EnhanceTransactionMetadata,
    expected_metadata: Option<StoredIronwoodMetadata>,
    incoming: Option<MemoBytes>,
    outgoing: IronwoodOutgoingResult<AccountId>,
}

/// Fields of a validated response; commit them together after identity rechecks.
pub struct IronwoodEnhancementData<AccountId> {
    pub request: EnhancePirRequest,
    pub has_transparent: bool,
    pub metadata: EnhanceTransactionMetadata,
    /// Snapshot to compare atomically before filling unknown metadata fields.
    /// `None` occurs only for transparent responses, whose metadata must not be stored.
    pub expected_metadata: Option<StoredIronwoodMetadata>,
    pub incoming: Option<MemoBytes>,
    pub outgoing: IronwoodOutgoingResult<AccountId>,
}

impl<AccountId> ValidatedIronwoodEnhancement<AccountId> {
    /// Unpacks all validated fields, including transaction metadata, for atomic storage.
    pub fn into_parts(self) -> IronwoodEnhancementData<AccountId> {
        IronwoodEnhancementData {
            request: self.request,
            has_transparent: self.has_transparent,
            metadata: self.metadata,
            expected_metadata: self.expected_metadata,
            incoming: self.incoming,
            outgoing: self.outgoing,
        }
    }

    /// Bypasses validation for storage tests only.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn for_testing(
        request: EnhancePirRequest,
        has_transparent: bool,
        incoming: Option<MemoBytes>,
        outgoing: IronwoodOutgoingResult<AccountId>,
        expected_metadata: Option<StoredIronwoodMetadata>,
    ) -> Self {
        Self {
            request,
            has_transparent,
            metadata: EnhanceTransactionMetadata::new(0, Some(0)).expect("test metadata"),
            expected_metadata,
            incoming,
            outgoing,
        }
    }
}

/// Transaction-scoped context and commit operations used by shared validation.
///
/// Commit must recheck captured identities and apply all note, queue, and routing changes
/// atomically, including the metadata comparison and fill. Known metadata is immutable under
/// PIR enhancement. A stale response must not change routing, even when it reports transparent data.
pub trait EnhancePirStorage {
    type AccountId: Copy;
    type Account: Account<AccountId = Self::AccountId>;
    type Error;

    /// Reads existing fee and expiry in the same transaction as pending action context.
    /// Returns `None` if the transaction no longer exists; unknown fields are represented
    /// by `Some(StoredIronwoodMetadata { fee_zatoshis: None, expiry_height: None })`.
    fn ironwood_transaction_metadata(
        &self,
        txid: zcash_primitives::transaction::TxId,
    ) -> Result<Option<StoredIronwoodMetadata>, Self::Error>;

    /// Loads durable metadata-only work from the same transaction snapshot.
    fn pending_ironwood_metadata(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMetadata<Self::AccountId>>, Self::Error>;

    /// Loads viewing keys from the same storage snapshot as the pending context.
    fn get_account(&self, id: Self::AccountId) -> Result<Option<Self::Account>, Self::Error>;
    /// Returns authentication context for an unresolved position.
    fn pending_ironwood_memo(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMemo<Self::AccountId>>, Self::Error>;

    /// Returns active outgoing recovery context, excluding suspended or completed work.
    fn pending_ironwood_outgoing(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodOutgoing<Self::AccountId>>, Self::Error>;

    /// Compares captured state and commits all response effects in one atomic operation.
    ///
    /// Recheck transaction/action identities first; stale or resolved work returns
    /// `AlreadyResolved` without mutation. For a private response, the current fee/expiry
    /// must exactly match `expected_metadata`, and agree with the supplied metadata.
    /// A missing snapshot or any disagreement returns `Rejected` without changing metadata,
    /// notes, routing, or queues. Fill only an unknown fee; known zero values are immutable.
    /// Do not persist any proposed expiry as authoritative transaction expiry:
    /// preserve the existing expiry so unauthenticated metadata cannot pin
    /// spendability across a reorg. A separate history-only assertion is allowed.
    /// The comparison, fills, and all action/queue writes must share a transaction; a write
    /// error must roll back every effect. Do not perform a separate metadata commit.
    ///
    /// For an action-bound transparent response, retain the LWD routing behavior and do
    /// not compare or store its fee/expiry. Its `expected_metadata` is `None`.
    fn compare_and_apply_ironwood_enhancement(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<Self::AccountId>,
    ) -> Result<EnhancePirStoreResult, Self::Error>;
}

struct FullOutput {
    cmx: [u8; 32],
    ephemeral_key: [u8; 32],
    enc_ciphertext: [u8; 580],
}

fn stitched_enc_ciphertext(prefix: &[u8; 52], record: &EnhanceRecord) -> [u8; 580] {
    let mut ciphertext = [0; 580];
    ciphertext[..52].copy_from_slice(prefix);
    ciphertext[52..].copy_from_slice(record.enc_ciphertext_suffix());
    ciphertext
}

impl ShieldedOutput<IronwoodDomain, 580> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }

    fn enc_ciphertext(&self) -> &[u8; 580] {
        &self.enc_ciphertext
    }
}

/// Validates one record and atomically applies all work captured by `request`.
///
/// Incoming ciphertext must decrypt to the scanned note. Send-only association
/// is trusted when outgoing decryption cannot authenticate the action. Incoming
/// authentication failures never cause public fallback. Identity checks precede
/// even a transparent-flag decision.
/// Private responses must agree with known transaction metadata; the captured snapshot
/// accompanies the response so the backend can reject a change before committing.
/// A rejected response leaves its work pending for validation against fresh context.
pub fn validate_and_apply_record<DbT: EnhancePirStorage>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &EnhanceRecord,
) -> Result<EnhancePirStoreResult, DbT::Error> {
    match validate_record(db, request, record)? {
        Ok(validated) => db.compare_and_apply_ironwood_enhancement(validated),
        Err(result) => Ok(result),
    }
}

/// Validates all live actions before committing any of them. The caller MUST roll
/// back its enclosing storage transaction on `Rejected` as well as on errors.
/// Identical requests are processed once; stale identities never supply metadata.
pub fn validate_and_apply_records<DbT: EnhancePirStorage>(
    db: &mut DbT,
    records: &[(EnhancePirRequest, EnhanceRecord)],
) -> Result<super::EnhancePirBatchResult, DbT::Error> {
    use super::{EnhancePirBatchRejection as Reason, EnhancePirBatchResult as Batch};
    let reject = |index, reason| Batch::Rejected { index, reason };
    let Some((first, _)) = records.first() else {
        return Ok(reject(None, Reason::Empty));
    };
    let mut unique = std::collections::BTreeMap::<(u64, u32), usize>::new();
    let mut aliases = Vec::new();
    let mut validated = Vec::new();
    let mut results = vec![EnhancePirStoreResult::AlreadyResolved; records.len()];
    let mut metadata = None;
    for (index, (request, record)) in records.iter().enumerate() {
        if request.request_id().txid() != first.request_id().txid() {
            return Ok(reject(Some(index), Reason::MixedTxid));
        }
        let key = (
            u64::from(request.position()),
            request.request_id().output_index(),
        );
        if let Some(&previous) = unique.get(&key) {
            if records[previous].1 != *record {
                return Ok(reject(Some(index), Reason::ConflictingDuplicate));
            }
            aliases.push((index, previous));
            continue;
        }
        unique.insert(key, index);
        match validate_record(db, *request, record)? {
            Err(EnhancePirStoreResult::AlreadyResolved) => {}
            Err(_) => return Ok(reject(Some(index), Reason::RecordRejected)),
            Ok(value) => {
                let proposed = (record.transparent_flags(), record.metadata());
                if metadata.is_some_and(|known| known != proposed) {
                    return Ok(reject(Some(index), Reason::MetadataConflict));
                }
                metadata = Some(proposed);
                validated.push((index, value));
            }
        }
    }
    let mut routed = false;
    for (index, mut value) in validated {
        if routed {
            results[index] = EnhancePirStoreResult::LwdRequired;
            continue;
        }
        // Earlier actions may have filled the same transaction's unknown fee.
        // The entire operation holds one storage transaction throughout.
        if !value.has_transparent {
            value.expected_metadata =
                db.ironwood_transaction_metadata(value.request.request_id().txid())?;
        }
        let result = db.compare_and_apply_ironwood_enhancement(value)?;
        if result == EnhancePirStoreResult::Rejected {
            return Ok(reject(Some(index), Reason::RecordRejected));
        }
        routed = result == EnhancePirStoreResult::LwdRequired;
        results[index] = result;
    }
    for (index, previous) in aliases {
        results[index] = results[previous];
    }
    Ok(Batch::Committed(results))
}

fn validate_record<DbT: EnhancePirStorage>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &EnhanceRecord,
) -> Result<Result<ValidatedIronwoodEnhancement<DbT::AccountId>, EnhancePirStoreResult>, DbT::Error>
{
    let metadata = db.pending_ironwood_metadata(request.position())?;
    let incoming = db.pending_ironwood_memo(request.position())?;
    let outgoing = db.pending_ironwood_outgoing(request.position())?;
    if (incoming.is_none() && outgoing.is_none() && metadata.is_none())
        || metadata
            .as_ref()
            .is_some_and(|p| p.request_id() != request.request_id())
        || incoming
            .as_ref()
            .is_some_and(|p| p.request_id != request.request_id())
        || outgoing
            .as_ref()
            .is_some_and(|p| p.request_id != request.request_id())
    {
        return Ok(Err(EnhancePirStoreResult::AlreadyResolved));
    }

    if let Some(binding) = metadata {
        let valid = match binding {
            PendingIronwoodMetadata::Incoming(pending) => {
                let account = db.get_account(pending.account_id)?;
                let ivk = account
                    .as_ref()
                    .and_then(|account| pending.incoming_key(account));
                pending.note.version() == NoteVersion::V3
                    && ivk
                        .and_then(|ivk| decrypt_memo(&pending, &ivk, record))
                        .is_some()
            }
            // The server's position association is trusted for send-only metadata.
            // No local decryption can authenticate an unrecoverable output.
            PendingIronwoodMetadata::Compact(_) => true,
        };
        if !valid {
            return Ok(Err(EnhancePirStoreResult::Rejected));
        }
    }
    if !record.has_transparent() && record.metadata().fee_zatoshis().is_none() {
        return Ok(Err(EnhancePirStoreResult::Rejected));
    }

    let memo = if let Some(pending) = incoming {
        if pending.note.version() != NoteVersion::V3 {
            return Ok(Err(EnhancePirStoreResult::Rejected));
        }
        let Some(account) = db.get_account(pending.account_id)? else {
            return Ok(Err(EnhancePirStoreResult::Rejected));
        };
        let ivk = pending.incoming_key(&account);
        let Some(memo) = ivk.and_then(|ivk| decrypt_memo(&pending, &ivk, record)) else {
            return Ok(Err(EnhancePirStoreResult::Rejected));
        };
        Some(memo)
    } else {
        None
    };

    let outgoing = if let Some(pending) = outgoing {
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
                        return Ok(Err(EnhancePirStoreResult::Rejected));
                    }
                    let Ok(value) = Zatoshis::from_u64(note.value().inner()) else {
                        return Ok(Err(EnhancePirStoreResult::Rejected));
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

    let expected_metadata = if record.has_transparent() {
        None
    } else {
        let Some(known) = db.ironwood_transaction_metadata(request.request_id().txid())? else {
            return Ok(Err(EnhancePirStoreResult::AlreadyResolved));
        };
        if !known.agrees_with(record.metadata()) {
            return Ok(Err(EnhancePirStoreResult::Rejected));
        }
        Some(known)
    };

    Ok(Ok(ValidatedIronwoodEnhancement {
        request,
        has_transparent: record.has_transparent(),
        metadata: record.metadata(),
        expected_metadata,
        incoming: memo,
        outgoing,
    }))
}

fn decrypt_memo<AccountId>(
    pending: &PendingIronwoodMemo<AccountId>,
    ivk: &PreparedIncomingViewingKey,
    record: &EnhanceRecord,
) -> Option<MemoBytes> {
    let expected_note = &pending.note;
    let nullifier = Nullifier::from_bytes(&expected_note.rho().to_bytes());
    let nullifier = Option::from(nullifier)?;
    let cmx = ExtractedNoteCommitment::from(expected_note.commitment());
    let compact = CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(pending.ephemeral_key),
        pending.compact_ciphertext,
    );
    let output = FullOutput {
        cmx: cmx.to_bytes(),
        ephemeral_key: pending.ephemeral_key,
        enc_ciphertext: stitched_enc_ciphertext(&pending.compact_ciphertext, record),
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

fn recover_outgoing<AccountId>(
    fvk: &orchard::keys::FullViewingKey,
    pending: &PendingIronwoodOutgoing<AccountId>,
    record: &EnhanceRecord,
) -> Option<(Note, Address, [u8; 512])> {
    let nullifier = Option::from(Nullifier::from_bytes(&pending.nullifier))?;
    let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&pending.cmx))?;
    let cv_net = Option::from(ValueCommitment::from_bytes(record.cv_net()))?;
    let compact = CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(pending.ephemeral_key),
        pending.compact_ciphertext,
    );
    let output = FullOutput {
        cmx: pending.cmx,
        ephemeral_key: pending.ephemeral_key,
        enc_ciphertext: stitched_enc_ciphertext(&pending.compact_ciphertext, record),
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
    use crate::data_api::enhance_pir::EnhanceRecordParts;
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
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::consensus::Network;

    use super::*;

    #[allow(non_upper_case_globals)]
    const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

    fn encrypted_record() -> (
        PendingIronwoodMemo<()>,
        PreparedIncomingViewingKey,
        EnhanceRecord,
    ) {
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
        let record = EnhanceRecord::from_parts(EnhanceRecordParts {
            enc_ciphertext_suffix: (encryptor.encrypt_note_plaintext())[52..]
                .try_into()
                .unwrap(),
            cv_net: [0; 32],
            out_ciphertext: [0; 80],
            has_transparent_inputs: false,
            has_transparent_outputs: false,
            metadata: crate::data_api::enhance_pir::EnhanceTransactionMetadata::new(0, Some(0))
                .unwrap(),
        });
        let pending = PendingIronwoodMemo {
            request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0),
            account_id: (),
            note,
            scope: Scope::External,
            receiving_ivk: None,
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            compact_ciphertext: encryptor.encrypt_note_plaintext()[..52].try_into().unwrap(),
        };
        (pending, fvk.to_ivk(Scope::External).prepare(), record)
    }

    #[test]
    fn accepts_authentic_ciphertext_and_rejects_tampering() {
        let (mut note, ivk, record) = encrypted_record();
        assert_eq!(
            decrypt_memo(&note, &ivk, &record).unwrap().as_slice(),
            &[7; 512]
        );

        let mut ciphertext = *record.enc_ciphertext_suffix();
        ciphertext[527] ^= 1;
        let tampered = EnhanceRecord::from_parts(EnhanceRecordParts {
            enc_ciphertext_suffix: ciphertext,
            cv_net: *record.cv_net(),
            out_ciphertext: *record.out_ciphertext(),
            has_transparent_inputs: false,
            has_transparent_outputs: false,
            metadata: crate::data_api::enhance_pir::EnhanceTransactionMetadata::new(0, Some(0))
                .unwrap(),
        });
        assert!(decrypt_memo(&note, &ivk, &tampered).is_none());

        note.compact_ciphertext[0] ^= 1;
        assert!(decrypt_memo(&note, &ivk, &record).is_none());
        note.compact_ciphertext[0] ^= 1;
        note.ephemeral_key[0] ^= 1;
        assert!(decrypt_memo(&note, &ivk, &record).is_none());
        note.ephemeral_key[0] ^= 1;

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
        let record = EnhanceRecord::from_parts(EnhanceRecordParts {
            enc_ciphertext_suffix: (encryptor.encrypt_note_plaintext())[52..]
                .try_into()
                .unwrap(),
            cv_net: cv_net.to_bytes(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut outgoing_rng),
            has_transparent_inputs: false,
            has_transparent_outputs: false,
            metadata: crate::data_api::enhance_pir::EnhanceTransactionMetadata::new(0, Some(0))
                .unwrap(),
        });
        let pending = PendingIronwoodOutgoing {
            request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0),
            account_ids: vec![()],
            nullifier: nf.to_bytes(),
            cmx: cmx.to_bytes(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            compact_ciphertext: encryptor.encrypt_note_plaintext()[..52].try_into().unwrap(),
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

        let mut bad_pending = pending;
        bad_pending.ephemeral_key[0] ^= 1;
        assert!(recover_outgoing(&fvk, &bad_pending, &record).is_none());
        bad_pending.ephemeral_key[0] ^= 1;
        bad_pending.compact_ciphertext[0] ^= 1;
        assert!(recover_outgoing(&fvk, &bad_pending, &record).is_none());
    }
}
