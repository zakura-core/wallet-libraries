//! Storage implementation contracts for action-bound record validation.
//!
//! Implement this trait on a transaction-scoped adapter, not an application wallet handle.
//! Hold a consistent storage transaction across context reads, validation, and commit.
//! Applications call `EnhancePirWrite::apply_ironwood_enhance_record` instead.

use super::{EnhancePirRequest, EnhancePirStoreResult, EnhanceRecord, IronwoodEnhanceRequestId};
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
    /// Compact fields match, but outgoing recovery did not succeed.
    NotRecoverable,
}

/// One validated response, with a private constructor to protect the write boundary.
///
/// All fields, including the routing decision, must be applied in one storage
/// transaction after rechecking the captured position and action identity.
/// Transparent metadata is trusted, not authenticated; the *record* must still
/// be bound to pending wallet state before its metadata can change routing.
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

/// Transaction-scoped context and commit operations used by shared validation.
///
/// Commit must recheck captured identities and apply all note, queue, and routing changes
/// atomically. A stale response must not change routing, even when it reports transparent data.
pub trait EnhancePirStorage {
    type AccountId: Copy;
    type Account: Account<AccountId = Self::AccountId>;
    type Error;

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

    /// Rechecks captured queue identities and commits note data and routing atomically.
    fn apply_ironwood_enhancement(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<Self::AccountId>,
    ) -> Result<EnhancePirStoreResult, Self::Error>;
}

struct FullOutput<'a> {
    cmx: [u8; 32],
    record: &'a EnhanceRecord,
}

impl ShieldedOutput<IronwoodDomain, 580> for FullOutput<'_> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(*self.record.ephemeral_key())
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }

    fn enc_ciphertext(&self) -> &[u8; 580] {
        self.record.enc_ciphertext()
    }
}

/// Validates one record and atomically applies all work captured by `request`.
///
/// Incoming ciphertext must decrypt to the scanned note; outgoing records must
/// match the scanned compact fields. Authentication/transport failures never
/// cause public fallback. Identity checks precede even a transparent-flag decision.
pub fn validate_and_apply_record<DbT: EnhancePirStorage>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &EnhanceRecord,
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
    record: &EnhanceRecord,
) -> Option<MemoBytes> {
    let nullifier = Nullifier::from_bytes(&expected_note.rho().to_bytes());
    let nullifier = Option::from(nullifier)?;
    let cmx = ExtractedNoteCommitment::from(expected_note.commitment());
    let compact = CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(*record.ephemeral_key()),
        record.enc_ciphertext()[..52]
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
    record: &EnhanceRecord,
) -> bool {
    pending.ephemeral_key == *record.ephemeral_key()
        && pending.compact_ciphertext == record.enc_ciphertext()[..52]
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
        EphemeralKeyBytes(*record.ephemeral_key()),
        record.enc_ciphertext()[..52]
            .try_into()
            .expect("fixed size"),
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

    fn encrypted_record() -> (Note, PreparedIncomingViewingKey, EnhanceRecord) {
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
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            cv_net: [0; 32],
            out_ciphertext: [0; 80],
            has_transparent_inputs: false,
            has_transparent_outputs: false,
        });
        (note, fvk.to_ivk(Scope::External).prepare(), record)
    }

    #[test]
    fn accepts_authentic_ciphertext_and_rejects_tampering() {
        let (note, ivk, record) = encrypted_record();
        assert_eq!(
            decrypt_memo(&note, &ivk, &record).unwrap().as_slice(),
            &[7; 512]
        );

        let mut ciphertext = *record.enc_ciphertext();
        ciphertext[579] ^= 1;
        let tampered = EnhanceRecord::from_parts(EnhanceRecordParts {
            ephemeral_key: *record.ephemeral_key(),
            enc_ciphertext: ciphertext,
            cv_net: *record.cv_net(),
            out_ciphertext: *record.out_ciphertext(),
            has_transparent_inputs: false,
            has_transparent_outputs: false,
        });
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
        let record = EnhanceRecord::from_parts(EnhanceRecordParts {
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            cv_net: cv_net.to_bytes(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut outgoing_rng),
            has_transparent_inputs: false,
            has_transparent_outputs: false,
        });
        let pending = PendingIronwoodOutgoing {
            request_id: IronwoodEnhanceRequestId::new(TxId::from_bytes([0; 32]), 0),
            account_ids: vec![()],
            nullifier: nf.to_bytes(),
            cmx: cmx.to_bytes(),
            ephemeral_key: *record.ephemeral_key(),
            compact_ciphertext: record.enc_ciphertext()[..52].try_into().unwrap(),
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
        let wrong_ephemeral_key_record = EnhanceRecord::from_parts(EnhanceRecordParts {
            ephemeral_key: wrong_ephemeral_key,
            enc_ciphertext: *record.enc_ciphertext(),
            cv_net: *record.cv_net(),
            out_ciphertext: *record.out_ciphertext(),
            has_transparent_inputs: false,
            has_transparent_outputs: false,
        });
        assert!(!record_matches_compact_action(
            &pending,
            &wrong_ephemeral_key_record
        ));

        let mut wrong_compact_ciphertext = *record.enc_ciphertext();
        wrong_compact_ciphertext[0] ^= 1;
        let wrong_compact_ciphertext_record = EnhanceRecord::from_parts(EnhanceRecordParts {
            ephemeral_key: *record.ephemeral_key(),
            enc_ciphertext: wrong_compact_ciphertext,
            cv_net: *record.cv_net(),
            out_ciphertext: *record.out_ciphertext(),
            has_transparent_inputs: false,
            has_transparent_outputs: false,
        });
        assert!(!record_matches_compact_action(
            &pending,
            &wrong_compact_ciphertext_record
        ));
    }
}
