//! Synthetic Ironwood output for tests that carry an Enhance record through a
//! real PIR path and then check that it still authenticates.
//!
//! Every input is fixed public test material, never a wallet credential: the
//! recipient spending key is `[7; 32]`, the other key `[8; 32]`, the note has
//! value 5, memo `[42; 512]`, rho zero, rseed `[9; 32]` and note version 3, and
//! the value commitment uses a zero trapdoor. The outgoing ciphertext is
//! encrypted with the thread RNG supplied, as wallets do; because the fixture
//! has an outgoing viewing key, note encryption draws nothing from it, so every
//! field of the fixture is deterministic.
//!
//! The Orchard and note-encryption types stay inside this module: callers pass
//! and receive plain bytes, so a consumer needs no direct dependency on either.

use orchard::{
    Note,
    keys::{FullViewingKey, OutgoingViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho},
    note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption, OrchardDomain},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use zcash_note_encryption::{
    Domain, EphemeralKeyBytes, ShieldedOutput, try_note_decryption, try_output_recovery_with_ovk,
};

/// Bytes of a full note ciphertext (`enc_ciphertext`).
pub const ENC_CIPHERTEXT_BYTES: usize = 580;
/// Bytes of the compact-block prefix of `enc_ciphertext`.
pub const COMPACT_PREFIX_BYTES: usize = 52;
/// Bytes of the `enc_ciphertext` suffix an Enhance record carries.
pub const ENC_CIPHERTEXT_SUFFIX_BYTES: usize = ENC_CIPHERTEXT_BYTES - COMPACT_PREFIX_BYTES;
/// Bytes of an outgoing ciphertext (`out_ciphertext`).
pub const OUT_CIPHERTEXT_BYTES: usize = 80;
/// Bytes of a memo.
pub const MEMO_BYTES: usize = 512;

/// Value of the fixture note, in zatoshis.
pub const FIXTURE_VALUE: u64 = 5;
/// Memo of the fixture note.
pub const FIXTURE_MEMO: [u8; MEMO_BYTES] = [42; MEMO_BYTES];

const OWN_SPENDING_KEY: [u8; 32] = [7; 32];
const OTHER_SPENDING_KEY: [u8; 32] = [8; 32];
const RHO: [u8; 32] = [0; 32];
const RSEED: [u8; 32] = [9; 32];
const TRAPDOOR: [u8; 32] = [0; 32];
const NULLIFIER: [u8; 32] = [0; 32];

/// Note-encryption domain used to attempt decryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteDomain {
    /// The Ironwood domain the fixture output was encrypted in.
    Ironwood,
    /// The Orchard domain, which must not accept an Ironwood output.
    Orchard,
}

/// Viewing key used to attempt decryption or recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureKey {
    /// Keys derived from the spending key the fixture note is sent to.
    Own,
    /// Keys derived from an unrelated spending key.
    Other,
}

/// What decryption or recovery produced, reduced to comparable plain values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredNote {
    /// Recovered note value, in zatoshis.
    pub value: u64,
    /// Whether the recovered recipient is the fixture recipient address.
    pub recipient_matches: bool,
    /// Whether the recovered note equals the fixture note in every field
    /// (recipient, value, rho, rseed and version).
    pub note_matches: bool,
    /// Recovered memo.
    pub memo: [u8; MEMO_BYTES],
}

impl RecoveredNote {
    /// Whether this is exactly the fixture note, recipient and memo.
    pub fn is_fixture(&self) -> bool {
        self.value == FIXTURE_VALUE
            && self.recipient_matches
            && self.note_matches
            && self.memo == FIXTURE_MEMO
    }
}

/// The parts of a shielded output that incoming decryption reads.
///
/// Fields are public so a test can rebuild `enc_ciphertext` from returned
/// record bytes or tamper with any single field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputBytes {
    /// Action nullifier, which determines the note's rho in the decryption domain.
    pub nullifier: [u8; 32],
    /// Extracted note commitment.
    pub cmx: [u8; 32],
    /// Ephemeral public key.
    pub ephemeral_key: [u8; 32],
    /// Full note ciphertext: compact prefix followed by the record suffix.
    pub enc_ciphertext: [u8; ENC_CIPHERTEXT_BYTES],
}

impl OutputBytes {
    /// The compact-block prefix of `enc_ciphertext`.
    pub fn compact_prefix(&self) -> [u8; COMPACT_PREFIX_BYTES] {
        self.enc_ciphertext[..COMPACT_PREFIX_BYTES]
            .try_into()
            .expect("prefix length")
    }

    /// The suffix of `enc_ciphertext` that an Enhance record carries.
    pub fn enc_ciphertext_suffix(&self) -> [u8; ENC_CIPHERTEXT_SUFFIX_BYTES] {
        self.enc_ciphertext[COMPACT_PREFIX_BYTES..]
            .try_into()
            .expect("suffix length")
    }

    /// A copy whose `enc_ciphertext` keeps this prefix and takes `suffix`.
    pub fn with_enc_ciphertext_suffix(&self, suffix: &[u8; ENC_CIPHERTEXT_SUFFIX_BYTES]) -> Self {
        let mut output = self.clone();
        output.enc_ciphertext[COMPACT_PREFIX_BYTES..].copy_from_slice(suffix);
        output
    }
}

impl<D: Domain<ExtractedCommitmentBytes = [u8; 32]>> ShieldedOutput<D, ENC_CIPHERTEXT_BYTES>
    for OutputBytes
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key)
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_BYTES] {
        &self.enc_ciphertext
    }
}

/// One fixture Ironwood output and the record fields derived from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IronwoodOutputFixture {
    /// Compact action parts and the full note ciphertext.
    pub output: OutputBytes,
    /// Net value commitment bytes (`cv_net`).
    pub cv_net: [u8; 32],
    /// Outgoing ciphertext, recoverable with the own outgoing viewing key.
    pub out_ciphertext: [u8; OUT_CIPHERTEXT_BYTES],
}

impl IronwoodOutputFixture {
    /// Encrypts the fixture note to the own key's external address at index 0,
    /// with the own outgoing viewing key. `out_ciphertext` is encrypted with the
    /// thread RNG supplied, which is unused when an outgoing viewing key is present.
    pub fn new() -> Self {
        let keys = Keys::new(OWN_SPENDING_KEY);
        let note = fixture_note(&keys);
        let cv = fixture_value_commitment();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let encryptor = IronwoodNoteEncryption::new(Some(keys.ovk), note, FIXTURE_MEMO);
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmx, &mut rand_10::rng());
        Self {
            output: OutputBytes {
                nullifier: NULLIFIER,
                cmx: cmx.to_bytes(),
                ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0,
                enc_ciphertext: encryptor.encrypt_note_plaintext(),
            },
            cv_net: cv.to_bytes(),
            out_ciphertext,
        }
    }
}

impl Default for IronwoodOutputFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Trial-decrypts `output` with `key`'s incoming viewing key in `domain`.
///
/// Returns `None` when decryption fails, including when the nullifier bytes
/// are not a valid nullifier.
pub fn decrypt_incoming(
    domain: NoteDomain,
    key: FixtureKey,
    output: &OutputBytes,
) -> Option<RecoveredNote> {
    let keys = Keys::for_key(key);
    let ivk = PreparedIncomingViewingKey::new(&keys.ivk);
    let compact = compact_action(output)?;
    let expected = expected();
    let recovered = match domain {
        NoteDomain::Ironwood => {
            try_note_decryption(&IronwoodDomain::for_compact_action(&compact), &ivk, output)
        }
        NoteDomain::Orchard => {
            try_note_decryption(&OrchardDomain::for_compact_action(&compact), &ivk, output)
        }
    }?;
    Some(expected.reduce(recovered))
}

/// Recovers `output` with `key`'s outgoing viewing key in the Ironwood domain,
/// given the record's `cv_net` and `out_ciphertext`.
///
/// Returns `None` when recovery fails, including when `cv_net` or the
/// nullifier bytes do not decode.
pub fn recover_outgoing(
    key: FixtureKey,
    output: &OutputBytes,
    cv_net: &[u8; 32],
    out_ciphertext: &[u8; OUT_CIPHERTEXT_BYTES],
) -> Option<RecoveredNote> {
    let keys = Keys::for_key(key);
    let compact = compact_action(output)?;
    let cv = Option::from(ValueCommitment::from_bytes(cv_net))?;
    let recovered = try_output_recovery_with_ovk(
        &IronwoodDomain::for_compact_action(&compact),
        &keys.ovk,
        output,
        &cv,
        out_ciphertext,
    )?;
    Some(expected().reduce(recovered))
}

struct Keys {
    fvk: FullViewingKey,
    ivk: orchard::keys::IncomingViewingKey,
    ovk: OutgoingViewingKey,
}

impl Keys {
    fn new(spending_key: [u8; 32]) -> Self {
        let sk = SpendingKey::from_bytes(spending_key).expect("fixed spending key is valid");
        let fvk = FullViewingKey::from(&sk);
        Self {
            ivk: fvk.to_ivk(Scope::External),
            ovk: fvk.to_ovk(Scope::External),
            fvk,
        }
    }

    fn for_key(key: FixtureKey) -> Self {
        Self::new(match key {
            FixtureKey::Own => OWN_SPENDING_KEY,
            FixtureKey::Other => OTHER_SPENDING_KEY,
        })
    }
}

fn fixture_note(keys: &Keys) -> Note {
    let rho = Rho::from_bytes(&RHO).expect("fixed rho is valid");
    Note::from_parts(
        keys.fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(FIXTURE_VALUE),
        rho,
        RandomSeed::from_bytes(RSEED, &rho).expect("fixed rseed is valid"),
        NoteVersion::V3,
    )
    .expect("fixed note is valid")
}

fn fixture_value_commitment() -> ValueCommitment {
    ValueCommitment::derive(
        NoteValue::from_raw(FIXTURE_VALUE) - NoteValue::from_raw(0),
        ValueCommitTrapdoor::from_bytes(TRAPDOOR).expect("fixed trapdoor is valid"),
    )
}

/// Builds the compact action whose rho selects the decryption domain. The
/// domain depends only on the nullifier; decryption itself reads the raw
/// `cmx`, ephemeral key and ciphertext bytes from `output`, so tampered values
/// reach the note-encryption checks unchanged.
fn compact_action(output: &OutputBytes) -> Option<CompactAction> {
    let nullifier = Option::from(Nullifier::from_bytes(&output.nullifier))?;
    let fixture_cmx =
        ExtractedNoteCommitment::from(fixture_note(&Keys::new(OWN_SPENDING_KEY)).commitment());
    Some(CompactAction::from_parts(
        nullifier,
        fixture_cmx,
        EphemeralKeyBytes(output.ephemeral_key),
        output.compact_prefix(),
    ))
}

struct Expected {
    note: Note,
}

fn expected() -> Expected {
    Expected {
        note: fixture_note(&Keys::new(OWN_SPENDING_KEY)),
    }
}

impl Expected {
    fn reduce(
        &self,
        (note, recipient, memo): (Note, orchard::Address, [u8; MEMO_BYTES]),
    ) -> RecoveredNote {
        RecoveredNote {
            value: note.value().inner(),
            recipient_matches: recipient == self.note.recipient(),
            note_matches: note == self.note,
            memo,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own(output: &OutputBytes) -> Option<RecoveredNote> {
        decrypt_incoming(NoteDomain::Ironwood, FixtureKey::Own, output)
    }

    #[test]
    fn fixture_is_deterministic() {
        let a = IronwoodOutputFixture::new();
        let b = IronwoodOutputFixture::new();
        assert_eq!(a, b);
        assert_eq!(
            a.output
                .with_enc_ciphertext_suffix(&a.output.enc_ciphertext_suffix()),
            a.output
        );
    }

    #[test]
    fn own_keys_decrypt_and_recover_the_fixture() {
        let fixture = IronwoodOutputFixture::new();
        let incoming = own(&fixture.output).unwrap();
        assert!(incoming.is_fixture());
        assert_eq!(incoming.value, FIXTURE_VALUE);
        assert_eq!(incoming.memo, FIXTURE_MEMO);
        let outgoing = recover_outgoing(
            FixtureKey::Own,
            &fixture.output,
            &fixture.cv_net,
            &fixture.out_ciphertext,
        )
        .unwrap();
        assert_eq!(outgoing, incoming);
    }

    #[test]
    fn orchard_domain_and_other_keys_fail() {
        let fixture = IronwoodOutputFixture::new();
        assert!(decrypt_incoming(NoteDomain::Orchard, FixtureKey::Own, &fixture.output).is_none());
        assert!(
            decrypt_incoming(NoteDomain::Ironwood, FixtureKey::Other, &fixture.output).is_none()
        );
        assert!(
            recover_outgoing(
                FixtureKey::Other,
                &fixture.output,
                &fixture.cv_net,
                &fixture.out_ciphertext
            )
            .is_none()
        );
    }

    #[test]
    fn out_ciphertext_corruption_breaks_only_outgoing_recovery() {
        let fixture = IronwoodOutputFixture::new();
        let mut out_ciphertext = fixture.out_ciphertext;
        out_ciphertext[0] ^= 1;
        assert!(
            recover_outgoing(
                FixtureKey::Own,
                &fixture.output,
                &fixture.cv_net,
                &out_ciphertext
            )
            .is_none()
        );
        assert!(own(&fixture.output).unwrap().is_fixture());
    }

    #[test]
    fn cv_net_change_breaks_outgoing_recovery() {
        let fixture = IronwoodOutputFixture::new();
        let mut cv_net = fixture.cv_net;
        cv_net[0] ^= 1;
        assert!(
            recover_outgoing(
                FixtureKey::Own,
                &fixture.output,
                &cv_net,
                &fixture.out_ciphertext
            )
            .is_none()
        );
    }

    #[test]
    fn tampered_output_fields_fail() {
        let fixture = IronwoodOutputFixture::new();

        let mut cmx = fixture.output.clone();
        cmx.cmx[0] ^= 1;
        assert!(own(&cmx).is_none());

        let mut suffix = fixture.output.enc_ciphertext_suffix();
        suffix[100] ^= 1;
        let corrupted = fixture.output.with_enc_ciphertext_suffix(&suffix);
        assert!(own(&corrupted).is_none());
        assert!(
            recover_outgoing(
                FixtureKey::Own,
                &corrupted,
                &fixture.cv_net,
                &fixture.out_ciphertext
            )
            .is_none()
        );

        let mut prefix = fixture.output.clone();
        prefix.enc_ciphertext[0] ^= 1;
        assert!(own(&prefix).is_none());

        let mut epk = fixture.output.clone();
        epk.ephemeral_key[0] ^= 1;
        assert!(own(&epk).is_none());

        let mut nullifier = fixture.output.clone();
        nullifier.nullifier[0] ^= 1;
        assert!(own(&nullifier).is_none());
    }
}
