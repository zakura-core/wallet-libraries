//! The canonical transparent event model.
//!
//! One self-contained record shape is shared by everything that touches an event:
//! the indexer that appends it to its journal, the builder that packs it into a
//! shard's directory and pages, and the wallet that decodes it out of a private
//! response. A single encoding is what makes those three agree; three
//! hand-written ones would agree only until they didn't.
//!
//! Two events exist, and between them they are the whole recovery scope: every
//! transparent output controlled by a supported script, and every later input
//! that consumes one of those outputs. Both are indexed under the *exact raw
//! locking script* of the output in question — for a spend, that is the script
//! of the output being consumed, not anything in the spending input.
//!
//! # What is deliberately absent
//!
//! There is no block hash in a record. It would cost 32 bytes of every 87, and
//! it would be worse than useless: a wallet that took an event's block hash
//! from the server could be handed an event placed on a branch it has not
//! accepted. The height is in the record, and the wallet resolves height to
//! hash against its own accepted chain, which is the only source that can
//! answer that question safely.
//!
//! There is no script in a record either. The script is the *key* a record is
//! stored under, and it is carried once in the enclosing directory entry or
//! page header rather than once per event. A decoder must therefore always
//! learn the script from the container and check it, never infer it.

use std::fmt;

/// Legacy v2 event width. V3 appends bounded metadata; PIR rows remain fixed size.
pub const EVENT_BYTES: usize = 87;
/// Maximum self-contained v3 journal event, including metadata.
pub const MAX_EVENT_BYTES: usize = EVENT_BYTES + 1 + 5 + 10;
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Whole-transaction fee; this does not attribute a fee to a wallet account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeState {
    Exact(u64),
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionMetadata {
    pub fee: FeeState,
    pub transparent_input_count: u32,
    pub has_shielded_components: bool,
}

impl TransactionMetadata {
    pub fn validate(self, coinbase: bool) -> Result<(), EventError> {
        if matches!(self.fee, FeeState::Exact(fee) if fee > MAX_MONEY)
            || coinbase != matches!(self.fee, FeeState::NotApplicable)
            || coinbase && self.transparent_input_count != 0
        {
            return Err(EventError::Metadata("invalid fee or coinbase input count"));
        }
        Ok(())
    }

    /// Metadata availability is explicit, including for legacy observations.
    pub fn flags(self) -> u8 {
        32 | if matches!(self.fee, FeeState::Exact(_)) {
            8
        } else {
            0
        } | if self.has_shielded_components { 16 } else { 0 }
    }

    pub fn encoded_len(self) -> usize {
        varint_len(self.transparent_input_count.into())
            + match self.fee {
                FeeState::Exact(fee) => varint_len(fee),
                _ => 0,
            }
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        encode_varint(self.transparent_input_count.into(), out);
        if let FeeState::Exact(fee) = self.fee {
            encode_varint(fee, out);
        }
    }

    pub fn decode(
        bytes: &[u8],
        flags: u8,
        coinbase: bool,
    ) -> Result<(Option<Self>, usize), EventError> {
        if flags & !56 != 0 || flags & 32 == 0 && flags != 0 {
            return Err(EventError::Flags(flags));
        }
        if flags == 0 {
            return Ok((None, 0));
        }
        let (count, mut used) = decode_varint(bytes, u32::MAX.into())?;
        let fee = if flags & 8 != 0 {
            let (fee, n) = decode_varint(&bytes[used..], MAX_MONEY)?;
            used += n;
            FeeState::Exact(fee)
        } else if coinbase {
            FeeState::NotApplicable
        } else {
            FeeState::Unknown
        };
        let metadata = Self {
            fee,
            transparent_input_count: count as u32,
            has_shielded_components: flags & 16 != 0,
        };
        metadata.validate(coinbase)?;
        Ok((Some(metadata), used))
    }
}

pub fn varint_len(mut value: u64) -> usize {
    let mut n = 1;
    while value >= 128 {
        n += 1;
        value >>= 7;
    }
    n
}

pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        out.push(byte | if value != 0 { 128 } else { 0 });
        if value == 0 {
            break;
        }
    }
}

pub fn decode_varint(bytes: &[u8], maximum: u64) -> Result<(u64, usize), EventError> {
    let mut value = 0u64;
    for i in 0..10 {
        let byte = *bytes
            .get(i)
            .ok_or(EventError::Metadata("truncated varint"))?;
        if i == 9 && byte > 1 {
            return Err(EventError::Metadata("overflowing varint"));
        }
        value |= u64::from(byte & 127) << (7 * i);
        if byte & 128 == 0 {
            if i != 0 && byte == 0 {
                return Err(EventError::Metadata("noncanonical varint"));
            }
            if value > maximum {
                return Err(EventError::Metadata("varint exceeds bound"));
            }
            return Ok((value, i + 1));
        }
    }
    Err(EventError::Metadata("overflowing varint"))
}

/// All observations of one transaction must describe the same placement and metadata.
/// Duplicate input identities must also name the same consumed outpoint.
pub fn check_transaction_consistency<'a>(
    events: impl IntoIterator<Item = &'a TransparentEvent>,
) -> Result<(), EventError> {
    let mut transactions = std::collections::BTreeMap::new();
    let mut inputs = std::collections::BTreeMap::new();
    for event in events {
        event.validate_metadata()?;
        let coinbase = matches!(event, TransparentEvent::Receive(receive) if receive.coinbase);
        let facts = (
            event.height(),
            event.transaction_index(),
            event.metadata(),
            coinbase,
        );
        if transactions
            .insert(event.txid(), facts)
            .is_some_and(|previous| previous != facts)
        {
            return Err(EventError::Metadata(
                "conflicting transaction metadata or placement",
            ));
        }
        if let TransparentEvent::Spend(spend) = event {
            let spent = (spend.spent_txid, spend.spent_output_index);
            if inputs
                .insert((spend.spending_txid, spend.input_index), spent)
                .is_some_and(|previous| previous != spent)
            {
                return Err(EventError::Metadata(
                    "conflicting transaction input identity",
                ));
            }
        }
    }
    Ok(())
}

const KIND_RECEIVE: u8 = 0;
const KIND_SPEND: u8 = 1;

/// Bit 0 of the flags byte. Receive is clear, spend is set.
const FLAG_SPEND: u8 = 1 << 0;
/// Bit 1 of the flags byte. Valid only on a receive.
const FLAG_COINBASE: u8 = 1 << 1;
const KNOWN_FLAGS: u8 = FLAG_SPEND | FLAG_COINBASE;

// Field offsets within a record. Packed, with no alignment padding.
const OFF_FLAGS: usize = 0;
const OFF_TX_INDEX: usize = 1;
const OFF_HEIGHT: usize = 3;
const OFF_VALUE: usize = 7;
const OFF_TXID: usize = 15;
const OFF_INDEX: usize = 47;
const OFF_SPENT_TXID: usize = 51;
const OFF_SPENT_INDEX: usize = 83;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EventError {
    #[error("transaction metadata: {0}")]
    Metadata(&'static str),
    #[error("event record is {0} bytes, expected {EVENT_BYTES}")]
    Length(usize),
    #[error("unknown flag bits set: {0:#04x}")]
    Flags(u8),
    #[error("an all-zero event record is not a valid event")]
    Empty,
    #[error("a {kind} event must not set {field}")]
    UnusedField {
        kind: &'static str,
        field: &'static str,
    },
}

/// A transaction id in internal (serialized) byte order.
///
/// The same discipline as block hashes: display order is the reverse, and is
/// only ever produced at a presentation boundary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Txid(pub [u8; 32]);

impl Txid {
    pub fn to_display_hex(self) -> String {
        let mut bytes = self.0;
        bytes.reverse();
        hex::encode(bytes)
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({})", self.to_display_hex())
    }
}

/// An output created under a wallet-supported script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveEvent {
    pub metadata: Option<TransactionMetadata>,
    pub height: u32,
    pub txid: Txid,
    pub transaction_index: u16,
    pub output_index: u32,
    pub value: u64,
    /// Retained for the wallet's maturity policy. Recovering a coinbase receive
    /// does not make it spendable; that decision stays with the wallet.
    pub coinbase: bool,
}

/// An input consuming an output that was created under a supported script.
///
/// `spent_txid` and `spent_output_index` identify the consumed outpoint, which
/// is what lets a wallet remove the right entry from its UTXO map. The script
/// this event is indexed under is the *consumed output's* script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendEvent {
    pub metadata: Option<TransactionMetadata>,
    pub height: u32,
    pub spending_txid: Txid,
    pub transaction_index: u16,
    pub input_index: u32,
    pub spent_txid: Txid,
    pub spent_output_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransparentEvent {
    Receive(ReceiveEvent),
    Spend(SpendEvent),
}

/// A receive's stable identity: the outpoint it creates.
pub type ReceiveIdentity = (Txid, u32);

/// A spend's stable identity.
///
/// The spending input *and* the consumed outpoint, together. The spender alone
/// would not be unique — one transaction can consume several of a wallet's
/// outputs — and the consumed outpoint alone would collide across a reorg that
/// re-spends it in a different transaction.
pub type SpendIdentity = (Txid, u32, Txid, u32);

impl TransparentEvent {
    pub fn metadata(&self) -> Option<TransactionMetadata> {
        match self {
            Self::Receive(e) => e.metadata,
            Self::Spend(e) => e.metadata,
        }
    }

    pub fn with_metadata(mut self, metadata: Option<TransactionMetadata>) -> Self {
        match &mut self {
            Self::Receive(e) => e.metadata = metadata,
            Self::Spend(e) => e.metadata = metadata,
        }
        self
    }

    pub fn validate_metadata(&self) -> Result<(), EventError> {
        if let Some(metadata) = self.metadata() {
            if matches!(self, Self::Receive(e) if e.value > MAX_MONEY) {
                return Err(EventError::Metadata("output value exceeds monetary bound"));
            }
            metadata.validate(matches!(self, Self::Receive(e) if e.coinbase))?;
            if matches!(self, Self::Spend(e) if e.input_index >= metadata.transparent_input_count) {
                return Err(EventError::Metadata(
                    "input index exceeds complete input count",
                ));
            }
        }
        Ok(())
    }

    /// Canonical self-contained event bytes; legacy events retain their v2 representation.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = self.to_legacy_bytes().to_vec();
        if let Some(metadata) = self.metadata() {
            bytes.push(metadata.flags());
            metadata.encode(&mut bytes);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventError> {
        if bytes.len() < EVENT_BYTES || bytes.len() > MAX_EVENT_BYTES {
            return Err(EventError::Length(bytes.len()));
        }
        let mut event = Self::from_legacy_bytes(&bytes[..EVENT_BYTES])?;
        if bytes.len() > EVENT_BYTES {
            let (metadata, used) = TransactionMetadata::decode(
                &bytes[EVENT_BYTES + 1..],
                bytes[EVENT_BYTES],
                matches!(event, Self::Receive(e) if e.coinbase),
            )?;
            if metadata.is_none() || EVENT_BYTES + 1 + used != bytes.len() {
                return Err(EventError::Metadata("invalid metadata framing"));
            }
            event = event.with_metadata(metadata);
        }
        event.validate_metadata()?;
        Ok(event)
    }
    pub fn height(&self) -> u32 {
        match self {
            TransparentEvent::Receive(event) => event.height,
            TransparentEvent::Spend(event) => event.height,
        }
    }

    pub fn transaction_index(&self) -> u16 {
        match self {
            TransparentEvent::Receive(event) => event.transaction_index,
            TransparentEvent::Spend(event) => event.transaction_index,
        }
    }

    /// The transaction this event belongs to.
    ///
    /// For a receive that is the creating transaction; for a spend, the
    /// spending one. This is the key a wallet uses to group events for history
    /// presentation, and the key into the optional transaction-detail table.
    pub fn txid(&self) -> Txid {
        match self {
            TransparentEvent::Receive(event) => event.txid,
            TransparentEvent::Spend(event) => event.spending_txid,
        }
    }

    /// A total order that is stable across rebuilds.
    ///
    /// Pages are ordered by this, and a wallet checks the ordering it receives,
    /// so it must be a function of the event alone — never of iteration order,
    /// hash-map layout, or the order the indexer happened to see transactions
    /// in. Height first, then position within the block, then the event's own
    /// identity to break ties within one transaction.
    pub fn sort_key(&self) -> (u32, u16, u8, Txid, u32, Txid, u32) {
        match self {
            TransparentEvent::Receive(event) => (
                event.height,
                event.transaction_index,
                KIND_RECEIVE,
                event.txid,
                event.output_index,
                Txid([0; 32]),
                0,
            ),
            TransparentEvent::Spend(event) => (
                event.height,
                event.transaction_index,
                KIND_SPEND,
                event.spending_txid,
                event.input_index,
                event.spent_txid,
                event.spent_output_index,
            ),
        }
    }

    pub fn to_legacy_bytes(self) -> [u8; EVENT_BYTES] {
        let mut bytes = [0u8; EVENT_BYTES];
        match self {
            TransparentEvent::Receive(event) => {
                if event.coinbase {
                    bytes[OFF_FLAGS] = FLAG_COINBASE;
                }
                bytes[OFF_TX_INDEX..OFF_HEIGHT]
                    .copy_from_slice(&event.transaction_index.to_le_bytes());
                bytes[OFF_HEIGHT..OFF_VALUE].copy_from_slice(&event.height.to_le_bytes());
                bytes[OFF_VALUE..OFF_TXID].copy_from_slice(&event.value.to_le_bytes());
                bytes[OFF_TXID..OFF_INDEX].copy_from_slice(&event.txid.0);
                bytes[OFF_INDEX..OFF_SPENT_TXID].copy_from_slice(&event.output_index.to_le_bytes());
            }
            TransparentEvent::Spend(event) => {
                bytes[OFF_FLAGS] = FLAG_SPEND;
                bytes[OFF_TX_INDEX..OFF_HEIGHT]
                    .copy_from_slice(&event.transaction_index.to_le_bytes());
                bytes[OFF_HEIGHT..OFF_VALUE].copy_from_slice(&event.height.to_le_bytes());
                bytes[OFF_TXID..OFF_INDEX].copy_from_slice(&event.spending_txid.0);
                bytes[OFF_INDEX..OFF_SPENT_TXID].copy_from_slice(&event.input_index.to_le_bytes());
                bytes[OFF_SPENT_TXID..OFF_SPENT_INDEX].copy_from_slice(&event.spent_txid.0);
                bytes[OFF_SPENT_INDEX..].copy_from_slice(&event.spent_output_index.to_le_bytes());
            }
        }
        debug_assert!(
            bytes.iter().any(|byte| *byte != 0),
            "an encoder must not emit the empty sentinel"
        );
        bytes
    }

    /// Decodes a record, rejecting anything it does not fully understand.
    ///
    /// Strictness is the point. These bytes arrive from a PIR response, and a
    /// record with an unknown kind, an unknown flag, dirty reserved bytes, or a
    /// field set that its kind does not use is evidence that the wallet and the
    /// service disagree about the encoding. Decoding it leniently would turn
    /// that disagreement into a wrong balance instead of an error.
    pub fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, EventError> {
        if bytes.len() != EVENT_BYTES {
            return Err(EventError::Length(bytes.len()));
        }
        // Directory inline slots use this pattern as the empty sentinel. A
        // non-coinbase receive still has flags 0, so kind-in-flags does not
        // create the sentinel by itself.
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(EventError::Empty);
        }
        let flags = bytes[OFF_FLAGS];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(EventError::Flags(flags));
        }
        let transaction_index =
            u16::from_le_bytes(bytes[OFF_TX_INDEX..OFF_HEIGHT].try_into().expect("2 bytes"));
        let height = u32::from_le_bytes(bytes[OFF_HEIGHT..OFF_VALUE].try_into().expect("4 bytes"));
        let value = u64::from_le_bytes(bytes[OFF_VALUE..OFF_TXID].try_into().expect("8 bytes"));
        let txid = Txid(bytes[OFF_TXID..OFF_INDEX].try_into().expect("32 bytes"));
        let index = u32::from_le_bytes(
            bytes[OFF_INDEX..OFF_SPENT_TXID]
                .try_into()
                .expect("4 bytes"),
        );
        let spent_txid = Txid(
            bytes[OFF_SPENT_TXID..OFF_SPENT_INDEX]
                .try_into()
                .expect("32 bytes"),
        );
        let spent_output_index =
            u32::from_le_bytes(bytes[OFF_SPENT_INDEX..].try_into().expect("4 bytes"));
        let spend = flags & FLAG_SPEND != 0;

        if !spend {
            if spent_txid != Txid([0; 32]) || spent_output_index != 0 {
                return Err(EventError::UnusedField {
                    kind: "receive",
                    field: "the consumed outpoint",
                });
            }
            Ok(TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height,
                txid,
                transaction_index,
                output_index: index,
                value,
                coinbase: flags & FLAG_COINBASE != 0,
            }))
        } else {
            if value != 0 {
                return Err(EventError::UnusedField {
                    kind: "spend",
                    field: "a value",
                });
            }
            if flags & FLAG_COINBASE != 0 {
                return Err(EventError::UnusedField {
                    kind: "spend",
                    field: "the coinbase flag",
                });
            }
            Ok(TransparentEvent::Spend(SpendEvent {
                metadata: None,
                height,
                spending_txid: txid,
                transaction_index,
                input_index: index,
                spent_txid,
                spent_output_index,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_states_and_canonical_integer_boundaries() {
        for value in [0, 1, 127, 128, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut bytes = Vec::new();
            encode_varint(value, &mut bytes);
            assert_eq!(bytes.len(), varint_len(value));
            assert_eq!(decode_varint(&bytes, u64::MAX), Ok((value, bytes.len())));
        }
        for bytes in [
            vec![],
            vec![128],
            vec![128, 0],
            vec![255; 11],
            vec![255; 10],
        ] {
            assert!(decode_varint(&bytes, u64::MAX).is_err());
        }
        assert!(decode_varint(&[128, 1], 127).is_err());
        for fee in [
            FeeState::Exact(0),
            FeeState::Exact(MAX_MONEY),
            FeeState::Unknown,
        ] {
            let event = spend().with_metadata(Some(TransactionMetadata {
                fee,
                transparent_input_count: u32::MAX,
                has_shielded_components: true,
            }));
            assert_eq!(TransparentEvent::from_bytes(&event.to_bytes()), Ok(event));
        }
        let coinbase = TransparentEvent::Receive(ReceiveEvent {
            coinbase: true,
            ..match receive() {
                TransparentEvent::Receive(e) => e,
                _ => unreachable!(),
            }
        })
        .with_metadata(Some(TransactionMetadata {
            fee: FeeState::NotApplicable,
            transparent_input_count: 0,
            has_shielded_components: false,
        }));
        assert_eq!(
            TransparentEvent::from_bytes(&coinbase.to_bytes()),
            Ok(coinbase)
        );
        let metadata = TransactionMetadata {
            fee: FeeState::Exact(500),
            transparent_input_count: 1,
            has_shielded_components: false,
        };
        let event = spend().with_metadata(Some(metadata));
        let bytes = event.to_bytes();
        for end in EVENT_BYTES + 1..bytes.len() {
            assert!(TransparentEvent::from_bytes(&bytes[..end]).is_err());
        }
        let mut reserved = bytes.clone();
        reserved[EVENT_BYTES] |= 64;
        assert!(TransparentEvent::from_bytes(&reserved).is_err());
        assert!(event
            .with_metadata(Some(TransactionMetadata {
                fee: FeeState::Exact(MAX_MONEY + 1),
                ..metadata
            }))
            .validate_metadata()
            .is_err());
        assert!(event
            .with_metadata(Some(TransactionMetadata {
                transparent_input_count: 0,
                ..metadata
            }))
            .validate_metadata()
            .is_err());
    }

    #[test]
    fn repeated_transaction_assertions_must_agree() {
        let metadata = TransactionMetadata {
            fee: FeeState::Exact(500),
            transparent_input_count: 1,
            has_shielded_components: false,
        };
        let event = spend().with_metadata(Some(metadata));
        let conflicting = event.with_metadata(Some(TransactionMetadata {
            fee: FeeState::Exact(501),
            ..metadata
        }));
        assert!(check_transaction_consistency([&event, &event]).is_ok());
        assert!(check_transaction_consistency([&event, &conflicting]).is_err());
    }

    fn receive() -> TransparentEvent {
        TransparentEvent::Receive(ReceiveEvent {
            metadata: None,
            height: 3_428_143,
            txid: Txid([7; 32]),
            transaction_index: 3,
            output_index: 1,
            value: 100_000,
            coinbase: false,
        })
    }

    fn spend() -> TransparentEvent {
        TransparentEvent::Spend(SpendEvent {
            metadata: None,
            height: 3_428_200,
            spending_txid: Txid([9; 32]),
            transaction_index: 2,
            input_index: 0,
            spent_txid: Txid([7; 32]),
            spent_output_index: 1,
        })
    }

    #[test]
    fn both_kinds_round_trip() {
        for event in [receive(), spend()] {
            assert_eq!(TransparentEvent::from_bytes(&event.to_bytes()), Ok(event));
        }
    }

    #[test]
    fn a_coinbase_receive_round_trips_its_flag() {
        let event = TransparentEvent::Receive(ReceiveEvent {
            coinbase: true,
            ..match receive() {
                TransparentEvent::Receive(event) => event,
                _ => unreachable!(),
            }
        });
        assert_eq!(TransparentEvent::from_bytes(&event.to_bytes()), Ok(event));
    }

    #[test]
    fn every_record_is_the_same_width_regardless_of_kind() {
        assert_eq!(receive().to_bytes().len(), EVENT_BYTES);
        assert_eq!(spend().to_bytes().len(), EVENT_BYTES);
    }

    /// A shorter or longer slice is a framing disagreement, not a value to
    /// interpret. Accepting one would silently reinterpret every later record
    /// in a page.
    #[test]
    fn a_wrong_length_record_is_refused() {
        let bytes = receive().to_bytes();
        assert_eq!(
            TransparentEvent::from_bytes(&bytes[..EVENT_BYTES - 1]),
            Err(EventError::Length(EVENT_BYTES - 1))
        );
    }

    #[test]
    fn an_all_zero_record_is_not_an_event() {
        assert_eq!(
            TransparentEvent::from_bytes(&[0u8; EVENT_BYTES]),
            Err(EventError::Empty)
        );
    }

    #[test]
    fn unknown_flags_are_refused() {
        let mut bytes = receive().to_bytes();
        bytes[OFF_FLAGS] = 0x80;
        assert_eq!(
            TransparentEvent::from_bytes(&bytes),
            Err(EventError::Flags(0x80))
        );
    }

    /// Fields a kind does not use must be zero. Otherwise a service could smuggle
    /// data past a wallet that ignores those bytes, and two implementations
    /// could disagree about a record while both calling it valid.
    #[test]
    fn fields_a_kind_does_not_use_must_be_zero() {
        let mut bytes = receive().to_bytes();
        bytes[OFF_SPENT_INDEX] = 1;
        assert!(matches!(
            TransparentEvent::from_bytes(&bytes),
            Err(EventError::UnusedField {
                kind: "receive",
                ..
            })
        ));

        let mut bytes = spend().to_bytes();
        bytes[OFF_VALUE] = 1;
        assert!(matches!(
            TransparentEvent::from_bytes(&bytes),
            Err(EventError::UnusedField { kind: "spend", .. })
        ));

        let mut bytes = spend().to_bytes();
        bytes[OFF_FLAGS] |= FLAG_COINBASE;
        assert!(matches!(
            TransparentEvent::from_bytes(&bytes),
            Err(EventError::UnusedField { kind: "spend", .. })
        ));
    }

    /// Ordering must not depend on which kind an event is at the same position,
    /// but it must be total: two events from one transaction still order.
    #[test]
    fn the_sort_key_orders_by_chain_position_then_identity() {
        let mut events = vec![spend(), receive()];
        events.sort_by_key(|event| event.sort_key());
        assert_eq!(events, vec![receive(), spend()]);

        let a = TransparentEvent::Receive(ReceiveEvent {
            output_index: 0,
            ..match receive() {
                TransparentEvent::Receive(event) => event,
                _ => unreachable!(),
            }
        });
        assert!(a.sort_key() < receive().sort_key());
    }

    #[test]
    fn txids_display_in_reversed_order() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        assert!(Txid(bytes).to_display_hex().ends_with("ab"));
    }
}
