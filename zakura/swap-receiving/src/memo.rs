const MAGIC: &[u8; 5] = b"\xffZSWP";

/// A v1 refund index carried by a swap funding transaction.
///
/// The deposit address is not stored: the funding transaction's single transparent
/// output already pays it, and recovery needs only the index.
///
/// Decoding does not establish provenance. Accept a record only after
/// authenticating an ordinary internal note and verifying that its transaction
/// was the wallet's own send. Process zero-value and spent notes too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefundMemo {
    index: u64,
}

impl RefundMemo {
    /// Creates a record for the given refund index.
    pub fn new(index: u64) -> Self {
        Self { index }
    }

    /// The index in the refund sequence, not a globally unique operation ID.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Encodes the fixed 512-byte binary memo, zeroing the reserved bytes.
    pub fn encode(&self) -> [u8; 512] {
        let mut bytes = [0; 512];
        bytes[..5].copy_from_slice(MAGIC);
        bytes[5] = 1;
        bytes[6] = 0;
        bytes[7..15].copy_from_slice(&self.index.to_le_bytes());
        bytes
    }

    /// Decodes a v1 record, or returns `None` for any other memo.
    ///
    /// A memo that starts with the `\xffZSWP` discriminator but has another version or
    /// purpose is a record this release cannot read. Callers that select records by
    /// that discriminator must keep such a memo pending rather than mark their
    /// recovery work complete. Bytes after the index are reserved and ignored, so
    /// prerelease records that appended a deposit address still decode.
    pub fn decode(bytes: &[u8; 512]) -> Option<Self> {
        if &bytes[..5] != MAGIC || bytes[5] != 1 || bytes[6] != 0 {
            return None;
        }
        let index = u64::from_le_bytes(bytes[7..15].try_into().expect("eight-byte index"));
        Some(Self { index })
    }
}
