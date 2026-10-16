//! Raw transparent scripts as filter elements.

/// A raw locking script, exactly as it appears in the block.
///
/// Filter elements are raw script bytes. They are never addresses, address
/// text, transaction identifiers or outpoints, and they are never normalized,
/// so a nonstandard or unparseable script is still a valid element.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScriptBytes(pub Vec<u8>);

/// `OP_RETURN`. An output whose script *begins* with this opcode is provably
/// unspendable and is excluded from the filter.
pub const OP_RETURN: u8 = 0x6a;

impl ScriptBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether this script's *first* opcode byte is `OP_RETURN`.
    ///
    /// Only the first byte counts. A script that merely contains `0x6a` at some
    /// later offset — inside a pushed data payload, say — is an ordinary
    /// script and must still be included.
    pub fn is_op_return(&self) -> bool {
        self.0.first() == Some(&OP_RETURN)
    }

    /// Whether this script belongs in a filter's element set at all.
    pub fn is_filter_element(&self) -> bool {
        !self.is_empty() && !self.is_op_return()
    }
}

impl AsRef<[u8]> for ScriptBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_leading_op_return_byte_excludes_a_script() {
        assert!(ScriptBytes::new(vec![0x6a]).is_op_return());
        assert!(ScriptBytes::new(vec![0x6a, 0x01, 0x02]).is_op_return());
        // A pushed payload that happens to contain 0x6a is a spendable script.
        assert!(!ScriptBytes::new(vec![0x76, 0xa9, 0x6a, 0x88, 0xac]).is_op_return());
        assert!(!ScriptBytes::new(vec![0x00, 0x6a]).is_op_return());
    }

    #[test]
    fn empty_and_op_return_scripts_are_not_elements() {
        assert!(!ScriptBytes::new(vec![]).is_filter_element());
        assert!(!ScriptBytes::new(vec![0x6a, 0x05]).is_filter_element());
        assert!(ScriptBytes::new(vec![0x76, 0xa9]).is_filter_element());
    }
}
