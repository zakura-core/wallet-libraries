//! Block and transaction hashes between the node's display order and protocol order.
//!
//! The node's RPC shows hashes as hex of the reversed bytes; blocks, transactions
//! and every PIR record use protocol byte order. These are the only conversions
//! between the two.
use crate::NodeError;

/// The display-order hex of the protocol-order block or transaction hash `hash`.
pub fn display(hash: &[u8; 32]) -> String {
    zakura_chain::block::Hash(*hash).to_string()
}

/// The protocol-order bytes of the display-order hex hash `displayed`.
pub fn parse_display(displayed: &str) -> Result<[u8; 32], NodeError> {
    displayed
        .parse::<zakura_chain::block::Hash>()
        .map(|hash| hash.0)
        .map_err(|error| NodeError::Block(format!("invalid hash {displayed:?}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Display order reverses protocol order, as the node's RPC and explorers show it;
    /// block and transaction IDs share the encoding.
    #[test]
    fn display_order_reverses_protocol_bytes() {
        let mut hash = [0u8; 32];
        hash[0] = 0xab;
        hash[31] = 0x01;
        let displayed = display(&hash);
        assert!(displayed.starts_with("01") && displayed.ends_with("ab"));
        assert_eq!(parse_display(&displayed).unwrap(), hash);
        let txid: zakura_chain::transaction::Hash = displayed.parse().unwrap();
        assert_eq!(txid.0, hash);
        assert!(parse_display("zz").is_err());
        assert!(parse_display(&displayed[2..]).is_err());
    }
}
