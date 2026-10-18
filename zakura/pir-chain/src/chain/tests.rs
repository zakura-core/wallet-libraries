//! Differential coverage against the pinned node decoder, which is test-only.
use super::*;
use zakura_chain::{
    block::Block as NodeBlock,
    serialization::{ZcashDeserialize, ZcashSerialize},
};

#[test]
fn historical_blocks_match_the_node_decoder() {
    let mainnet = &*zakura_test::vectors::MAINNET_BLOCKS;
    let testnet = &*zakura_test::vectors::TESTNET_BLOCKS;
    assert!(!mainnet.is_empty() && !testnet.is_empty());
    for (height, bytes) in mainnet.iter().chain(testnet.iter()) {
        let node = NodeBlock::zcash_deserialize(*bytes).unwrap();
        let block = Block::zcash_deserialize(*bytes).unwrap();
        assert_eq!(block.hash().0, node.hash().0, "block at height {height}");
        assert_eq!(
            block.header.previous_block_hash.0,
            node.header.previous_block_hash.0
        );
        assert_eq!(block.header.time, node.header.time.timestamp());
        assert_eq!(
            block.coinbase_height().map(|h| h.0),
            node.coinbase_height().map(|h| h.0)
        );
        assert_eq!(block.merkle_root(), node.header.merkle_root.0);
        assert_eq!(block.transactions.len(), node.transactions.len());
        for (decoded, reference) in block.transactions.iter().zip(&node.transactions) {
            assert_eq!(decoded.hash().0, reference.hash().0);
            assert_eq!(decoded.is_coinbase(), reference.is_coinbase());
            assert_eq!(decoded.has_shielded_data(), reference.has_shielded_data());
            assert_eq!(
                decoded.expiry_height().map(|h| h.0).unwrap_or(0),
                reference.expiry_height().map(|h| h.0).unwrap_or(0)
            );
            assert_eq!(decoded.outputs().len(), reference.outputs().len());
            for (output, expected) in decoded.outputs().iter().zip(reference.outputs()) {
                assert_eq!(u64::from(output.value), u64::from(expected.value));
                assert_eq!(
                    output.lock_script.as_raw_bytes(),
                    expected.lock_script.as_raw_bytes()
                );
                assert_eq!(
                    output.zcash_serialize_to_vec().unwrap(),
                    expected.zcash_serialize_to_vec().unwrap()
                );
            }
            let bytes = reference.zcash_serialize_to_vec().unwrap();
            let mut written = Vec::new();
            decoded.wallet().write(&mut written).unwrap();
            assert_eq!(written, bytes);
        }
    }
}

#[test]
fn ironwood_transactions_match_the_node_decoder() {
    for hex in [
        include_str!("../../tests/fixtures/ironwood-fee-expiry.hex"),
        include_str!("../../tests/fixtures/receiver-refund.hex"),
    ] {
        let raw = hex::decode(hex.trim()).unwrap();
        let node =
            zakura_chain::transaction::Transaction::zcash_deserialize(raw.as_slice()).unwrap();
        let tx = Transaction::zcash_deserialize(raw.as_slice()).unwrap();
        assert_eq!(tx.hash().0, node.hash().0);
        assert!(tx.ironwood_actions().next().is_some());
        for (action, reference) in tx.ironwood_actions().zip(node.ironwood_actions()) {
            assert_eq!(action.cv, <[u8; 32]>::from(reference.cv));
            assert_eq!(action.nullifier, <[u8; 32]>::from(reference.nullifier));
            assert_eq!(action.cm_x, <[u8; 32]>::from(reference.cm_x));
            assert_eq!(
                action.ephemeral_key,
                <[u8; 32]>::from(reference.ephemeral_key)
            );
            assert_eq!(
                action.enc_ciphertext,
                <[u8; 580]>::from(reference.enc_ciphertext)
            );
            assert_eq!(
                action.out_ciphertext,
                <[u8; 80]>::from(reference.out_ciphertext)
            );
        }
    }
}

#[cfg(feature = "transparent")]
#[test]
fn exact_block_reads_reject_truncation_and_trailing_bytes() {
    use crate::transparent::FetchedBlock;
    let bytes = &*zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES;
    assert!(FetchedBlock::from_exact_bytes(bytes).is_ok());
    assert!(FetchedBlock::from_exact_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(FetchedBlock::from_exact_bytes(&trailing).is_err());
    let mut header = &bytes[..];
    BlockHeader::read(&mut header).unwrap();
    let header_len = bytes.len() - header.len();
    let mut huge_count = bytes[..header_len].to_vec();
    CompactSize::write(&mut huge_count, 1_000_000).unwrap();
    assert!(FetchedBlock::from_exact_bytes(&huge_count).is_err());
    let mut bad_header = bytes.clone();
    bad_header[..4].copy_from_slice(&3u32.to_le_bytes());
    assert!(FetchedBlock::from_exact_bytes(&bad_header).is_err());
}

#[test]
fn supported_network_constants_match_the_node() {
    for network in [crate::Network::Mainnet, crate::Network::Testnet] {
        let node = match network {
            crate::Network::Mainnet => zakura_chain::parameters::Network::Mainnet,
            crate::Network::Testnet => zakura_chain::parameters::Network::new_default_testnet(),
        };
        assert_eq!(network.genesis_hash(), node.genesis_hash().0);
        assert_eq!(
            network.ironwood_activation(),
            zakura_chain::parameters::NetworkUpgrade::Nu6_3
                .activation_height(&node)
                .unwrap()
                .0
        );
    }
}
