//! The wallet's own scanned chain as the independent view a pass is checked against.

use crate::engine::{Acceptance, Anchor, ChainView};
use zcash_client_backend::data_api::{WalletRead, transparent_ledger::ChainPoint};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::convert::{block_hash_from_display, height_u64};

/// A [`ChainView`] over the blocks a wallet scanned, answering only through `target`.
///
/// Answers come from [`WalletRead::get_block_hash`], never from a publication.
/// At or below the target a height the wallet holds is accepted exactly when the
/// offered display hex parses to the wallet's hash, and rejected otherwise. Above
/// the target, and wherever the wallet holds no block or cannot be read, the
/// answer is [`Acceptance::Unknown`], so a pass stops rather than trusting the
/// publisher. Build it with the target of the watch set the pass recovers.
pub struct WalletChain<'a, W: ?Sized> {
    wallet: &'a W,
    target: ChainPoint,
}

impl<'a, W: WalletRead + ?Sized> WalletChain<'a, W> {
    /// A view of `wallet`'s scanned blocks through `target`.
    pub fn new(wallet: &'a W, target: ChainPoint) -> Self {
        Self { wallet, target }
    }

    /// The wallet's hash at `height`, when `height` is at or below the target and
    /// the wallet holds and can read that block.
    fn held(&self, height: u64) -> Option<BlockHash> {
        if height > height_u64(self.target.height) {
            return None;
        }
        let height = BlockHeight::from(u32::try_from(height).ok()?);
        self.wallet.get_block_hash(height).ok().flatten()
    }
}

impl<W: WalletRead + ?Sized> ChainView for WalletChain<'_, W> {
    fn is_accepted(&self, height: u64, hash_display_hex: &str) -> Acceptance {
        match self.held(height) {
            None => Acceptance::Unknown,
            Some(held)
                if block_hash_from_display(hash_display_hex)
                    .is_ok_and(|offered| offered == held) =>
            {
                Acceptance::Accepted
            }
            Some(_) => Acceptance::Rejected,
        }
    }

    fn tip(&self) -> Option<Anchor> {
        Some(Anchor {
            height: height_u64(self.target.height),
            hash: self.target.hash.to_string(),
        })
    }

    fn hash_at(&self, height: u64) -> Option<String> {
        self.held(height).map(|hash| hash.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::testing::TestBuilder;
    use zcash_client_sqlite::testing::{BlockCache, db::TestDbFactory};

    #[test]
    fn wallet_chain_answers_only_through_its_target() {
        let mut state = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let first = state.sapling_activation_height();
        let tip = state.generate_and_scan_empty_blocks(4);
        let wallet = state.wallet();
        let scanned = |height: BlockHeight| wallet.get_block_hash(height).unwrap().unwrap();
        let target = ChainPoint {
            height: tip - 1,
            hash: scanned(tip - 1),
        };
        let chain = WalletChain::new(wallet, target);
        let at = |height: BlockHeight| u64::from(u32::from(height));

        // At and below the target, the wallet's own scanned hashes answer.
        for height in [first, first + 1, target.height] {
            let display = scanned(height).to_string();
            assert_eq!(
                chain.is_accepted(at(height), &display),
                Acceptance::Accepted
            );
            assert_eq!(
                chain.is_accepted(at(height), &display.to_uppercase()),
                Acceptance::Accepted
            );
            assert_eq!(chain.hash_at(at(height)), Some(display));
            assert_eq!(
                chain.is_accepted(at(height), &"ab".repeat(32)),
                Acceptance::Rejected
            );
            assert_eq!(
                chain.is_accepted(at(height), "not a block hash"),
                Acceptance::Rejected
            );
        }
        // Above the target, even a block the wallet has scanned is unknown.
        assert_eq!(
            chain.is_accepted(at(tip), &scanned(tip).to_string()),
            Acceptance::Unknown
        );
        assert_eq!(chain.hash_at(at(tip)), None);
        // Below its first scanned block the wallet holds nothing.
        assert_eq!(
            chain.is_accepted(at(first) - 1, &"00".repeat(32)),
            Acceptance::Unknown
        );
        assert_eq!(chain.hash_at(at(first) - 1), None);
        assert_eq!(
            chain.tip(),
            Some(Anchor {
                height: at(target.height),
                hash: target.hash.to_string(),
            })
        );
    }
}
