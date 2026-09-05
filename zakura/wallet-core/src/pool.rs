//! The shielded pool abstraction.
//!
//! Orchard and Ironwood are structurally one protocol. They share
//! [`orchard::note::Note`], [`orchard::note::Nullifier`],
//! [`orchard::tree::MerkleHashOrchard`], the action circuit, the Orchard
//! receiver, and the ZIP 32 keys used to spend and view. Ironwood (ZIP 2005,
//! activating at NU6.3) differs in exactly three ways that matter to a wallet:
//!
//! 1. its note plaintexts are V3 (lead byte `0x03`, with `rcm` derived by
//!    `rcm_v3`), which is expressed here as a distinct [`ShieldedPool::Domain`];
//! 2. it maintains its own note commitment tree, anchors and nullifier set; and
//! 3. it only appears in v6 transactions.
//!
//! Only the first is a *type* difference, so it is the only associated type on
//! the trait. Everything else — notes, nullifiers, tree nodes, compact actions —
//! stays concrete and shared. Making those associated "for symmetry" is what
//! turns a pool abstraction into a leaky one, because it invites callers to
//! believe two pools might disagree about a type that they cannot.
//!
//! Transparent is deliberately *not* a [`ShieldedPool`]. It has no trial
//! decryption, no commitment tree, no positions and no nullifiers; forcing it
//! into this trait would mean fields that are permanently `None` and invariants
//! nobody can state. Transparent and shielded funds unify one level up, where
//! input selection and balance care about spendable value rather than about how
//! it was found.

use orchard::{
    keys::PreparedIncomingViewingKey,
    note::Note,
    note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
};
use zcash_note_encryption::{BatchDomain, COMPACT_NOTE_SIZE, ShieldedOutput, batch};
use zcash_protocol::{
    ShieldedPool as ProtocolPool,
    consensus::{BlockHeight, NetworkUpgrade, Parameters},
};

use crate::block::CompactTx;

/// The shielded pools this wallet supports.
///
/// Sapling is deliberately absent: this wallet does not scan, store or spend
/// Sapling notes. The discriminants match the pool codes used in the wallet
/// database and in [`zcash_protocol::PoolType`], so they are wire-stable and
/// must not be renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PoolId {
    /// The Orchard pool, active from NU5.
    Orchard = 3,
    /// The Ironwood pool, active from NU6.3.
    Ironwood = 4,
}

impl PoolId {
    /// Every pool this wallet supports, in ascending code order.
    pub const ALL: [PoolId; 2] = [PoolId::Orchard, PoolId::Ironwood];

    /// Returns the wire-stable code stored in the database for this pool.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Returns the pool with the given database code, or `None` if the code is
    /// not one this wallet supports.
    ///
    /// Codes for pools outside this wallet's scope — transparent (0) and
    /// Sapling (2) — return `None` rather than panicking, because they can
    /// legitimately appear in data written by another implementation.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            3 => Some(PoolId::Orchard),
            4 => Some(PoolId::Ironwood),
            _ => None,
        }
    }
}

impl From<PoolId> for ProtocolPool {
    fn from(id: PoolId) -> Self {
        match id {
            PoolId::Orchard => ProtocolPool::Orchard,
            PoolId::Ironwood => ProtocolPool::Ironwood,
        }
    }
}

/// A shielded pool, as a type.
///
/// Implementors are the zero-sized markers [`Orchard`] and [`Ironwood`]. Code
/// that is the same for both pools is written once, generic in `P`; code that
/// needs a pool value at runtime uses [`dispatch`].
pub trait ShieldedPool: Copy + 'static {
    /// The runtime identity of this pool.
    const ID: PoolId;

    /// The height of a note commitment tree shard, as a number of levels.
    ///
    /// Both pools use Orchard's geometry. This is a constant rather than a
    /// value because the shard store is generic over it.
    const SHARD_HEIGHT: u8 = 16;

    /// The network upgrade at which this pool activates.
    ///
    /// No note of this pool can exist below its activation height, so a scan
    /// range entirely below it need never be fetched for this pool's sake.
    const ACTIVATION: NetworkUpgrade;

    /// The note-encryption domain for this pool.
    ///
    /// This is the only genuine type-level difference between the pools: the
    /// domain fixes the note plaintext version that trial decryption will
    /// accept, so an Orchard note cannot be mistaken for an Ironwood one even
    /// though both decrypt under the same incoming viewing key.
    type Domain: BatchDomain<Note = Note, IncomingViewingKey = PreparedIncomingViewingKey>
        + Send
        + Sync;

    /// Returns this pool's compact actions within a compact transaction.
    fn actions(tx: &CompactTx) -> &[CompactAction];

    /// Returns the size of this pool's note commitment tree as of the end of
    /// the block whose metadata is given.
    fn tree_size(sizes: &TreeSizes) -> u32;

    /// Returns a mutable reference to this pool's slot in `sizes`.
    fn tree_size_mut(sizes: &mut TreeSizes) -> &mut u32;

    /// Constructs the domain under which this action's output note is trial
    /// decrypted.
    fn domain_for(action: &CompactAction) -> Self::Domain;

    /// Trial-decrypts a batch of this pool's compact actions.
    ///
    /// Returns one entry per output, in the order given: the decrypted note and
    /// the index of the viewing key that opened it, or `None` if no key did.
    ///
    /// This is a method on the pool rather than a free function so that the
    /// `ShieldedOutput` relationship between [`CompactAction`] and
    /// [`Self::Domain`] is discharged once, here, instead of reappearing as a
    /// `where` clause on every generic function that scans a block.
    ///
    /// Batching is not merely a loop: the underlying implementation amortises
    /// the per-output scalar multiplication across the whole slice, so calling
    /// this once with many outputs is substantially cheaper than calling it
    /// many times with one.
    fn batch_decrypt(
        ivks: &[PreparedIncomingViewingKey],
        outputs: &[(Self::Domain, CompactAction)],
    ) -> Vec<Option<(Note, usize)>>;

    /// Returns the height at which this pool activates on `params`, or `None`
    /// if the network has no activation height for it.
    fn activation_height<P: Parameters>(params: &P) -> Option<BlockHeight> {
        params.activation_height(Self::ACTIVATION)
    }
}

/// The size of each pool's note commitment tree as of the end of a block.
///
/// Kept as one struct with a field per pool, rather than a map, so that a pool
/// added in future is a compile error at every site that must handle it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeSizes {
    /// The size of the Orchard note commitment tree.
    pub orchard: u32,
    /// The size of the Ironwood note commitment tree.
    pub ironwood: u32,
}

impl TreeSizes {
    /// Returns the size of the given pool's tree.
    pub fn get(&self, pool: PoolId) -> u32 {
        match pool {
            PoolId::Orchard => self.orchard,
            PoolId::Ironwood => self.ironwood,
        }
    }
}


/// The body of [`ShieldedPool::batch_decrypt`], shared by both pools.
///
/// Both pools decrypt identically; only the domain differs, which is exactly
/// what the type parameter carries.
fn batch_decrypt_actions<D>(
    ivks: &[PreparedIncomingViewingKey],
    outputs: &[(D, CompactAction)],
) -> Vec<Option<(Note, usize)>>
where
    D: BatchDomain<Note = Note, IncomingViewingKey = PreparedIncomingViewingKey>,
    CompactAction: ShieldedOutput<D, COMPACT_NOTE_SIZE>,
{
    batch::try_compact_note_decryption(ivks, outputs)
        .into_iter()
        .map(|res| res.map(|((note, _recipient), ivk_index)| (note, ivk_index)))
        .collect()
}

/// The Orchard pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Orchard;

/// The Ironwood pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ironwood;

impl ShieldedPool for Orchard {
    const ID: PoolId = PoolId::Orchard;
    const ACTIVATION: NetworkUpgrade = NetworkUpgrade::Nu5;
    type Domain = OrchardDomain;

    fn actions(tx: &CompactTx) -> &[CompactAction] {
        &tx.orchard_actions
    }

    fn tree_size(sizes: &TreeSizes) -> u32 {
        sizes.orchard
    }

    fn tree_size_mut(sizes: &mut TreeSizes) -> &mut u32 {
        &mut sizes.orchard
    }

    fn domain_for(action: &CompactAction) -> Self::Domain {
        OrchardDomain::for_compact_action(action)
    }

    fn batch_decrypt(
        ivks: &[PreparedIncomingViewingKey],
        outputs: &[(Self::Domain, CompactAction)],
    ) -> Vec<Option<(Note, usize)>> {
        batch_decrypt_actions(ivks, outputs)
    }
}

impl ShieldedPool for Ironwood {
    const ID: PoolId = PoolId::Ironwood;
    const ACTIVATION: NetworkUpgrade = NetworkUpgrade::Nu6_3;
    type Domain = IronwoodDomain;

    fn actions(tx: &CompactTx) -> &[CompactAction] {
        &tx.ironwood_actions
    }

    fn tree_size(sizes: &TreeSizes) -> u32 {
        sizes.ironwood
    }

    fn tree_size_mut(sizes: &mut TreeSizes) -> &mut u32 {
        &mut sizes.ironwood
    }

    fn domain_for(action: &CompactAction) -> Self::Domain {
        IronwoodDomain::for_compact_action(action)
    }

    fn batch_decrypt(
        ivks: &[PreparedIncomingViewingKey],
        outputs: &[(Self::Domain, CompactAction)],
    ) -> Vec<Option<(Note, usize)>> {
        batch_decrypt_actions(ivks, outputs)
    }
}

/// An operation that is generic over the shielded pool it acts on.
///
/// This is the bridge from a runtime [`PoolId`] to a static [`ShieldedPool`]
/// type parameter. Implement it for the operation, then call [`dispatch`].
pub trait PoolVisitor {
    /// The result of the operation.
    type Out;

    /// Performs the operation for pool `P`.
    fn visit<P: ShieldedPool>(self) -> Self::Out;
}

/// Runs `v` for the pool named by `id`.
///
/// This is the only place in the workspace that matches on a pool identity to
/// choose a type. Everything downstream is written once, generically; adding a
/// pool means adding an arm here and nowhere else.
pub fn dispatch<V: PoolVisitor>(id: PoolId, v: V) -> V::Out {
    match id {
        PoolId::Orchard => v.visit::<Orchard>(),
        PoolId::Ironwood => v.visit::<Ironwood>(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_codes_round_trip() {
        for pool in PoolId::ALL {
            assert_eq!(PoolId::from_code(pool.code()), Some(pool));
        }
    }

    #[test]
    fn pool_codes_match_the_wallet_database() {
        // These are the `output_pool` codes the existing wallet schema uses.
        // Renumbering them would silently reinterpret stored rows.
        assert_eq!(PoolId::Orchard.code(), 3);
        assert_eq!(PoolId::Ironwood.code(), 4);
    }

    #[test]
    fn pools_convert_to_the_protocol_enum() {
        // The protocol enum also carries Sapling, which this wallet has no
        // variant for; conversion is deliberately one-way.
        assert_eq!(ProtocolPool::from(PoolId::Orchard), ProtocolPool::Orchard);
        assert_eq!(ProtocolPool::from(PoolId::Ironwood), ProtocolPool::Ironwood);
    }

    #[test]
    fn unsupported_pool_codes_are_rejected() {
        // Transparent (0) and Sapling (2) are out of scope, and a wallet
        // written by another implementation may still use them.
        assert_eq!(PoolId::from_code(0), None);
        assert_eq!(PoolId::from_code(2), None);
        assert_eq!(PoolId::from_code(5), None);
    }

    struct PoolIdentity;

    impl PoolVisitor for PoolIdentity {
        type Out = PoolId;

        fn visit<P: ShieldedPool>(self) -> PoolId {
            P::ID
        }
    }

    #[test]
    fn dispatch_selects_the_named_pool() {
        for pool in PoolId::ALL {
            assert_eq!(dispatch(pool, PoolIdentity), pool);
        }
    }

    struct ShardHeight;

    impl PoolVisitor for ShardHeight {
        type Out = u8;

        fn visit<P: ShieldedPool>(self) -> u8 {
            P::SHARD_HEIGHT
        }
    }

    #[test]
    fn both_pools_use_orchard_shard_geometry() {
        for pool in PoolId::ALL {
            assert_eq!(dispatch(pool, ShardHeight), 16);
        }
    }

    #[test]
    fn tree_sizes_are_addressable_both_ways() {
        let mut sizes = TreeSizes::default();
        *Orchard::tree_size_mut(&mut sizes) = 7;
        *Ironwood::tree_size_mut(&mut sizes) = 11;

        assert_eq!(Orchard::tree_size(&sizes), 7);
        assert_eq!(Ironwood::tree_size(&sizes), 11);
        assert_eq!(sizes.get(PoolId::Orchard), 7);
        assert_eq!(sizes.get(PoolId::Ironwood), 11);
    }
}
