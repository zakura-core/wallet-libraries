//! The seam the private transparent ledger plugs into.
//!
//! Transparent funds are not discovered by scanning. A compact block carries
//! `vin` and `vout`, and this wallet used to match its own scripts against
//! them, but matching only finds a payment to an address that was already
//! derived when the block went past — and a restored wallet meets a receipt at
//! a high address index while its window is still narrow. The mechanism that
//! closed that gap named every address of an account to the server in one
//! request, which is the one disclosure the rest of this wallet is built to
//! avoid.
//!
//! Both are gone. What replaces them recovers from a birthday without naming
//! anything: public activity filters matched locally, then private retrieval of
//! history only from the ranges that matched. See
//! `docs/zakura_transparent_pir.md`.
//!
//! The trait is here and its implementation is not, for the same reason
//! [`Retrieval`](crate::retrieval::Retrieval) is: the engine should not carry a
//! PIR stack in its dependency graph in order to know that a transparent step
//! exists.
//!
//! `recover` is blocking and takes the wallet. Both are deliberate. The PIR
//! client is CPU-bound rather than IO-bound, so there is nothing for an async
//! runtime to interleave, and every check the ledger makes — that a shard sits
//! on the wallet's own accepted chain, that a script is one the wallet derived
//! — needs the wallet's own state to check against. The engine runs it the way
//! it runs detection: on a blocking task, with the connection moved in and
//! back out.

use zcash_protocol::consensus::BlockHeight;

/// The error a transparent source failed with.
///
/// Boxed so the trait stays object-safe: an engine holds whichever source it
/// was given without being generic over it, and the failure of a transparent
/// run is reported to the caller rather than interpreted by the engine.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// What one run of the transparent ledger did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransparentProgress {
    /// Outputs recovered and stored.
    pub outputs: usize,
    /// Spends of recovered outputs.
    pub spends: usize,
    /// Spends whose consumed output the run never saw.
    ///
    /// Non-zero means the balance is not synchronized, however current its
    /// coverage looks: an unresolved spend is an output the wallet still
    /// counts and something has already consumed.
    pub unresolved: usize,
    /// The lowest settled coverage across the wallet's scripts.
    ///
    /// `None` when nothing is watched, or when the run advanced nothing.
    pub settled_through: Option<BlockHeight>,
    /// The lowest coverage including any unsealed tail.
    pub covered_through: Option<BlockHeight>,
}

/// A source of privately retrieved transparent history.
pub trait TransparentSource: Send + Sync + 'static {
    /// Reads from wherever coverage currently reaches and commits what it
    /// recovers.
    ///
    /// Takes the wallet rather than returning rows to be written by the caller:
    /// the events and the coverage that explains them have to be committed
    /// together. A caller that wrote events without their coverage would pay to
    /// re-derive them on the next run; one that wrote coverage without its
    /// events would never look at that range again.
    fn recover(
        &self,
        db: &mut zakura_wallet_store::WalletDb,
    ) -> Result<TransparentProgress, BoxError>;
}
