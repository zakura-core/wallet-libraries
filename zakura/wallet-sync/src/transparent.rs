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

use std::fmt;

use zcash_protocol::consensus::BlockHeight;

/// The error a transparent source failed with.
///
/// Boxed so the trait stays object-safe: an engine holds whichever source it
/// was given without being generic over it, and the failure of a transparent
/// run is reported to the caller rather than interpreted by the engine.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Whether a run finished what it set out to read.
///
/// A run that stopped short is not a failure — everything it committed is
/// kept, and the next run continues it — but it is not a synchronized balance
/// either, and the interface must not present it as one. The reason is the
/// library's own wording, so what a person sees is what the log says:
/// `query-budget`, `byte-budget`, `pending-limit`, `overloaded:<shard>`,
/// `chain-unknown:<height>`, `publication-behind:<height>`, `unresolved-spends`,
/// `discovery-unbounded`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TransparentCompletion {
    /// Every script is covered from its required height to the accepted target.
    #[default]
    Complete,
    /// The run stopped short, for this reason.
    Incomplete(String),
}

impl TransparentCompletion {
    /// Whether the run read everything it meant to.
    pub fn is_complete(&self) -> bool {
        matches!(self, TransparentCompletion::Complete)
    }
}

impl fmt::Display for TransparentCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransparentCompletion::Complete => f.write_str("complete"),
            TransparentCompletion::Incomplete(reason) => f.write_str(reason),
        }
    }
}

/// What one run of the transparent ledger did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransparentProgress {
    /// Outputs recovered and stored by this run.
    pub outputs: usize,
    /// Spends of recovered outputs stored by this run.
    pub spends: usize,
    /// Spends whose consumed output the ledger has never seen.
    ///
    /// Non-zero means the balance is not synchronized, however current its
    /// coverage looks: an unresolved spend is an output the wallet still
    /// counts and something has already consumed.
    pub unresolved: usize,
    /// The lowest settled coverage across the wallet's scripts.
    ///
    /// `None` when nothing is watched, or when the run read nothing.
    pub settled_through: Option<BlockHeight>,
    /// The lowest coverage including any unsealed tail.
    pub covered_through: Option<BlockHeight>,
    /// Whether the run finished, and if not, why.
    pub completion: TransparentCompletion,
    /// Page retrievals still owed after this run.
    pub pending: usize,
    /// The height everything above was rolled back to, if this run found a
    /// reorg or a replaced provisional tail.
    pub rolled_back_to: Option<BlockHeight>,
    /// Scripts the private tables cannot index, so their history is outside
    /// what this path can recover. Not empty: unknown.
    pub outside_coverage: usize,
}

impl TransparentProgress {
    /// Whether the transparent balance may be called synchronized: the run
    /// completed and nothing it holds contradicts itself.
    pub fn is_synchronized(&self) -> bool {
        self.completion.is_complete() && self.unresolved == 0 && self.pending == 0
    }
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
    ///
    /// A run that stops short is `Ok` with a reason, not an error. Everything
    /// it committed is kept; what it did not read is still owed, and the
    /// engine reports the state rather than failing the pass.
    fn recover(
        &self,
        db: &mut zakura_wallet_store::WalletDb,
    ) -> Result<TransparentProgress, BoxError>;
}
