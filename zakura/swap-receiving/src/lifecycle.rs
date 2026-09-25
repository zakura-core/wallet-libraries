//! Shared swap completion policy. Wallet storage owns canonical-chain validation,
//! receipt attribution, and atomic persistence of this state with scan coverage.

use std::ops::Range;

use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

/// A block on the wallet's accepted Zcash chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainAnchor {
    /// Block height.
    pub height: BlockHeight,
    /// Block hash in the wallet's canonical byte representation.
    pub hash: [u8; 32],
}

/// Defaults are wallet conventions, not consensus parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionPolicy {
    /// Additional blocks to scan after observing terminal status.
    pub grace_blocks: u32,
    /// Seconds after first terminal observation before directory reconciliation.
    pub reconciliation_delay_secs: u64,
}

impl Default for CompletionPolicy {
    fn default() -> Self {
        Self {
            grace_blocks: 10,
            reconciliation_delay_secs: 12 * 60 * 60,
        }
    }
}

/// The route adapter's interpretation of the expected Zcash receipt.
/// Incoming source-chain refunds must not be interpreted as Zcash refunds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptExpectation {
    /// The supported route explicitly establishes that no Zcash receipt is expected.
    None,
    /// A positive receipt is expected. `None` means its amount is unavailable.
    Positive(Option<Zatoshis>),
    /// Receipt details are missing, malformed, or otherwise inconclusive.
    Unknown,
}

/// Current receipt accounting, recomputed from the wallet's canonical notes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptAccounting {
    /// Required notes are unconfirmed, or attribution to this operation is ambiguous.
    Unresolved,
    /// Every receipt is resolved under ordinary confirmation policy and attributed
    /// exclusively to this operation. Never count one note toward two operations.
    /// Zero notes and value are valid when a completed directory check found none.
    Resolved {
        /// Number of confirmed notes, including notes already spent.
        note_count: usize,
        /// Their actual on-chain value, not an API-reported balance.
        total: Zatoshis,
    },
}

/// The first terminal observation and its durable deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalObservation {
    tip: ChainAnchor,
    observed_at: u64,
    grace_target: BlockHeight,
    reconcile_after: u64,
}

impl TerminalObservation {
    fn new(tip: ChainAnchor, now: u64, policy: CompletionPolicy) -> Result<Self, LifecycleError> {
        let height = u32::from(tip.height)
            .checked_add(policy.grace_blocks)
            .ok_or(LifecycleError::DeadlineOverflow)?;
        let due = now
            .checked_add(policy.reconciliation_delay_secs)
            .ok_or(LifecycleError::DeadlineOverflow)?;
        Self::from_parts(tip, now, height.into(), due)
    }

    /// Reconstructs persisted deadlines without applying today's defaults.
    pub fn from_parts(
        tip: ChainAnchor,
        observed_at: u64,
        grace_target: BlockHeight,
        reconcile_after: u64,
    ) -> Result<Self, LifecycleError> {
        if grace_target < tip.height || reconcile_after < observed_at {
            return Err(LifecycleError::InvalidState);
        }
        Ok(Self {
            tip,
            observed_at,
            grace_target,
            reconcile_after,
        })
    }

    /// Accepted tip at the first terminal observation.
    pub fn tip(&self) -> ChainAnchor {
        self.tip
    }
    /// Unix timestamp in seconds of that observation.
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }
    /// Inclusive height through which this key must have scanned.
    pub fn grace_target(&self) -> BlockHeight {
        self.grace_target
    }
    /// Unix timestamp in seconds when reconciliation becomes due.
    pub fn reconcile_after(&self) -> u64 {
        self.reconcile_after
    }
}

/// Durable state of the one logical directory reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    /// A target has not yet been selected, or an earlier target was invalidated.
    NotStarted,
    /// Preserve this target across retries, pagination, and restarts.
    Pending(ChainAnchor),
    /// All returned payments through the target were resolved.
    Complete {
        /// Accepted chain anchor checked by the directory query.
        target: ChainAnchor,
        /// Earliest height covered by the validated result.
        covered_from: BlockHeight,
    },
}

/// A directory result validated by the caller against the accepted chain and
/// publication. This is not a raw server response or a proof of non-omission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconciliationResult {
    /// The saved target that this response was checked against, including its hash.
    pub target: ChainAnchor,
    /// Inclusive lower bound of complete directory coverage.
    pub covered_from: BlockHeight,
    /// Inclusive upper bound of complete directory coverage.
    pub covered_through: BlockHeight,
    /// Every returned payment was resolved into canonical wallet accounting,
    /// including unambiguous operation attribution and ordinary confirmations.
    /// An empty result is complete only if publication coverage and every required
    /// page were validated.
    pub all_payments_resolved: bool,
}

/// Why this operation still needs trial decryption, or can leave the active set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanDecision {
    /// No supported terminal observation is available.
    NoTerminalStatus,
    /// Some required history through the saved grace target remains unscanned.
    MissingCoverage,
    /// The expected receipt or required reconciliation remains unresolved.
    UnresolvedReceipt,
    /// Trial decryption may stop. Delayed reconciliation can still be pending.
    Retire,
}

/// Persist this state per operation. Multiple operations may share a receiving key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    terminal: Option<TerminalObservation>,
    expectation: ReceiptExpectation,
    reconciliation: Reconciliation,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            terminal: None,
            expectation: ReceiptExpectation::Unknown,
            reconciliation: Reconciliation::NotStarted,
        }
    }
}

impl Lifecycle {
    /// Restores durable state without moving deadlines or query targets.
    pub fn from_parts(
        terminal: Option<TerminalObservation>,
        expectation: ReceiptExpectation,
        reconciliation: Reconciliation,
    ) -> Result<Self, LifecycleError> {
        validate_expectation(expectation)?;
        match terminal {
            None if expectation != ReceiptExpectation::Unknown
                || reconciliation != Reconciliation::NotStarted =>
            {
                return Err(LifecycleError::InvalidState);
            }
            Some(observation) => {
                let target = match reconciliation {
                    Reconciliation::NotStarted => None,
                    Reconciliation::Pending(target) => Some(target),
                    Reconciliation::Complete {
                        target,
                        covered_from,
                    } => {
                        if covered_from > target.height {
                            return Err(LifecycleError::InvalidState);
                        }
                        Some(target)
                    }
                };
                if target.is_some_and(|t| t.height < observation.grace_target) {
                    return Err(LifecycleError::InvalidState);
                }
            }
            None => {}
        }
        Ok(Self {
            terminal,
            expectation,
            reconciliation,
        })
    }

    /// Saved terminal evidence. Persist all fields before retiring a key.
    pub fn terminal(&self) -> Option<TerminalObservation> {
        self.terminal
    }
    /// Current route-specific receipt expectation.
    pub fn expectation(&self) -> ReceiptExpectation {
        self.expectation
    }
    /// Saved directory query progress.
    pub fn reconciliation(&self) -> Reconciliation {
        self.reconciliation
    }

    /// Records supported terminal status. Repeated observations preserve the
    /// original deadlines. Changed receipt details invalidate directory completion.
    /// Unknown statuses and transport errors must not call this method.
    pub fn observe_terminal(
        &mut self,
        tip: ChainAnchor,
        now: u64,
        expectation: ReceiptExpectation,
        policy: CompletionPolicy,
    ) -> Result<(), LifecycleError> {
        validate_expectation(expectation)?;
        let terminal = match self.terminal {
            Some(saved) => saved,
            None => TerminalObservation::new(tip, now, policy)?,
        };
        if self.expectation != expectation {
            self.reconciliation = Reconciliation::NotStarted;
        }
        self.terminal = Some(terminal);
        self.expectation = expectation;
        Ok(())
    }

    /// A supported nonterminal status has replaced terminal status. Network
    /// failures and unknown statuses preserve state instead of calling this.
    pub fn resume(&mut self) {
        *self = Self::default();
    }

    /// Invalidates completion anchored above the retained canonical height.
    /// The caller must also trim scan coverage and invalidate reorged receipts.
    pub fn rewind(&mut self, retained: BlockHeight) {
        if self.terminal.is_some_and(|t| t.tip.height > retained) {
            self.resume();
        } else {
            let target = match self.reconciliation {
                Reconciliation::NotStarted => None,
                Reconciliation::Pending(t) | Reconciliation::Complete { target: t, .. } => Some(t),
            };
            if target.is_some_and(|t| t.height > retained) {
                self.reconciliation = Reconciliation::NotStarted;
            }
        }
    }

    /// Selects a target when due and the accepted tip has reached the grace height.
    /// Returns an existing pending target unchanged. Earlier required history
    /// invalidates an inadequate completed check. Persist the target before querying.
    pub fn begin_reconciliation(
        &mut self,
        now: u64,
        tip: ChainAnchor,
        scan_from: BlockHeight,
    ) -> Option<ChainAnchor> {
        let terminal = self.terminal?;
        if tip.height < scan_from {
            return None;
        }
        if matches!(self.reconciliation,
            Reconciliation::Complete { covered_from, .. } if covered_from > scan_from)
        {
            self.reconciliation = Reconciliation::NotStarted;
        }
        match self.reconciliation {
            Reconciliation::Pending(target) => (tip.height >= target.height).then_some(target),
            Reconciliation::Complete { .. } => None,
            Reconciliation::NotStarted
                if now >= terminal.reconcile_after && tip.height >= terminal.grace_target =>
            {
                self.reconciliation = Reconciliation::Pending(tip);
                Some(tip)
            }
            Reconciliation::NotStarted => None,
        }
    }

    /// Completes a pending query only with adequate coverage and resolved payments.
    /// `false` leaves it pending. Transport errors do not call this method.
    pub fn finish_reconciliation(
        &mut self,
        scan_from: BlockHeight,
        result: ReconciliationResult,
    ) -> Result<bool, LifecycleError> {
        let Reconciliation::Pending(target) = self.reconciliation else {
            return Err(LifecycleError::NoPendingReconciliation);
        };
        if result.target != target {
            return Err(LifecycleError::StaleTarget);
        }
        if scan_from > target.height
            || result.covered_from > scan_from
            || result.covered_through < target.height
            || result.covered_from > result.covered_through
            || !result.all_payments_resolved
        {
            return Ok(false);
        }
        self.reconciliation = Reconciliation::Complete {
            target,
            covered_from: result.covered_from,
        };
        Ok(true)
    }

    /// Evaluates retirement using current canonical coverage and receipt accounting.
    /// Coverage must be sorted by start height. Overlaps are allowed, gaps are not.
    /// Recompute after receipt changes or rewinds, even if the key was retired.
    pub fn scan_decision(
        &self,
        scan_from: BlockHeight,
        coverage: &[Range<BlockHeight>],
        receipts: ReceiptAccounting,
    ) -> ScanDecision {
        let Some(terminal) = self.terminal else {
            return ScanDecision::NoTerminalStatus;
        };
        if !covers_through(coverage, scan_from, terminal.grace_target) {
            return ScanDecision::MissingCoverage;
        }
        let accounted = match self.expectation {
            ReceiptExpectation::None => true,
            ReceiptExpectation::Positive(expected) => match receipts {
                ReceiptAccounting::Resolved { note_count, total } => {
                    note_count > 0
                        && total > Zatoshis::ZERO
                        && expected.is_none_or(|amount| total >= amount)
                }
                ReceiptAccounting::Unresolved => false,
            },
            ReceiptExpectation::Unknown => {
                receipts != ReceiptAccounting::Unresolved
                    && matches!(self.reconciliation,
                    Reconciliation::Complete { covered_from, .. } if covered_from <= scan_from)
            }
        };
        if accounted {
            ScanDecision::Retire
        } else {
            ScanDecision::UnresolvedReceipt
        }
    }
}

/// A key remains active for unknown uses, an empty operation list (such as restored
/// lookahead), or any operation still requiring scanning. Supply every linked use.
pub fn key_needs_scanning(
    decisions: impl IntoIterator<Item = ScanDecision>,
    has_unknown_use: bool,
) -> bool {
    let mut any = false;
    for decision in decisions {
        any = true;
        if decision != ScanDecision::Retire {
            return true;
        }
    }
    has_unknown_use || !any
}

fn covers_through(ranges: &[Range<BlockHeight>], from: BlockHeight, through: BlockHeight) -> bool {
    if from > through {
        return false;
    }
    let mut next = from;
    for range in ranges {
        if range.is_empty() || range.end <= next {
            continue;
        }
        if range.start > next {
            return false;
        }
        if range.end > through {
            return true;
        }
        next = range.end;
    }
    false
}

fn validate_expectation(expectation: ReceiptExpectation) -> Result<(), LifecycleError> {
    if expectation == ReceiptExpectation::Positive(Some(Zatoshis::ZERO)) {
        Err(LifecycleError::InvalidState)
    } else {
        Ok(())
    }
}

/// Invalid lifecycle data or an obsolete asynchronous directory result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    /// Computing a deadline would overflow its height or timestamp representation.
    DeadlineOverflow,
    /// Persisted fields or receipt expectations contradict each other.
    InvalidState,
    /// Completion was attempted without a pending query.
    NoPendingReconciliation,
    /// The response belongs to a different target or chain revision.
    StaleTarget,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DeadlineOverflow => "swap completion deadline overflow",
            Self::InvalidState => "invalid swap completion state",
            Self::NoPendingReconciliation => "no pending swap reconciliation",
            Self::StaleTarget => "swap reconciliation target changed",
        })
    }
}
impl std::error::Error for LifecycleError {}

#[cfg(test)]
mod tests;
