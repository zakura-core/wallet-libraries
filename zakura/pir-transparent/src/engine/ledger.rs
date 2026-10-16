//! Replaying validated events into a UTXO set, a balance and a history.
//!
//! This is the wallet's own arithmetic, and it is deliberately separate from
//! everything that fetches. It takes events and produces state; it has no
//! opinion about where the events came from, which is what lets the same code
//! be driven by private retrieval in the POC and by an independent traversal of
//! the chain in the equality check.
//!
//! # What it refuses to do
//!
//! It does not decide spendability. Recovering a receive does not make an
//! output spendable: confirmation depth, coinbase maturity, key availability
//! and dust policy are all wallet policy, and they stay with the wallet.
//! [`Ledger::confirmed_balance`] is the sum of what exists, not of what can be
//! spent.
//!
//! It does not silently absorb a spend of an output it has never seen. That is
//! unresolved work — it may mean missing historical coverage, an incomplete
//! index, an unsupported script class, or a malformed response — and it is
//! recorded rather than ignored, because ignoring it produces a balance that is
//! too high and looks perfectly normal.

use std::collections::BTreeMap;
use transparent_events::{
    FeeState, ReceiveEvent, SpendEvent, TransactionMetadata, TransparentEvent, Txid,
};

/// An output the wallet controls, as recovered from the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: Txid,
    pub output_index: u32,
    pub value: u64,
    /// The exact raw locking script the event was indexed under.
    pub script: Vec<u8>,
    pub creation_height: u32,
    /// Retained for the wallet's maturity policy, which this does not apply.
    pub coinbase: bool,
}

/// A spend of a recovered output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedSpend {
    pub input_index: u32,
    pub spent_txid: Txid,
    pub spent_output_index: u32,
    pub spending_txid: Txid,
    pub height: u32,
    pub value: u64,
    pub script: Vec<u8>,
}

/// A spend whose consumed output the ledger never saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedSpend {
    pub event: SpendEvent,
    pub script: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("transaction metadata contradicts recovered history: {0}")]
    Metadata(#[from] transparent_events::EventError),
    #[error("outpoint {0}:{1} was received twice with different contents")]
    ConflictingReceive(String, u32),
    #[error("outpoint {0}:{1} was spent twice, by different transactions")]
    DoubleSpend(String, u32),
}

/// One transaction's effect on the wallet, for history presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionSummary {
    pub txid: Txid,
    pub height: u32,
    /// Value of wallet outputs this transaction created.
    pub received: u64,
    /// Value of wallet outputs this transaction consumed.
    pub spent: u64,
    pub metadata: Option<TransactionMetadata>,
    /// Includes known spends whose input values are still unresolved.
    pub owned_input_count: u32,
    pub unresolved_input_count: u32,
}

impl TransactionSummary {
    /// Aggregate external payment is available only with complete selected-account
    /// effects and sole funding. The caller supplies independently established coverage.
    pub fn aggregate_payment(&self, owned_effects_complete: bool) -> Option<u64> {
        let metadata = self.metadata?;
        let FeeState::Exact(fee) = metadata.fee else {
            return None;
        };
        if !owned_effects_complete
            || metadata.has_shielded_components
            || self.unresolved_input_count != 0
            || self.owned_input_count == 0
            || self.owned_input_count != metadata.transparent_input_count
        {
            return None;
        }
        self.spent.checked_sub(self.received)?.checked_sub(fee)
    }
    /// Received minus spent.
    ///
    /// This is recovered account movement; unresolved values remain explicitly partial.
    pub fn net(&self) -> i128 {
        self.received as i128 - self.spent as i128
    }
}

/// Canonical chain order and event identity, matching `TransparentEvent::sort_key`.
type ObservationKey = (u32, u16, u8, Txid, u32, Txid, u32);

#[derive(Debug, Default)]
pub struct Ledger {
    observations: BTreeMap<ObservationKey, TransparentEvent>,
    utxos: BTreeMap<(Txid, u32), Utxo>,
    /// Every recovered receive, kept after it is spent so history survives.
    receives: BTreeMap<(Txid, u32), Utxo>,
    spends: Vec<ConfirmedSpend>,
    /// Index into `spends` by consumed outpoint, so a long history does not
    /// pay a scan per spend.
    spent_index: BTreeMap<(Txid, u32), usize>,
    unresolved: Vec<UnresolvedSpend>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replays events in chain order.
    ///
    /// Sorting here rather than requiring sorted input is deliberate: a spend
    /// can only be matched to its receive if the receive was applied first, and
    /// events arrive from several pages and inline slots whose concatenation is
    /// not ordered. The order is the canonical one — height, then position in
    /// the block, then receives before spends within a transaction, then the
    /// event's own identity — so the result does not depend on retrieval order.
    ///
    /// That order is also what resolves a receive and its spend within one
    /// block: an output cannot be consumed by the transaction that creates it,
    /// so the creating transaction always has the lower index.
    pub fn replay(
        &mut self,
        events: &mut [(Vec<u8>, TransparentEvent)],
    ) -> Result<(), LedgerError> {
        transparent_events::check_transaction_consistency(
            self.observations
                .values()
                .chain(events.iter().map(|(_, event)| event)),
        )?;
        events.sort_by_key(|entry| entry.1.sort_key());
        for (script, event) in events.iter() {
            self.apply(script, event)?;
            self.observations.insert(event.sort_key(), *event);
        }
        Ok(())
    }

    /// Applies a later batch to a ledger that already holds history, then
    /// retries every unresolved spend against the receives now present.
    ///
    /// This is a returning wallet's path: a receive kept from an earlier sync
    /// resolves a spend found today, and a receive found today — from a
    /// script's historical discovery after a gap-limit advance — resolves a
    /// spend recorded as unresolved earlier.
    pub fn extend(
        &mut self,
        events: &mut [(Vec<u8>, TransparentEvent)],
    ) -> Result<(), LedgerError> {
        self.replay(events)?;
        self.resolve_unresolved()
    }

    fn resolve_unresolved(&mut self) -> Result<(), LedgerError> {
        let pending = std::mem::take(&mut self.unresolved);
        for unresolved in pending {
            let key = (
                unresolved.event.spent_txid,
                unresolved.event.spent_output_index,
            );
            if self.receives.contains_key(&key) {
                self.apply_spend(&unresolved.script, &unresolved.event)?;
            } else {
                self.unresolved.push(unresolved);
            }
        }
        Ok(())
    }

    /// Removes every receive and spend above `height`, restoring outputs
    /// whose spend was removed but whose receive survives. A reorg, or a
    /// replaced provisional tail.
    pub fn truncate_above(&mut self, height: u32) {
        self.observations
            .retain(|_, event| event.height() <= height);
        self.receives
            .retain(|_, utxo| utxo.creation_height <= height);
        self.utxos.retain(|key, _| self.receives.contains_key(key));
        let kept: Vec<ConfirmedSpend> = self
            .spends
            .drain(..)
            .filter(|spend| spend.height <= height)
            .collect();
        self.spent_index.clear();
        self.spends = Vec::new();
        for spend in kept {
            let key = (spend.spent_txid, spend.spent_output_index);
            self.spent_index.insert(key, self.spends.len());
            self.spends.push(spend);
        }
        // An output whose spend was above the cut is unspent again.
        for (key, utxo) in &self.receives {
            if !self.spent_index.contains_key(key) {
                self.utxos.entry(*key).or_insert_with(|| utxo.clone());
            }
        }
        self.unresolved
            .retain(|unresolved| unresolved.event.height <= height);
    }

    fn apply(&mut self, script: &[u8], event: &TransparentEvent) -> Result<(), LedgerError> {
        match event {
            TransparentEvent::Receive(receive) => self.apply_receive(script, receive),
            TransparentEvent::Spend(spend) => self.apply_spend(script, spend),
        }
    }

    fn apply_receive(&mut self, script: &[u8], event: &ReceiveEvent) -> Result<(), LedgerError> {
        let utxo = Utxo {
            txid: event.txid,
            output_index: event.output_index,
            value: event.value,
            script: script.to_vec(),
            creation_height: event.height,
            coinbase: event.coinbase,
        };
        let key = (event.txid, event.output_index);
        // A repeat of the identical receive is idempotent — the same event can
        // reach the wallet through an inline slot and a page. A repeat with
        // different contents is not, and means two sources disagree about the
        // same outpoint.
        if let Some(existing) = self.receives.get(&key) {
            if *existing != utxo {
                return Err(LedgerError::ConflictingReceive(
                    event.txid.to_display_hex(),
                    event.output_index,
                ));
            }
            return Ok(());
        }
        self.receives.insert(key, utxo.clone());
        self.utxos.insert(key, utxo);
        Ok(())
    }

    fn apply_spend(&mut self, script: &[u8], event: &SpendEvent) -> Result<(), LedgerError> {
        let key = (event.spent_txid, event.spent_output_index);
        // Idempotent for the same spend arriving twice — through an inline slot
        // and a page, say. A second spend of the same outpoint by a *different*
        // transaction is not a repeat: one output cannot be consumed twice on
        // one chain, so the two sources contradict each other and taking either
        // one would produce a ledger that looks fine and is wrong.
        if let Some(existing) = self.spent_index.get(&key).map(|&index| &self.spends[index]) {
            if existing.spending_txid != event.spending_txid || existing.height != event.height {
                return Err(LedgerError::DoubleSpend(
                    event.spent_txid.to_display_hex(),
                    event.spent_output_index,
                ));
            }
            return Ok(());
        }
        match self.receives.get(&key) {
            Some(utxo) => {
                let spend = ConfirmedSpend {
                    input_index: event.input_index,
                    spent_txid: event.spent_txid,
                    spent_output_index: event.spent_output_index,
                    spending_txid: event.spending_txid,
                    height: event.height,
                    value: utxo.value,
                    script: utxo.script.clone(),
                };
                self.utxos.remove(&key);
                self.spent_index.insert(key, self.spends.len());
                self.spends.push(spend);
            }
            None => {
                // Not an error to record, but never silently dropped: a spend
                // of an output the wallet never saw means its recovered history
                // is incomplete, and a balance computed over it is too high.
                let unresolved = UnresolvedSpend {
                    event: *event,
                    script: script.to_vec(),
                };
                if !self.unresolved.contains(&unresolved) {
                    self.unresolved.push(unresolved);
                }
            }
        }
        Ok(())
    }

    /// Outputs recovered and not yet consumed.
    pub fn utxos(&self) -> impl Iterator<Item = &Utxo> {
        self.utxos.values()
    }

    pub fn spends(&self) -> &[ConfirmedSpend] {
        &self.spends
    }

    /// Spends of outputs this ledger never saw.
    ///
    /// A non-empty result means the reconstruction is incomplete. A caller must
    /// not present the balance as synchronized while this is non-empty.
    pub fn unresolved(&self) -> &[UnresolvedSpend] {
        &self.unresolved
    }

    /// Sum of the current UTXO set.
    ///
    /// Confirmed, not spendable. Applying maturity, depth and key availability
    /// is the wallet's job and is deliberately not done here.
    pub fn confirmed_balance(&self) -> u64 {
        self.utxos.values().map(|utxo| utxo.value).sum()
    }

    /// History grouped by transaction, ascending by height then transaction id.
    pub fn history(&self) -> Vec<TransactionSummary> {
        let mut by_txid: BTreeMap<Txid, TransactionSummary> = BTreeMap::new();
        for utxo in self.receives.values() {
            let entry = by_txid.entry(utxo.txid).or_insert(TransactionSummary {
                txid: utxo.txid,
                height: utxo.creation_height,
                received: 0,
                spent: 0,
                metadata: None,
                owned_input_count: 0,
                unresolved_input_count: 0,
            });
            entry.received += utxo.value;
            entry.height = entry.height.min(utxo.creation_height);
        }
        for spend in &self.spends {
            let entry = by_txid
                .entry(spend.spending_txid)
                .or_insert(TransactionSummary {
                    txid: spend.spending_txid,
                    height: spend.height,
                    received: 0,
                    spent: 0,
                    metadata: None,
                    owned_input_count: 0,
                    unresolved_input_count: 0,
                });
            entry.spent += spend.value;
            entry.height = entry.height.min(spend.height);
        }
        let mut input_ids = std::collections::BTreeSet::new();
        for event in self.observations.values() {
            let entry = by_txid.entry(event.txid()).or_insert(TransactionSummary {
                txid: event.txid(),
                height: event.height(),
                received: 0,
                spent: 0,
                metadata: None,
                owned_input_count: 0,
                unresolved_input_count: 0,
            });
            entry.metadata = event.metadata();
            if let TransparentEvent::Spend(spend) = event {
                if input_ids.insert((spend.spending_txid, spend.input_index)) {
                    entry.owned_input_count += 1;
                    if !self
                        .spent_index
                        .contains_key(&(spend.spent_txid, spend.spent_output_index))
                    {
                        entry.unresolved_input_count += 1;
                    }
                }
            }
        }
        let mut history: Vec<_> = by_txid.into_values().collect();
        history.sort_by_key(|summary| (summary.height, summary.txid));
        history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_payment_requires_sole_funding_complete_effects_and_values() {
        let summary = TransactionSummary {
            txid: txid(1),
            height: 10,
            received: 2000,
            spent: 10000,
            metadata: Some(TransactionMetadata {
                fee: FeeState::Exact(1000),
                transparent_input_count: 2,
                has_shielded_components: false,
            }),
            owned_input_count: 2,
            unresolved_input_count: 0,
        };
        assert_eq!(summary.aggregate_payment(true), Some(7000));
        assert_eq!(summary.aggregate_payment(false), None);
        let mut partial = summary.clone();
        partial.owned_input_count = 1;
        assert_eq!(partial.aggregate_payment(true), None);
        let mut mixed = summary.clone();
        mixed.metadata.as_mut().unwrap().has_shielded_components = true;
        assert_eq!(mixed.aggregate_payment(true), None);
        let mut unresolved = summary.clone();
        unresolved.unresolved_input_count = 1;
        assert_eq!(unresolved.aggregate_payment(true), None);
        let mut legacy = summary;
        legacy.metadata = None;
        assert_eq!(legacy.aggregate_payment(true), None);
        let ledger = replay(vec![spend(9, 9, 0, 2, 110)]);
        let history = ledger.history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].unresolved_input_count, 1);
    }

    fn txid(tag: u8) -> Txid {
        Txid([tag; 32])
    }

    fn script(tag: u8) -> Vec<u8> {
        vec![0x76, 0xa9, 0x14, tag]
    }

    fn receive(tag: u8, index: u32, value: u64, height: u32) -> (Vec<u8>, TransparentEvent) {
        (
            script(tag),
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height,
                txid: txid(tag),
                transaction_index: 0,
                output_index: index,
                value,
                coinbase: false,
            }),
        )
    }

    fn spend(
        script_tag: u8,
        spent: u8,
        spent_index: u32,
        spender: u8,
        height: u32,
    ) -> (Vec<u8>, TransparentEvent) {
        (
            script(script_tag),
            TransparentEvent::Spend(SpendEvent {
                metadata: None,
                height,
                spending_txid: txid(spender),
                transaction_index: 1,
                input_index: u32::from(spent) * 256 + spent_index,
                spent_txid: txid(spent),
                spent_output_index: spent_index,
            }),
        )
    }

    fn replay(mut events: Vec<(Vec<u8>, TransparentEvent)>) -> Ledger {
        let mut ledger = Ledger::new();
        ledger.replay(&mut events).expect("replay");
        ledger
    }

    #[test]
    fn a_receive_becomes_a_utxo_and_a_balance() {
        let ledger = replay(vec![receive(1, 0, 5_000, 100)]);
        assert_eq!(ledger.utxos().count(), 1);
        assert_eq!(ledger.confirmed_balance(), 5_000);
        assert!(ledger.unresolved().is_empty());
    }

    #[test]
    fn a_spend_removes_its_output_and_is_recorded() {
        let ledger = replay(vec![receive(1, 0, 5_000, 100), spend(1, 1, 0, 2, 110)]);
        assert_eq!(ledger.utxos().count(), 0);
        assert_eq!(ledger.confirmed_balance(), 0);
        assert_eq!(ledger.spends().len(), 1);
        assert_eq!(ledger.spends()[0].value, 5_000);
        assert!(ledger.unresolved().is_empty());
    }

    /// Events arrive from several pages and inline slots, whose concatenation
    /// is not in chain order. A spend applied before its receive would look
    /// unresolved, so the replay must order them itself.
    #[test]
    fn events_are_replayed_in_chain_order_whatever_order_they_arrive_in() {
        let forward = replay(vec![receive(1, 0, 5_000, 100), spend(1, 1, 0, 2, 110)]);
        let reversed = replay(vec![spend(1, 1, 0, 2, 110), receive(1, 0, 5_000, 100)]);
        assert_eq!(forward.confirmed_balance(), reversed.confirmed_balance());
        assert_eq!(reversed.spends().len(), 1);
        assert!(
            reversed.unresolved().is_empty(),
            "ordering must resolve the spend"
        );
    }

    /// A zero balance is not the same as no history. This is the case the whole
    /// design exists for: an empty UTXO set must not be read as a script never
    /// having been used.
    #[test]
    fn a_fully_spent_wallet_has_no_balance_but_keeps_its_history() {
        let ledger = replay(vec![
            receive(1, 0, 5_000, 100),
            receive(2, 0, 3_000, 105),
            spend(1, 1, 0, 3, 110),
            spend(2, 2, 0, 3, 110),
        ]);
        assert_eq!(ledger.confirmed_balance(), 0);
        assert_eq!(ledger.utxos().count(), 0);
        assert_eq!(ledger.spends().len(), 2);
        assert_eq!(ledger.history().len(), 3, "two receives and one spender");
    }

    /// The failure that must never be silent. A spend of an output the wallet
    /// never saw means the recovered history is incomplete, and the balance
    /// computed over it is too high while looking entirely normal.
    #[test]
    fn a_spend_of_an_unknown_output_is_recorded_as_unresolved() {
        let ledger = replay(vec![receive(1, 0, 5_000, 100), spend(9, 9, 0, 2, 110)]);
        assert_eq!(ledger.unresolved().len(), 1);
        assert_eq!(ledger.unresolved()[0].script, script(9));
        // The known output is untouched, so the error is isolated rather than
        // corrupting the rest of the reconstruction.
        assert_eq!(ledger.confirmed_balance(), 5_000);
    }

    /// The same event can reach a wallet through an inline slot and a page.
    /// Applying it twice must not double-count.
    #[test]
    fn duplicate_events_are_idempotent() {
        let ledger = replay(vec![
            receive(1, 0, 5_000, 100),
            receive(1, 0, 5_000, 100),
            spend(1, 1, 0, 2, 110),
            spend(1, 1, 0, 2, 110),
        ]);
        assert_eq!(ledger.confirmed_balance(), 0);
        assert_eq!(ledger.spends().len(), 1);
        assert!(ledger.unresolved().is_empty());
    }

    /// Two sources disagreeing about one outpoint is a real fault, not a
    /// duplicate, and must not be resolved by taking whichever arrived last.
    #[test]
    fn a_conflicting_receive_for_one_outpoint_is_an_error() {
        let mut events = vec![receive(1, 0, 5_000, 100), receive(1, 0, 9_999, 100)];
        let mut ledger = Ledger::new();
        assert!(matches!(
            ledger.replay(&mut events),
            Err(LedgerError::ConflictingReceive(_, 0))
        ));
    }

    #[test]
    fn several_outputs_of_one_transaction_are_distinct() {
        let ledger = replay(vec![
            receive(1, 0, 1_000, 100),
            receive(1, 1, 2_000, 100),
            receive(1, 2, 3_000, 100),
        ]);
        assert_eq!(ledger.utxos().count(), 3);
        assert_eq!(ledger.confirmed_balance(), 6_000);
    }

    /// A transaction that both consumes and creates wallet outputs is a
    /// self-transfer or change, and its net value is what a history should
    /// show.
    /// An output created and spent in the same block is the case the canonical
    /// order exists to settle: an output cannot be consumed by the transaction
    /// that creates it, so the creating transaction has the lower index and the
    /// receive is applied first however the two events arrived.
    #[test]
    fn a_receive_and_its_spend_in_one_block_resolve_by_transaction_index() {
        let receive = receive(1, 0, 500, 900);
        let spend = spend(1, 1, 0, 2, 900);
        // Deliberately the wrong way round on the wire.
        let mut events = vec![spend, receive];
        let mut ledger = Ledger::new();
        ledger.replay(&mut events).expect("replay");

        assert_eq!(ledger.confirmed_balance(), 0, "the output was consumed");
        assert_eq!(ledger.spends().len(), 1);
        assert!(
            ledger.unresolved().is_empty(),
            "the receive must be applied before its spend, not after"
        );
    }

    /// A repeat that differs is a contradiction, not a newer version. Taking
    /// either copy would produce a ledger that looks perfectly normal and is
    /// wrong about where the money went.
    #[test]
    fn the_same_outpoint_spent_by_two_transactions_is_an_error() {
        let mut events = vec![
            receive(1, 0, 500, 900),
            spend(1, 1, 0, 2, 901),
            spend(1, 1, 0, 3, 902),
        ];
        let mut ledger = Ledger::new();
        assert_eq!(
            ledger.replay(&mut events),
            Err(LedgerError::DoubleSpend(txid(1).to_display_hex(), 0))
        );
    }

    /// The identical spend arriving twice — through an inline slot and a page —
    /// is a repeat and must be absorbed silently.
    #[test]
    fn the_identical_spend_twice_is_idempotent() {
        let mut events = vec![
            receive(1, 0, 500, 900),
            spend(1, 1, 0, 2, 901),
            spend(1, 1, 0, 2, 901),
        ];
        let mut ledger = Ledger::new();
        ledger.replay(&mut events).expect("a repeat is idempotent");
        assert_eq!(ledger.spends().len(), 1);
    }

    /// An unresolved spend delivered twice is one piece of unresolved work, not
    /// two. Counting it twice would overstate how incomplete the recovery is.
    #[test]
    fn a_repeated_unresolved_spend_is_recorded_once() {
        let mut events = vec![spend(1, 9, 0, 2, 901), spend(1, 9, 0, 2, 901)];
        let mut ledger = Ledger::new();
        ledger.replay(&mut events).expect("replay");
        assert_eq!(ledger.unresolved().len(), 1);
    }

    #[test]
    fn history_reports_net_value_per_transaction() {
        let mut events = vec![receive(1, 0, 5_000, 100)];
        // Transaction 3 spends the 5,000 output and pays 4,000 back.
        events.push(spend(1, 1, 0, 3, 110));
        events.push((
            script(4),
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height: 110,
                txid: txid(3),
                transaction_index: 1,
                output_index: 0,
                value: 4_000,
                coinbase: false,
            }),
        ));
        let ledger = replay(events);
        assert_eq!(ledger.confirmed_balance(), 4_000);

        let history = ledger.history();
        let summary = history
            .iter()
            .find(|entry| entry.txid == txid(3))
            .expect("the self-transfer");
        assert_eq!(summary.received, 4_000);
        assert_eq!(summary.spent, 5_000);
        assert_eq!(summary.net(), -1_000, "the fee leaves the wallet");
    }

    /// A returning wallet: the receive was kept from an earlier sync, the
    /// spend arrives in a later one, and the two resolve.
    #[test]
    fn a_spend_extended_later_resolves_against_a_kept_receive() {
        let mut ledger = replay(vec![receive(1, 0, 5_000, 100)]);
        let mut later = vec![spend(1, 1, 0, 2, 110)];
        ledger.extend(&mut later).unwrap();
        assert_eq!(ledger.spends().len(), 1);
        assert!(ledger.unresolved().is_empty());
        assert_eq!(ledger.confirmed_balance(), 0);
    }

    /// The other order: a spend recorded as unresolved is resolved by a
    /// receive discovered later, as historical discovery of a new script
    /// produces.
    #[test]
    fn an_unresolved_spend_is_resolved_by_a_receive_extended_later() {
        let mut ledger = replay(vec![spend(1, 1, 0, 2, 110)]);
        assert_eq!(ledger.unresolved().len(), 1);
        let mut later = vec![receive(1, 0, 5_000, 100)];
        ledger.extend(&mut later).unwrap();
        assert!(ledger.unresolved().is_empty());
        assert_eq!(ledger.spends().len(), 1);
        assert_eq!(ledger.confirmed_balance(), 0);
    }

    /// Truncation removes what is above the cut and restores an output whose
    /// spend was cut away while its receive remains.
    #[test]
    fn truncating_above_a_height_restores_outputs_spent_above_it() {
        let mut ledger = replay(vec![
            receive(1, 0, 5_000, 100),
            receive(2, 0, 3_000, 150),
            spend(1, 1, 0, 3, 200),
            spend(9, 9, 0, 4, 210),
        ]);
        assert_eq!(ledger.confirmed_balance(), 3_000);
        ledger.truncate_above(199);
        assert_eq!(ledger.confirmed_balance(), 8_000, "the cut spend is undone");
        assert!(ledger.spends().is_empty());
        assert!(
            ledger.unresolved().is_empty(),
            "unresolved above the cut is gone too"
        );
        ledger.truncate_above(120);
        assert_eq!(ledger.utxos().count(), 1);
        assert_eq!(ledger.confirmed_balance(), 5_000);
        // A spend applied after truncation is indexed correctly again.
        let mut later = vec![spend(1, 1, 0, 3, 200)];
        ledger.extend(&mut later).unwrap();
        assert_eq!(ledger.spends().len(), 1);
        assert_eq!(ledger.confirmed_balance(), 0);
    }

    /// Recovering a coinbase receive does not make it spendable. The flag is
    /// carried through so the wallet can apply maturity itself.
    #[test]
    fn coinbase_status_survives_replay_without_being_applied() {
        let mut events = vec![(
            script(1),
            TransparentEvent::Receive(ReceiveEvent {
                metadata: None,
                height: 100,
                txid: txid(1),
                transaction_index: 0,
                output_index: 0,
                value: 6_250,
                coinbase: true,
            }),
        )];
        let mut ledger = Ledger::new();
        ledger.replay(&mut events).unwrap();
        let utxo = ledger.utxos().next().unwrap();
        assert!(utxo.coinbase);
        // Counted in the confirmed balance; whether it is spendable is not this
        // module's decision.
        assert_eq!(ledger.confirmed_balance(), 6_250);
    }
}
