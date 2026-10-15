//! Exact whole-transaction fees from canonical transaction data.
//!
//! The fee of a non-coinbase transaction is the remaining value in its
//! transaction value pool: transparent inputs minus transparent outputs, plus
//! the Sprout, Sapling, Orchard and Ironwood value balances. Transparent input
//! values are not in the transaction; they come from the outputs it spends.
//! An input whose spent output is unknown makes the fee unknown, so this
//! module never substitutes zero, guesses, or sums only the inputs it found.

use std::collections::{HashMap, HashSet, VecDeque};
use zakura_chain::amount::{Amount, NonNegative};
use zakura_chain::transaction::{self, Transaction};
use zakura_chain::transparent::{Input, OutPoint, Output, Script, Utxo};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeeError {
    #[error("spent output {0} is unavailable")]
    MissingPrevout(String),
    #[error("transaction spends {0} more than once")]
    DuplicateInput(String),
    #[error("invalid value balance: {0}")]
    ValueBalance(String),
    #[error("transaction value pool is negative or out of range: {0}")]
    Negative(String),
}

/// Display form of an outpoint: RPC-order txid and output index.
pub(crate) fn outpoint_label(outpoint: &OutPoint) -> String {
    format!("{}:{}", outpoint.hash, outpoint.index)
}

/// Returns the exact fee, or `None` for a coinbase transaction.
///
/// `utxos` must hold the output spent by every transparent input. A coinbase
/// transaction has no fee of its own and is answered without reading `utxos`.
/// Presence is checked here first: `Transaction::value_balance` panics on a
/// missing outpoint.
pub(crate) fn transaction_fee(
    transaction: &Transaction,
    utxos: &HashMap<OutPoint, Utxo>,
) -> Result<Option<u64>, FeeError> {
    if transaction
        .inputs()
        .iter()
        .any(|input| matches!(input, Input::Coinbase { .. }))
    {
        return Ok(None);
    }
    let mut spent = HashSet::with_capacity(transaction.inputs().len());
    for outpoint in transaction.inputs().iter().filter_map(Input::outpoint) {
        if !spent.insert(outpoint) {
            return Err(FeeError::DuplicateInput(outpoint_label(&outpoint)));
        }
        if !utxos.contains_key(&outpoint) {
            return Err(FeeError::MissingPrevout(outpoint_label(&outpoint)));
        }
    }
    let remaining = transaction
        .value_balance(utxos)
        .map_err(|error| FeeError::ValueBalance(error.to_string()))?
        .remaining_transaction_value()
        .map_err(|error| FeeError::Negative(error.to_string()))?;
    let fee: i64 = remaining.into();
    u64::try_from(fee)
        .map(Some)
        .map_err(|_| FeeError::Negative(fee.to_string()))
}

/// Whether publishing this transaction's fee needs spent-output values.
pub(crate) fn needs_prevouts(transaction: &Transaction) -> bool {
    !transaction
        .inputs()
        .iter()
        .any(|input| matches!(input, Input::Coinbase { .. }))
        && transaction
            .inputs()
            .iter()
            .any(|input| input.outpoint().is_some())
}

/// Default cross-block budget, in transparent outputs.
///
/// An entry is an outpoint and a value, about 100 bytes with map overhead, so
/// the default holds roughly 25 MB. A miss is correct, only slower: it costs
/// a batched `getrawtransaction` for the block.
pub const DEFAULT_CACHE_OUTPUTS: usize = 250_000;

/// Spent-output values of recently seen transactions, evicted oldest first.
///
/// Values are keyed by outpoint, and a txid commits to its outputs, so an
/// entry stays correct across reorganizations; a reorganized-out transaction
/// is only a wasted entry. Eviction removes whole transactions, so a
/// transaction is either fully present or absent, while the budget counts
/// outputs because transaction counts are a poor proxy for memory.
pub(crate) struct OutputCache {
    values: HashMap<OutPoint, Amount<NonNegative>>,
    order: VecDeque<(transaction::Hash, u32)>,
    outputs: usize,
    capacity: usize,
}

impl OutputCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            values: HashMap::new(),
            order: VecDeque::new(),
            outputs: 0,
            capacity: capacity.max(1),
        }
    }

    /// Records every transparent output of a transaction.
    pub(crate) fn insert_transaction(&mut self, transaction: &Transaction) {
        self.insert_outputs(transaction.hash(), transaction.outputs());
    }

    pub(crate) fn insert_outputs(&mut self, txid: transaction::Hash, outputs: &[Output]) {
        if outputs.is_empty()
            || self.values.contains_key(&OutPoint {
                hash: txid,
                index: 0,
            })
        {
            return;
        }
        for (index, output) in outputs.iter().enumerate() {
            self.values.insert(
                OutPoint {
                    hash: txid,
                    index: index as u32,
                },
                output.value,
            );
        }
        self.order.push_back((txid, outputs.len() as u32));
        self.outputs += outputs.len();
        // A transaction larger than the budget is kept until another arrives,
        // so the block being processed can still resolve it.
        while self.outputs > self.capacity && self.order.len() > 1 {
            let Some((evicted, count)) = self.order.pop_front() else {
                break;
            };
            for index in 0..count {
                self.values.remove(&OutPoint {
                    hash: evicted,
                    index,
                });
            }
            self.outputs -= count as usize;
        }
    }

    pub(crate) fn get(&self, outpoint: &OutPoint) -> Option<Amount<NonNegative>> {
        self.values.get(outpoint).copied()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.values.len()
    }
}

/// The spent output passed to `value_balance`, which reads only its value.
///
/// Height and coinbase origin feed maturity checks, not the value pool; the
/// script is not retained by the cache.
pub(crate) fn spent_output(value: Amount<NonNegative>) -> Utxo {
    Utxo::new(
        Output {
            value,
            lock_script: Script::new(&[]),
        },
        zakura_chain::block::Height(0),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_chain::serialization::{ZcashDeserialize, ZcashSerialize};
    use zakura_chain::transaction::LockTime;

    fn amount(value: i64) -> Amount<NonNegative> {
        Amount::try_from(value).unwrap()
    }

    fn output(value: i64) -> Output {
        Output {
            value: amount(value),
            lock_script: Script::new(&[0x51]),
        }
    }

    fn reparse(transaction: Transaction) -> Transaction {
        Transaction::zcash_deserialize(transaction.zcash_serialize_to_vec().unwrap().as_slice())
            .unwrap()
    }

    fn fixture() -> Transaction {
        let bytes =
            hex::decode(include_str!("../tests/fixtures/ironwood-fee-expiry.hex").trim()).unwrap();
        Transaction::zcash_deserialize(bytes.as_slice()).unwrap()
    }

    fn spend(seed: u8, index: u32) -> Input {
        Input::PrevOut {
            outpoint: OutPoint {
                hash: transaction::Hash([seed; 32]),
                index,
            },
            unlock_script: Script::new(&[0x51]),
            sequence: u32::MAX,
        }
    }

    /// The fixture's Ironwood actions with replaced transparent parts.
    fn mixed(inputs: Vec<Input>, outputs: Vec<Output>, ironwood: i64) -> Transaction {
        let Transaction::V6 {
            network_upgrade,
            lock_time,
            expiry_height,
            sapling_shielded_data,
            orchard_shielded_data,
            mut ironwood_shielded_data,
            ..
        } = fixture()
        else {
            panic!("fixture is V6");
        };
        ironwood_shielded_data.as_mut().unwrap().value_balance =
            Amount::try_from(ironwood).unwrap();
        reparse(Transaction::V6 {
            network_upgrade,
            lock_time,
            expiry_height,
            inputs,
            outputs,
            sapling_shielded_data,
            orchard_shielded_data,
            ironwood_shielded_data,
        })
    }

    fn utxos(values: &[(Input, i64)]) -> HashMap<OutPoint, Utxo> {
        values
            .iter()
            .map(|(input, value)| (input.outpoint().unwrap(), spent_output(amount(*value))))
            .collect()
    }

    #[test]
    fn transparent_into_ironwood_publishes_the_whole_fee() {
        let tx = mixed(vec![spend(1, 0)], vec![], -400_000);
        let fee = transaction_fee(&tx, &utxos(&[(spend(1, 0), 420_000)])).unwrap();
        assert_eq!(fee, Some(20_000));
    }

    #[test]
    fn pure_ironwood_fixture_keeps_its_fee() {
        assert_eq!(
            transaction_fee(&fixture(), &HashMap::new()).unwrap(),
            Some(10_000)
        );
        assert!(!needs_prevouts(&fixture()));
    }

    #[test]
    fn missing_duplicate_and_overspent_inputs_are_errors() {
        let tx = mixed(vec![spend(1, 0), spend(2, 1)], vec![], -100_000);
        assert_eq!(
            transaction_fee(&tx, &utxos(&[(spend(1, 0), 420_000)])),
            Err(FeeError::MissingPrevout(outpoint_label(
                &spend(2, 1).outpoint().unwrap()
            )))
        );
        let duplicate = mixed(vec![spend(1, 0), spend(1, 0)], vec![], -100_000);
        assert!(matches!(
            transaction_fee(&duplicate, &utxos(&[(spend(1, 0), 420_000)])),
            Err(FeeError::DuplicateInput(_))
        ));
        let overspent = mixed(vec![spend(1, 0)], vec![output(30_000)], -400_000);
        assert!(matches!(
            transaction_fee(&overspent, &utxos(&[(spend(1, 0), 420_000)])),
            Err(FeeError::Negative(_))
        ));
    }

    #[test]
    fn coinbase_has_no_fee_and_reads_no_utxos() {
        let coinbase = reparse(Transaction::V4 {
            inputs: vec![Input::Coinbase {
                height: zakura_chain::block::Height(3_500_000),
                data: vec![0; 4],
                sequence: u32::MAX,
            }],
            outputs: vec![output(625_000)],
            lock_time: LockTime::unlocked(),
            expiry_height: zakura_chain::block::Height(0),
            joinsplit_data: None,
            sapling_shielded_data: None,
        });
        assert!(!needs_prevouts(&coinbase));
        assert_eq!(transaction_fee(&coinbase, &HashMap::new()).unwrap(), None);
    }

    #[test]
    fn cache_evicts_whole_transactions_by_output_budget() {
        let make = |seed: u8, count: usize| {
            reparse(Transaction::V4 {
                inputs: vec![spend(seed, 0)],
                outputs: (0..count).map(|i| output(1 + i as i64)).collect(),
                lock_time: LockTime::unlocked(),
                expiry_height: zakura_chain::block::Height(0),
                joinsplit_data: None,
                sapling_shielded_data: None,
            })
        };
        let mut cache = OutputCache::new(5);
        let first = make(1, 4);
        let second = make(2, 3);
        cache.insert_transaction(&first);
        let first_out = OutPoint {
            hash: first.hash(),
            index: 3,
        };
        assert_eq!(cache.get(&first_out), Some(amount(4)));
        cache.insert_transaction(&second);
        assert_eq!(cache.get(&first_out), None);
        assert_eq!(cache.len(), 3);
        // Re-inserting a known transaction does not double count its outputs.
        cache.insert_transaction(&second);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.outputs, 3);
    }
}
