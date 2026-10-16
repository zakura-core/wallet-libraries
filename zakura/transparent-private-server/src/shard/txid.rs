//! What a publisher derives a transaction's display entry from; the entry and
//! its codec are [`zakura_transparent_private_shared::shard::txid`].

use serde::{Deserialize, Serialize};
use zakura_transparent_private_shared::events::{Txid, MAX_MONEY};
use zakura_transparent_private_shared::shard::txid::{
    Address, DisplayEntry, EntryOutput, Error, Tag, OUTPUT_SLOTS,
};

fn bad(s: &str) -> Error {
    Error(s.to_string())
}

/// An entry with the txid it was derived from, as the publisher keeps it.
/// Published tables hold only the entry; the txid stays with the publisher's
/// journal and tooling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayRecord {
    pub txid: Txid,
    pub entry: DisplayEntry,
}

impl AsRef<DisplayEntry> for DisplayRecord {
    fn as_ref(&self) -> &DisplayEntry {
        &self.entry
    }
}

impl DisplayRecord {
    /// Refuses an entry whose tag is not this txid's.
    pub fn new(txid: Txid, entry: DisplayEntry) -> Result<Self, Error> {
        if entry.tag != Tag::of(&txid) {
            return Err(bad("entry tag is not the txid's"));
        }
        Ok(Self { txid, entry })
    }
}

/// A transparent output: an amount and its raw locking script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayOutput {
    pub value: u64,
    pub script: Vec<u8>,
}

/// What the publisher knows about one transaction, from which its entry is
/// derived. `spent` is the output each transparent input spends, in input
/// order; resolving those is what gives an entry its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayFacts {
    pub txid: Txid,
    pub coinbase: bool,
    /// The exact whole-transaction fee; zero for coinbase.
    pub fee: u64,
    pub has_shielded_components: bool,
    pub spent: Vec<DisplayOutput>,
    pub outputs: Vec<DisplayOutput>,
}

impl DisplayFacts {
    /// The entry these facts publish, with their txid.
    pub fn record(&self) -> Result<DisplayRecord, Error> {
        Ok(DisplayRecord {
            txid: self.txid,
            entry: self.entry()?,
        })
    }

    /// The entry these facts publish.
    pub fn entry(&self) -> Result<DisplayEntry, Error> {
        let input_count = u32::try_from(self.spent.len()).map_err(|_| bad("input count"))?;
        let output_count = u32::try_from(self.outputs.len()).map_err(|_| bad("output count"))?;
        let source = if self.spent.is_empty() {
            Address::ABSENT
        } else {
            self.spent
                .iter()
                .map(|s| Address::from_script(&s.script))
                .find(Address::is_address)
                .unwrap_or(Address::OTHER)
        };
        let first = self.spent.first().map(|s| &s.script);
        let multiple_source_scripts = self.spent.iter().any(|s| Some(&s.script) != first);
        // Shielded pools' net contribution = fee + outputs - inputs. Positive
        // means shielded value paid part of a transaction that also has
        // transparent inputs.
        let sum = |outputs: &[DisplayOutput]| -> Result<u128, Error> {
            outputs.iter().try_fold(0u128, |total, o| {
                (o.value <= MAX_MONEY)
                    .then_some(total + u128::from(o.value))
                    .ok_or_else(|| bad("value bound"))
            })
        };
        let inputs = sum(&self.spent)?;
        let shielded_and_transparent_funding = !self.spent.is_empty()
            && self.has_shielded_components
            && u128::from(self.fee) + sum(&self.outputs)? > inputs;
        let mut outputs = [None; OUTPUT_SLOTS];
        for (slot, output) in outputs.iter_mut().zip(&self.outputs) {
            *slot = Some(EntryOutput {
                value: output.value,
                address: Address::from_script(&output.script),
            });
        }
        let entry = DisplayEntry {
            tag: Tag::of(&self.txid),
            coinbase: self.coinbase,
            shielded_components: self.has_shielded_components,
            multiple_source_scripts,
            shielded_and_transparent_funding,
            fee: self.fee,
            input_count,
            output_count,
            source,
            outputs,
        };
        entry.validate()?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_transparent_private_shared::shard::txid::{
        encode_row, find_entry, flags, row_entries, ENTRY_BYTES, TAG_BYTES,
    };

    fn p2pkh(byte: u8) -> Vec<u8> {
        [&[0x76, 0xa9, 0x14][..], &[byte; 20], &[0x88, 0xac]].concat()
    }
    fn p2sh(byte: u8) -> Vec<u8> {
        [&[0xa9, 0x14][..], &[byte; 20], &[0x87]].concat()
    }
    fn out(value: u64, script: Vec<u8>) -> DisplayOutput {
        DisplayOutput { value, script }
    }
    fn facts(spent: Vec<DisplayOutput>, outputs: Vec<DisplayOutput>) -> DisplayFacts {
        DisplayFacts {
            txid: Txid([7; 32]),
            coinbase: false,
            fee: 10_000,
            has_shielded_components: false,
            spent,
            outputs,
        }
    }
    fn round_trip(entry: &DisplayEntry) {
        let bytes = entry.encode().unwrap();
        assert_eq!(bytes.len(), ENTRY_BYTES);
        assert_eq!(&DisplayEntry::decode(&bytes).unwrap(), entry);
    }

    #[test]
    fn regular_send_with_shielded_change() {
        let mut f = facts(
            vec![out(100_010_000, p2pkh(1))],
            vec![out(60_000_000, p2pkh(2))],
        );
        f.has_shielded_components = true;
        let e = f.entry().unwrap();
        assert_eq!(e.source, Address::from_script(&p2pkh(1)));
        assert_eq!((e.input_count, e.output_count), (1, 1));
        assert!(e.shielded_components && e.is_complete());
        assert!(!e.shielded_and_transparent_funding);
        assert_eq!(e.outputs[0].unwrap().value, 60_000_000);
        assert_eq!(e.outputs[1], None);
        round_trip(&e);
    }

    #[test]
    fn several_inputs_one_script_is_one_source() {
        let e = facts(
            vec![out(5, p2pkh(1)), out(6, p2pkh(1)), out(10_000, p2pkh(1))],
            vec![out(11, p2pkh(2)), out(0, p2pkh(1))],
        )
        .entry()
        .unwrap();
        assert!(!e.multiple_source_scripts && e.is_complete());
        assert_eq!(e.input_count, 3);
        round_trip(&e);
    }

    #[test]
    fn first_address_shaped_source_and_multiple_scripts() {
        let p2pk = [&[0x21][..], &[2; 33], &[0xac]].concat();
        let e = facts(
            vec![out(5, p2pk.clone()), out(6, p2sh(3)), out(10_000, p2pkh(4))],
            vec![out(11, p2pkh(2))],
        )
        .entry()
        .unwrap();
        assert!(e.multiple_source_scripts && !e.is_complete());
        assert_eq!(e.source, Address::from_script(&p2sh(3)));
        round_trip(&e);
        let only = facts(vec![out(10_011, p2pk)], vec![out(1, p2pkh(2))])
            .entry()
            .unwrap();
        assert_eq!(only.source, Address::OTHER);
        assert!(!only.is_complete());
        round_trip(&only);
    }

    #[test]
    fn zcashd_two_outputs_and_more_than_two() {
        let two = facts(
            vec![out(30_000, p2pkh(1))],
            vec![out(10_000, p2pkh(2)), out(10_000, p2pkh(1))],
        )
        .entry()
        .unwrap();
        assert!(two.is_complete() && !two.more_than_two_outputs());
        round_trip(&two);
        let three = facts(
            vec![out(40_000, p2pkh(1))],
            vec![
                out(10_000, p2pkh(2)),
                out(10_000, vec![0x6a]),
                out(10_000, p2pkh(5)),
            ],
        )
        .entry()
        .unwrap();
        assert!(three.more_than_two_outputs() && !three.is_complete());
        assert_eq!(three.output_count, 3);
        assert_eq!(three.outputs[1].unwrap().address, Address::OTHER);
        assert_eq!(
            three.flags() & flags::MORE_THAN_TWO_OUTPUTS,
            flags::MORE_THAN_TWO_OUTPUTS
        );
        round_trip(&three);
    }

    #[test]
    fn shielding_unshielding_and_mixed_funding() {
        // t→z: inputs pay outputs, fee and the shielded pool.
        let mut shielding = facts(vec![out(1_000_000, p2pkh(1))], vec![]);
        shielding.has_shielded_components = true;
        let e = shielding.entry().unwrap();
        assert!(!e.shielded_and_transparent_funding && e.outputs == [None, None]);
        round_trip(&e);
        // z→t: no transparent input; the source is absent, not omitted.
        let mut unshield = facts(vec![], vec![out(990_000, p2pkh(2))]);
        unshield.has_shielded_components = true;
        let e = unshield.entry().unwrap();
        assert_eq!(e.source, Address::ABSENT);
        assert!(e.is_complete() && !e.shielded_and_transparent_funding);
        round_trip(&e);
        // Both pools fund it: outputs + fee exceed the transparent inputs.
        let mut mixed = facts(vec![out(500_000, p2pkh(1))], vec![out(990_000, p2pkh(2))]);
        mixed.has_shielded_components = true;
        let e = mixed.entry().unwrap();
        assert!(e.shielded_and_transparent_funding && !e.is_complete());
        round_trip(&e);
        // Without shielded components the same arithmetic is a malformed fee,
        // not mixed funding.
        let mut unfunded = unshield.clone();
        unfunded.has_shielded_components = false;
        assert!(unfunded.entry().is_err());
    }

    #[test]
    fn coinbase() {
        let mut f = facts(vec![], vec![out(625_000_000, p2pkh(9)), out(1, p2sh(8))]);
        f.coinbase = true;
        f.fee = 0;
        let e = f.entry().unwrap();
        assert!(e.coinbase && e.is_complete());
        assert_eq!(e.source, Address::ABSENT);
        round_trip(&e);
        f.fee = 1;
        assert!(f.entry().is_err());
        f.fee = 0;
        f.spent = vec![out(1, p2pkh(1))];
        assert!(f.entry().is_err());
    }

    #[test]
    fn decode_refuses_noncanonical_bytes() {
        let e = facts(vec![out(30_000, p2pkh(1))], vec![out(10_000, p2pkh(2))])
            .entry()
            .unwrap();
        let good = e.encode().unwrap();
        let mutate = |at: usize, value: u8| {
            let mut b = good;
            b[at] = value;
            DisplayEntry::decode(&b)
        };
        assert!(mutate(16, 1 << 5).is_err(), "reserved flag");
        assert!(
            mutate(16, flags::MORE_THAN_TWO_OUTPUTS as u8).is_err(),
            "flag without count"
        );
        assert!(
            mutate(16, flags::COINBASE as u8).is_err(),
            "coinbase with inputs and fee"
        );
        assert!(mutate(34, 0).is_err(), "inputs without a source");
        assert!(mutate(34, 4).is_err(), "unknown kind");
        assert!(mutate(30, 2).is_err(), "count names a missing slot");
        assert!(mutate(30, 0).is_err(), "slot beyond the count");
        assert!(mutate(55 + 29 + 3, 1).is_err(), "value in an absent slot");
        let mut other = e;
        other.source = Address::OTHER;
        let mut b = other.encode().unwrap();
        b[40] = 1;
        assert!(DisplayEntry::decode(&b).is_err(), "hash on a non-address");
        assert!(DisplayEntry::decode(&good[1..]).is_err(), "width");
        let mut zero_tag = e;
        zero_tag.tag = Tag([0; TAG_BYTES]);
        assert!(zero_tag.encode().is_err());
        let mut money = e;
        money.fee = MAX_MONEY + 1;
        assert!(money.encode().is_err());
        let mut values = e;
        values.output_count = 2;
        values.outputs = [
            Some(EntryOutput {
                value: MAX_MONEY,
                address: Address::OTHER,
            }),
            Some(EntryOutput {
                value: 1,
                address: Address::OTHER,
            }),
        ];
        assert!(values.encode().is_err());
    }

    #[test]
    fn rows_are_canonical_and_found_by_tag() {
        let entries: Vec<DisplayEntry> = (0u8..36)
            .map(|i| {
                let mut f = facts(vec![out(20_000, p2pkh(i))], vec![out(10_000, p2pkh(i))]);
                f.txid = Txid([i; 32]);
                f.entry().unwrap()
            })
            .collect();
        const ROW: usize = 4096;
        let anywhere = |_: &Tag| true;
        let row = encode_row(&entries, ROW).unwrap();
        assert_eq!(row.len(), ROW);
        let decoded = row_entries(&row).unwrap();
        assert_eq!(decoded.len(), 36);
        assert!(decoded.windows(2).all(|w| w[0].tag < w[1].tag));
        for i in [0u8, 17, 35] {
            let found = find_entry(std::slice::from_ref(&row), &Txid([i; 32]), anywhere).unwrap();
            assert_eq!(found.unwrap().tag, Tag::of(&Txid([i; 32])));
        }
        assert_eq!(
            find_entry(std::slice::from_ref(&row), &Txid([99; 32]), anywhere).unwrap(),
            None
        );
        // An entry the placement puts in another row is refused.
        let elsewhere = Tag::of(&Txid([5; 32]));
        assert!(find_entry(
            std::slice::from_ref(&row),
            &Txid([99; 32]),
            |tag: &Tag| *tag != elsewhere
        )
        .is_err());
        assert!(encode_row(&[entries.clone(), vec![entries[0]]].concat(), ROW).is_err());
        assert!(encode_row(&[entries[0], entries[0]], ROW).is_err());
        // A wider row holds twice the entries.
        let wide = encode_row(&[entries.clone(), entries.clone()].concat()[..36], 8192).unwrap();
        assert_eq!((wide.len(), row_entries(&wide).unwrap().len()), (8192, 36));
        assert!(row_entries(&wide[..100]).is_err(), "narrower than an entry");

        // Order, gaps and padding are part of the format.
        let short = encode_row(&entries[..3], ROW).unwrap();
        let mut pair = entries[..2].to_vec();
        pair.sort_by_key(|e| e.tag);
        let mut swapped = [pair[1].encode().unwrap(), pair[0].encode().unwrap()].concat();
        swapped.resize(ROW, 0);
        assert!(row_entries(&swapped).is_err(), "out of order");
        let mut gap = short.clone();
        gap[..ENTRY_BYTES].fill(0);
        assert!(row_entries(&gap).is_err(), "entry after an empty slot");
        let mut padded = short.clone();
        padded[ROW - 1] = 1;
        assert!(row_entries(&padded).is_err(), "padding");
        // The same entry in two segments is a contradiction.
        let other = encode_row(&[entries[0], entries[1]], ROW).unwrap();
        assert!(find_entry(&[short, other], &Txid([0; 32]), anywhere).is_err());
    }

    /// The tag is the only identity an entry carries: a publisher pair is
    /// refused under another txid, and a row answers only its own txid.

    #[test]
    fn an_entry_belongs_only_to_the_txid_of_its_tag() {
        let record = facts(vec![out(20_000, p2pkh(1))], vec![out(10_000, p2pkh(2))])
            .record()
            .unwrap();
        assert_eq!(
            DisplayRecord::new(record.txid, record.entry).unwrap(),
            record
        );
        let other = Txid([8; 32]);
        assert!(DisplayRecord::new(other, record.entry).is_err());
        let rows = [encode_row(&[record.entry], 8192).unwrap()];
        let anywhere = |_: &Tag| true;
        assert_eq!(
            find_entry(&rows, &record.txid, anywhere).unwrap(),
            Some(record.entry)
        );
        assert_eq!(find_entry(&rows, &other, anywhere).unwrap(), None);
    }
}
