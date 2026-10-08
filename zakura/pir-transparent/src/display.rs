//! Txid display lookups as the wallet's transparent display facts and lookup outcomes.
//!
//! The wallet validates and stores the facts (`TransparentDetailWrite`); this module only
//! translates. Under `PrivateRequired` a failed lookup is deferred, never retried publicly.
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::transparent_ledger::{
    TransparentDetailOutcome, TransparentDisplayFacts, TransparentDisplayOutput,
    TransparentDisplayProvenance, TransparentDisplaySender,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::recovery::{RecoveryError, failure, require};
use transparent_txid_client::{
    Address, AddressKind, DisplayEntry, OUTPUT_SLOTS, Placement, Provenance, Tag, TxidError,
    TxidLookup,
};

/// Decodes a display map digest as the client reports it (hex).
pub fn map_sha256(hex: &str) -> Option<[u8; 32]> {
    hex::decode(hex).ok()?.try_into().ok()
}

/// The address an entry's address slot names: `None` for a script without one.
fn address(slot: &Address) -> Result<Option<TransparentAddress>, RecoveryError> {
    match slot.kind {
        AddressKind::P2pkh => Ok(Some(TransparentAddress::PublicKeyHash(slot.hash))),
        AddressKind::P2sh => Ok(Some(TransparentAddress::ScriptHash(slot.hash))),
        AddressKind::Other => Ok(None),
        AddressKind::Absent => Err(RecoveryError::Invalid(
            "display output without a kind".into(),
        )),
    }
}

/// The wallet's display facts for `txid`'s `entry`, found through the publication
/// `provenance` names by its mined height `looked_up_height`.
///
/// Fails when the entry's tag is not `txid`'s, a value exceeds `MAX_MONEY`, the entry
/// disagrees with itself, or the map digest is malformed; the wallet still validates the facts
/// against its own state.
pub fn display_facts(
    txid: TxId,
    entry: &DisplayEntry,
    provenance: &Provenance,
    looked_up_height: BlockHeight,
) -> Result<TransparentDisplayFacts, RecoveryError> {
    require(
        entry.tag == Tag::of(&transparent_events::Txid(*txid.as_ref())),
        "display entry is not the txid's",
    )?;
    let sender = match entry.source.kind {
        AddressKind::Absent => TransparentDisplaySender::Absent,
        _ => address(&entry.source)?.map_or(
            TransparentDisplaySender::NonStandard,
            TransparentDisplaySender::Address,
        ),
    };
    let held = (entry.output_count as usize).min(OUTPUT_SLOTS);
    require(
        entry.outputs[held..].iter().all(Option::is_none),
        "display output beyond the output count",
    )?;
    let outputs = entry.outputs[..held]
        .iter()
        .map(|slot| {
            let output = slot.as_ref().ok_or_else(|| {
                RecoveryError::Invalid("display output missing below the output count".into())
            })?;
            Ok(TransparentDisplayOutput {
                value: Zatoshis::from_u64(output.value).map_err(failure)?,
                address: address(&output.address)?,
            })
        })
        .collect::<Result<_, RecoveryError>>()?;
    let facts = TransparentDisplayFacts {
        txid,
        coinbase: entry.coinbase,
        fee: Zatoshis::from_u64(entry.fee).map_err(failure)?,
        input_count: entry.input_count,
        output_count: entry.output_count,
        shielded_components: entry.shielded_components,
        sender,
        outputs,
        multiple_source_scripts: entry.multiple_source_scripts,
        shielded_and_transparent_funding: entry.shielded_and_transparent_funding,
        provenance: TransparentDisplayProvenance {
            shard_id: provenance.shard_id,
            revision: provenance.revision,
            map_sha256: map_sha256(&provenance.map_sha256)
                .ok_or_else(|| RecoveryError::Invalid("malformed display map digest".into()))?,
            looked_up_height,
        },
    };
    require(
        facts.is_well_formed(),
        "display entry disagrees with itself",
    )?;
    Ok(facts)
}

/// How to defer a lookup that did not find the entry, or `None` when it found it or was
/// cancelled before completing (which is not an attempt).
pub fn deferral(lookup: &Result<TxidLookup, TxidError>) -> Option<TransparentDetailOutcome> {
    match lookup {
        Ok(TxidLookup::Found { .. }) | Err(TxidError::Cancelled) => None,
        Ok(TxidLookup::Absent) => Some(TransparentDetailOutcome::Absent),
        // Above the newest shard is transient: the publication has not caught up yet.
        Ok(TxidLookup::PlacementUnknown(Placement::Above)) => {
            Some(TransparentDetailOutcome::NotYetPublished)
        }
        Ok(TxidLookup::PlacementUnknown(Placement::Below)) => {
            Some(TransparentDetailOutcome::NotCovered)
        }
        Ok(TxidLookup::Unsupported) => Some(TransparentDetailOutcome::Unsupported),
        Err(TxidError::Unavailable { retry_after }) => {
            Some(TransparentDetailOutcome::Unavailable {
                retry_after: *retry_after,
            })
        }
        Err(TxidError::Stale | TxidError::Transport(_)) => {
            Some(TransparentDetailOutcome::Unavailable { retry_after: None })
        }
        Err(TxidError::Refused(_) | TxidError::Protocol(_)) => {
            Some(TransparentDetailOutcome::Protocol)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transparent_txid_client::{EntryOutput, ProtocolKind, Tier};

    const TXID: [u8; 32] = [9; 32];

    fn provenance() -> Provenance {
        Provenance {
            map_sha256: "ab".repeat(32),
            shard_id: 7,
            revision: 2,
            manifest_digest: "cd".repeat(32),
            tier: Tier::Recent,
        }
    }

    fn slot(kind: AddressKind, byte: u8) -> Address {
        Address {
            kind,
            hash: [byte; 20],
        }
    }

    /// Two inputs spending two scripts, partly shielded funding, and three outputs: a P2SH one
    /// and one without an address given, one omitted.
    fn entry() -> DisplayEntry {
        DisplayEntry {
            tag: Tag::of(&transparent_events::Txid(TXID)),
            coinbase: false,
            shielded_components: true,
            multiple_source_scripts: true,
            shielded_and_transparent_funding: true,
            fee: 10_000,
            input_count: 2,
            output_count: 3,
            source: slot(AddressKind::P2pkh, 1),
            outputs: [
                Some(EntryOutput {
                    value: 5,
                    address: slot(AddressKind::P2sh, 2),
                }),
                Some(EntryOutput {
                    value: 0,
                    address: Address::OTHER,
                }),
            ],
        }
    }

    fn facts(entry: &DisplayEntry) -> Result<TransparentDisplayFacts, RecoveryError> {
        display_facts(
            TxId::from_bytes(TXID),
            entry,
            &provenance(),
            BlockHeight::from_u32(3_000_000),
        )
    }

    #[test]
    fn display_entry_to_backend_facts() {
        let mixed = facts(&entry()).unwrap();
        assert_eq!(mixed.txid, TxId::from_bytes(TXID));
        assert!(!mixed.coinbase && mixed.shielded_components);
        assert_eq!(mixed.fee, Zatoshis::const_from_u64(10_000));
        assert_eq!((mixed.input_count, mixed.output_count), (2, 3));
        assert!(mixed.more_than_two_outputs());
        assert_eq!(
            mixed.sender,
            TransparentDisplaySender::Address(TransparentAddress::PublicKeyHash([1; 20]))
        );
        assert!(mixed.multiple_source_scripts && mixed.shielded_and_transparent_funding);
        assert_eq!(
            mixed.outputs,
            vec![
                TransparentDisplayOutput {
                    value: Zatoshis::const_from_u64(5),
                    address: Some(TransparentAddress::ScriptHash([2; 20])),
                },
                TransparentDisplayOutput {
                    value: Zatoshis::ZERO,
                    address: None,
                },
            ]
        );
        assert_eq!(
            mixed.provenance,
            TransparentDisplayProvenance {
                shard_id: 7,
                revision: 2,
                map_sha256: [0xab; 32],
                looked_up_height: BlockHeight::from_u32(3_000_000),
            }
        );

        // Inputs exist but none spends an address-shaped script.
        let mut other = entry();
        other.source = Address::OTHER;
        assert_eq!(
            facts(&other).unwrap().sender,
            TransparentDisplaySender::NonStandard
        );
        // Unshielding: no input, so no sender; one output.
        let mut unshield = entry();
        unshield.input_count = 0;
        unshield.source = Address::ABSENT;
        unshield.multiple_source_scripts = false;
        unshield.shielded_and_transparent_funding = false;
        unshield.output_count = 1;
        unshield.outputs[1] = None;
        let unshielding = facts(&unshield).unwrap();
        assert_eq!(unshielding.sender, TransparentDisplaySender::Absent);
        assert_eq!(unshielding.outputs.len(), 1);
        // Coinbase: no input and no fee.
        let mut coinbase = unshield;
        coinbase.coinbase = true;
        coinbase.shielded_components = false;
        coinbase.fee = 0;
        assert!(facts(&coinbase).unwrap().coinbase);
    }

    #[test]
    fn inconsistent_entries_are_refused() {
        let refused = |change: &dyn Fn(&mut DisplayEntry)| {
            let mut entry = entry();
            change(&mut entry);
            facts(&entry).is_err()
        };
        assert!(!refused(&|_| {}));
        assert!(refused(
            &|e| e.tag = Tag::of(&transparent_events::Txid([8; 32]))
        ));
        assert!(refused(&|e| e.fee = u64::MAX));
        assert!(refused(&|e| e.outputs[0].as_mut().unwrap().value = u64::MAX));
        assert!(refused(&|e| e.outputs[1] = None));
        assert!(refused(&|e| e.output_count = 1));
        assert!(refused(
            &|e| e.outputs[0].as_mut().unwrap().address = Address::ABSENT
        ));
        assert!(refused(&|e| e.source = Address::ABSENT));
        assert!(refused(&|e| e.coinbase = true));
        assert!(refused(&|e| e.input_count = 1));
        assert!(refused(&|e| e.shielded_components = false));
        let mut digest = provenance();
        digest.map_sha256 = "zz".into();
        assert!(
            display_facts(
                TxId::from_bytes(TXID),
                &entry(),
                &digest,
                BlockHeight::from_u32(1)
            )
            .is_err()
        );
    }

    #[test]
    fn lookup_results_map_to_deferrals() {
        use TransparentDetailOutcome as O;
        let retry = Some(std::time::Duration::from_secs(9));
        for (lookup, expected) in [
            (Ok(TxidLookup::Absent), Some(O::Absent)),
            (
                Ok(TxidLookup::PlacementUnknown(Placement::Above)),
                Some(O::NotYetPublished),
            ),
            (
                Ok(TxidLookup::PlacementUnknown(Placement::Below)),
                Some(O::NotCovered),
            ),
            (Ok(TxidLookup::Unsupported), Some(O::Unsupported)),
            (
                Err(TxidError::Unavailable { retry_after: retry }),
                Some(O::Unavailable { retry_after: retry }),
            ),
            (
                Err(TxidError::Stale),
                Some(O::Unavailable { retry_after: None }),
            ),
            (Err(TxidError::Refused(400)), Some(O::Protocol)),
            (
                Err(TxidError::Protocol(ProtocolKind::Decode)),
                Some(O::Protocol),
            ),
            (Err(TxidError::Cancelled), None),
        ] {
            assert_eq!(deferral(&lookup), expected, "{lookup:?}");
        }
    }
}
