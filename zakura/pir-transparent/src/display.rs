//! Txid display lookups as the wallet's transparent display facts and lookup outcomes.
//!
//! The wallet validates and stores the facts (`TransparentDetailWrite`); this module only
//! translates. Under `PrivateRequired` a failed lookup is deferred, never retried publicly.
use zcash_client_backend::data_api::transparent_ledger::{
    TransparentDetailOutcome, TransparentDisplayFacts, TransparentDisplayOutput,
    TransparentDisplayProvenance,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

use crate::recovery::{RecoveryError, failure, metadata, require};
use transparent_txid_client::{Provenance, TransparentDisplayRecord, TxidError, TxidLookup};

/// Decodes a display map digest as the client reports it (hex).
pub fn map_sha256(hex: &str) -> Option<[u8; 32]> {
    hex::decode(hex).ok()?.try_into().ok()
}

/// The wallet's display facts for `record`, found through the publication `provenance`
/// names by its mined height `looked_up_height`.
///
/// Fails when a value exceeds `MAX_MONEY`, the metadata does not suit the coinbase flag, or
/// the map digest is malformed; the wallet still validates the facts against its own state.
pub fn display_facts(
    record: &TransparentDisplayRecord,
    provenance: &Provenance,
    looked_up_height: BlockHeight,
) -> Result<TransparentDisplayFacts, RecoveryError> {
    let metadata = metadata(Some(record.metadata))?.expect("metadata is present");
    require(
        metadata.is_valid_for(record.coinbase),
        "display metadata does not suit the coinbase flag",
    )?;
    let outputs = record
        .outputs
        .iter()
        .map(|output| {
            Ok(TransparentDisplayOutput {
                value: Zatoshis::from_u64(output.value).map_err(failure)?,
                script: output.script.clone(),
            })
        })
        .collect::<Result<_, RecoveryError>>()?;
    Ok(TransparentDisplayFacts {
        txid: TxId::from_bytes(record.txid.0),
        coinbase: record.coinbase,
        metadata,
        outputs,
        provenance: TransparentDisplayProvenance {
            shard_id: provenance.shard_id,
            revision: provenance.revision,
            map_sha256: map_sha256(&provenance.map_sha256)
                .ok_or_else(|| RecoveryError::Invalid("malformed display map digest".into()))?,
            looked_up_height,
        },
    })
}

/// How to defer a lookup that did not find the record, or `None` when it found it or was
/// cancelled before completing (which is not an attempt).
pub fn deferral(lookup: &Result<TxidLookup, TxidError>) -> Option<TransparentDetailOutcome> {
    match lookup {
        Ok(TxidLookup::Found { .. }) | Err(TxidError::Cancelled) => None,
        Ok(TxidLookup::Absent) => Some(TransparentDetailOutcome::Absent),
        Ok(TxidLookup::PlacementUnknown(_)) => Some(TransparentDetailOutcome::NotCovered),
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
    use transparent_events::{FeeState, TransactionMetadata, Txid};
    use transparent_txid_client::{DisplayOutput, Placement, ProtocolKind, Tier};
    use zcash_client_backend::data_api::transparent_ledger::WholeTransactionFee;

    fn provenance() -> Provenance {
        Provenance {
            map_sha256: "ab".repeat(32),
            shard_id: 7,
            revision: 2,
            manifest_digest: "cd".repeat(32),
            tier: Tier::Recent,
        }
    }

    fn record(coinbase: bool, fee: FeeState, inputs: u32) -> TransparentDisplayRecord {
        TransparentDisplayRecord {
            txid: Txid([9; 32]),
            coinbase,
            metadata: TransactionMetadata {
                fee,
                transparent_input_count: inputs,
                has_shielded_components: true,
            },
            outputs: vec![
                DisplayOutput {
                    value: 5,
                    script: vec![0x51],
                },
                DisplayOutput {
                    value: 0,
                    script: vec![],
                },
            ],
        }
    }

    #[test]
    fn display_record_to_backend_facts() {
        let height = BlockHeight::from_u32(3_000_000);
        let facts =
            display_facts(&record(false, FeeState::Exact(0), 3), &provenance(), height).unwrap();
        assert_eq!(facts.txid, TxId::from_bytes([9; 32]));
        assert!(!facts.coinbase);
        assert_eq!(
            facts.metadata.fee,
            WholeTransactionFee::Exact(Zatoshis::ZERO)
        );
        assert_eq!(facts.metadata.transparent_input_count, 3);
        assert!(facts.metadata.has_shielded_components);
        assert_eq!(
            facts.outputs,
            vec![
                TransparentDisplayOutput {
                    value: Zatoshis::const_from_u64(5),
                    script: vec![0x51],
                },
                TransparentDisplayOutput {
                    value: Zatoshis::ZERO,
                    script: vec![],
                },
            ]
        );
        assert_eq!(
            facts.provenance,
            TransparentDisplayProvenance {
                shard_id: 7,
                revision: 2,
                map_sha256: [0xab; 32],
                looked_up_height: height,
            }
        );
        let unknown =
            display_facts(&record(false, FeeState::Unknown, 1), &provenance(), height).unwrap();
        assert_eq!(unknown.metadata.fee, WholeTransactionFee::Unknown);
        let coinbase = display_facts(
            &record(true, FeeState::NotApplicable, 0),
            &provenance(),
            height,
        )
        .unwrap();
        assert!(coinbase.coinbase);
        assert_eq!(coinbase.metadata.fee, WholeTransactionFee::NotApplicable);

        // Inconsistent or malformed input is refused rather than translated.
        assert!(
            display_facts(&record(true, FeeState::Exact(1), 0), &provenance(), height).is_err()
        );
        let mut excessive = record(false, FeeState::Unknown, 1);
        excessive.outputs[0].value = u64::MAX;
        assert!(display_facts(&excessive, &provenance(), height).is_err());
        let mut digest = provenance();
        digest.map_sha256 = "zz".into();
        assert!(display_facts(&record(false, FeeState::Unknown, 1), &digest, height).is_err());
    }

    #[test]
    fn lookup_results_map_to_deferrals() {
        use TransparentDetailOutcome as O;
        let retry = Some(std::time::Duration::from_secs(9));
        for (lookup, expected) in [
            (Ok(TxidLookup::Absent), Some(O::Absent)),
            (
                Ok(TxidLookup::PlacementUnknown(Placement::Above)),
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
