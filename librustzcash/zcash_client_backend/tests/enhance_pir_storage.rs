//! An external storage implementation needs only the explicit implementation contract.
#![cfg(all(feature = "zakura-pir-enhance", feature = "test-dependencies"))]

use incrementalmerkletree::Position;
use zcash_client_backend::data_api::enhance_pir::{
    EnhancePirRequest, EnhancePirStoreResult, EnhanceRecord, EnhanceRecordParts,
    IronwoodEnhanceRequestId,
    storage::{
        EnhancePirStorage, PendingIronwoodMemo, PendingIronwoodOutgoing,
        ValidatedIronwoodEnhancement, validate_and_apply_record,
    },
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

struct TransactionContext {
    request: EnhancePirRequest,
    committed: bool,
}

impl EnhancePirStorage for TransactionContext {
    type AccountId = u32;
    type Account = (u32, UnifiedFullViewingKey, BlockHeight);
    type Error = std::convert::Infallible;

    fn pending_ironwood_metadata(
        &self,
        _: incrementalmerkletree::Position,
    ) -> Result<
        Option<
            zcash_client_backend::data_api::enhance_pir::storage::PendingIronwoodMetadata<
                Self::AccountId,
            >,
        >,
        Self::Error,
    > {
        Ok(None)
    }

    fn get_account(&self, _: u32) -> Result<Option<Self::Account>, Self::Error> {
        Ok(None)
    }

    fn pending_ironwood_memo(
        &self,
        _: Position,
    ) -> Result<Option<PendingIronwoodMemo<u32>>, Self::Error> {
        Ok(None)
    }

    fn pending_ironwood_outgoing(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodOutgoing<u32>>, Self::Error> {
        Ok(
            (position == self.request.position()).then(|| PendingIronwoodOutgoing {
                request_id: self.request.request_id(),
                account_ids: vec![],
                nullifier: [0; 32],
                cmx: [0; 32],
                ephemeral_key: [1; 32],
                compact_ciphertext: [2; 52],
            }),
        )
    }

    fn ironwood_transaction_metadata(
        &self,
        _: TxId,
    ) -> Result<
        Option<zcash_client_backend::data_api::enhance_pir::storage::StoredIronwoodMetadata>,
        Self::Error,
    > {
        panic!("transparent routing must not read transaction metadata")
    }

    fn compare_and_apply_ironwood_enhancement(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<u32>,
    ) -> Result<EnhancePirStoreResult, Self::Error> {
        let zcash_client_backend::data_api::enhance_pir::storage::IronwoodEnhancementData {
            request,
            has_transparent,
            ..
        } = enhancement.into_parts();
        if request != self.request {
            return Ok(EnhancePirStoreResult::AlreadyResolved);
        }
        assert!(has_transparent);
        self.committed = true;
        Ok(EnhancePirStoreResult::LwdRequired)
    }
}

#[test]
fn custom_storage_uses_shared_validation_before_routing() {
    let request = EnhancePirRequest::new(
        5.into(),
        IronwoodEnhanceRequestId::new(TxId::from_bytes([3; 32]), 0),
    );
    let mut storage = TransactionContext {
        request,
        committed: false,
    };
    let record = |ephemeral_key| {
        EnhanceRecord::from_parts(EnhanceRecordParts {
            ephemeral_key,
            enc_ciphertext: [2; 580],
            cv_net: [0; 32],
            out_ciphertext: [0; 80],
            has_transparent_inputs: true,
            has_transparent_outputs: false,
            metadata: zcash_client_backend::data_api::enhance_pir::EnhanceTransactionMetadata::new(
                0,
                Some(0),
            )
            .unwrap(),
        })
    };
    assert_eq!(
        validate_and_apply_record(&mut storage, request, &record([9; 32])),
        Ok(EnhancePirStoreResult::Rejected)
    );
    assert!(!storage.committed);
    let stale = EnhancePirRequest::new(
        request.position(),
        IronwoodEnhanceRequestId::new(TxId::from_bytes([4; 32]), 0),
    );
    assert_eq!(
        validate_and_apply_record(&mut storage, stale, &record([1; 32])),
        Ok(EnhancePirStoreResult::AlreadyResolved)
    );
    assert!(!storage.committed);
    assert_eq!(
        validate_and_apply_record(&mut storage, request, &record([1; 32])),
        Ok(EnhancePirStoreResult::LwdRequired)
    );
    assert!(storage.committed);
}

#[test]
fn canonical_fixture_agrees_with_standard_transaction_fee_and_expiry() {
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId, MAIN_NETWORK},
        value::BalanceError,
    };
    let bytes = hex::decode(include_str!("fixtures/ironwood-fee-expiry.hex").trim()).unwrap();
    let tx = Transaction::read(
        bytes.as_slice(),
        BranchId::for_height(&MAIN_NETWORK, BlockHeight::from_u32(3483367)),
    )
    .unwrap();
    assert_eq!(
        tx.txid().to_string(),
        "f337d9675817668120ae626021f61e5350ff5412beeb5e42b67bd412452b8d13"
    );
    let data = tx.into_data();
    assert_eq!(u32::from(data.expiry_height()), 3483371);
    let fee = data
        .fee_paid::<BalanceError, _>(|_| Ok(None))
        .unwrap()
        .unwrap();
    assert_eq!(u64::from(fee), 10000);
}

use zcash_client_backend::data_api::enhance_pir::{
    EnhanceTransactionMetadata,
    storage::{PendingIronwoodMetadata, StoredIronwoodMetadata},
};

/// A transaction-scoped custom store: action effects are staged until commit succeeds.
struct MetadataStore {
    known: Option<StoredIronwoodMetadata>,
    pending: Vec<EnhancePirRequest>,
    applied: Vec<EnhancePirRequest>,
    lwd_required: bool,
    commit_calls: usize,
    concurrent_metadata: Option<StoredIronwoodMetadata>,
    fail_write: bool,
}

impl MetadataStore {
    fn new(known: StoredIronwoodMetadata) -> Self {
        Self {
            known: Some(known),
            pending: (0..2)
                .map(|index| {
                    EnhancePirRequest::new(
                        Position::from(5 + u64::from(index)),
                        IronwoodEnhanceRequestId::new(TxId::from_bytes([3; 32]), index),
                    )
                })
                .collect(),
            applied: vec![],
            lwd_required: false,
            commit_calls: 0,
            concurrent_metadata: None,
            fail_write: false,
        }
    }
}

impl EnhancePirStorage for MetadataStore {
    type AccountId = u32;
    type Account = (u32, UnifiedFullViewingKey, BlockHeight);
    type Error = &'static str;

    fn ironwood_transaction_metadata(
        &self,
        _: TxId,
    ) -> Result<Option<StoredIronwoodMetadata>, Self::Error> {
        Ok(self.known)
    }

    fn pending_ironwood_metadata(
        &self,
        position: Position,
    ) -> Result<Option<PendingIronwoodMetadata<u32>>, Self::Error> {
        Ok(self
            .pending
            .iter()
            .find(|r| r.position() == position)
            .map(|request| {
                PendingIronwoodMetadata::Compact(PendingIronwoodOutgoing {
                    request_id: request.request_id(),
                    account_ids: vec![],
                    nullifier: [0; 32],
                    cmx: [0; 32],
                    ephemeral_key: [1 + request.request_id().output_index() as u8; 32],
                    compact_ciphertext: [2; 52],
                })
            }))
    }

    fn get_account(&self, _: u32) -> Result<Option<Self::Account>, Self::Error> {
        Ok(None)
    }
    fn pending_ironwood_memo(
        &self,
        _: Position,
    ) -> Result<Option<PendingIronwoodMemo<u32>>, Self::Error> {
        Ok(None)
    }
    fn pending_ironwood_outgoing(
        &self,
        _: Position,
    ) -> Result<Option<PendingIronwoodOutgoing<u32>>, Self::Error> {
        Ok(None)
    }

    fn compare_and_apply_ironwood_enhancement(
        &mut self,
        enhancement: ValidatedIronwoodEnhancement<u32>,
    ) -> Result<EnhancePirStoreResult, Self::Error> {
        self.commit_calls += 1;
        let data = enhancement.into_parts();
        if !self.pending.contains(&data.request) {
            return Ok(EnhancePirStoreResult::AlreadyResolved);
        }
        // Simulate an independent committed writer after the shared read.
        if let Some(concurrent) = self.concurrent_metadata.take() {
            self.known = Some(concurrent);
        }
        let mut next_metadata = self.known;
        if !data.has_transparent {
            let Some(expected) = data.expected_metadata else {
                return Ok(EnhancePirStoreResult::Rejected);
            };
            if self.known != Some(expected) || !expected.agrees_with(data.metadata) {
                return Ok(EnhancePirStoreResult::Rejected);
            }
            next_metadata = Some(expected.filled_from(data.metadata));
        } else {
            assert_eq!(data.expected_metadata, None);
        }
        // A storage error after staging metadata must not leave any response effects.
        if self.fail_write {
            return Err("action write failed");
        }
        self.known = next_metadata;
        self.applied.push(data.request);
        if data.has_transparent {
            self.lwd_required = true;
            self.pending.clear();
            Ok(EnhancePirStoreResult::LwdRequired)
        } else {
            self.pending.retain(|r| *r != data.request);
            Ok(EnhancePirStoreResult::Stored)
        }
    }
}

fn metadata_record(
    request: EnhancePirRequest,
    fee: Option<u64>,
    expiry: u32,
    transparent: bool,
) -> EnhanceRecord {
    EnhanceRecord::from_parts(EnhanceRecordParts {
        ephemeral_key: [1 + request.request_id().output_index() as u8; 32],
        enc_ciphertext: [2; 580],
        cv_net: [0; 32],
        out_ciphertext: [0; 80],
        has_transparent_inputs: transparent,
        has_transparent_outputs: false,
        metadata: EnhanceTransactionMetadata::new(expiry, fee).unwrap(),
    })
}

#[test]
fn custom_store_rejects_known_transaction_metadata_disagreement_before_commit() {
    for differing in [(20_000, 100), (10_000, 101), (20_000, 101)] {
        for reverse in [false, true] {
            let mut values = [(10_000, 100), differing];
            if reverse {
                values.reverse();
            }
            // Expiry must come from an independent trusted source, not the first PIR response.
            let mut store = MetadataStore::new(StoredIronwoodMetadata {
                fee_zatoshis: None,
                expiry_height: Some(values[0].1),
            });
            let requests = store.pending.clone();
            let first = metadata_record(requests[0], Some(values[0].0), values[0].1, false);
            let second = metadata_record(requests[1], Some(values[1].0), values[1].1, false);
            assert_eq!(
                validate_and_apply_record(&mut store, requests[0], &first),
                Ok(EnhancePirStoreResult::Stored)
            );
            let committed = store.known;
            assert_eq!(
                validate_and_apply_record(&mut store, requests[1], &second),
                Ok(EnhancePirStoreResult::Rejected)
            );
            assert_eq!(
                store.commit_calls, 1,
                "shared validation must reject before backend commit"
            );
            assert_eq!(store.known, committed);
            assert_eq!(store.pending, vec![requests[1]]);
            assert_eq!(store.applied, vec![requests[0]]);
            assert!(!store.lwd_required);
        }
    }
}

#[test]
fn custom_store_fills_unknown_fields_and_accepts_matching_actions_including_zero_fee() {
    for (fee, expiry) in [(10_000u64, 100u32), (0, 0), (0, 499_999_999)] {
        let known_cases = [
            StoredIronwoodMetadata::default(),
            StoredIronwoodMetadata {
                fee_zatoshis: Some(fee),
                expiry_height: None,
            },
            StoredIronwoodMetadata {
                fee_zatoshis: None,
                expiry_height: Some(expiry),
            },
            StoredIronwoodMetadata {
                fee_zatoshis: Some(fee),
                expiry_height: Some(expiry),
            },
        ];
        for known in known_cases {
            let mut store = MetadataStore::new(known);
            for request in store.pending.clone() {
                let record = metadata_record(request, Some(fee), expiry, false);
                assert_eq!(
                    validate_and_apply_record(&mut store, request, &record),
                    Ok(EnhancePirStoreResult::Stored)
                );
            }
            assert_eq!(
                store.known,
                Some(StoredIronwoodMetadata {
                    fee_zatoshis: Some(fee),
                    expiry_height: known.expiry_height,
                })
            );
            assert!(store.pending.is_empty());
            assert_eq!(store.applied.len(), 2);
        }
    }
}

#[test]
fn custom_store_does_not_treat_known_zero_as_unknown() {
    for known in [
        StoredIronwoodMetadata {
            fee_zatoshis: Some(0),
            expiry_height: None,
        },
        StoredIronwoodMetadata {
            fee_zatoshis: None,
            expiry_height: Some(0),
        },
    ] {
        let mut store = MetadataStore::new(known);
        let request = store.pending[0];
        let record = metadata_record(request, Some(10_000), 100, false);
        assert_eq!(
            validate_and_apply_record(&mut store, request, &record),
            Ok(EnhancePirStoreResult::Rejected)
        );
        assert_eq!(store.known, Some(known));
        assert_eq!(store.commit_calls, 0);
        assert_eq!(store.pending.len(), 2);
    }
}

#[test]
fn custom_store_compare_and_apply_rejects_changed_snapshot_even_when_values_agree() {
    for concurrent in [
        StoredIronwoodMetadata {
            fee_zatoshis: Some(20_000),
            expiry_height: Some(101),
        },
        StoredIronwoodMetadata {
            fee_zatoshis: Some(10_000),
            expiry_height: Some(100),
        },
    ] {
        let mut store = MetadataStore::new(StoredIronwoodMetadata::default());
        let request = store.pending[0];
        store.concurrent_metadata = Some(concurrent);
        let record = metadata_record(request, Some(10_000), 100, false);
        assert_eq!(
            validate_and_apply_record(&mut store, request, &record),
            Ok(EnhancePirStoreResult::Rejected)
        );
        assert_eq!(store.commit_calls, 1);
        assert_eq!(store.known, Some(concurrent));
        assert_eq!(store.pending.len(), 2);
        assert!(store.applied.is_empty());
        assert!(!store.lwd_required);
        if concurrent.fee_zatoshis == Some(10_000) {
            assert_eq!(
                validate_and_apply_record(&mut store, request, &record),
                Ok(EnhancePirStoreResult::Stored)
            );
        }
    }
}

#[test]
fn custom_store_write_failure_does_not_commit_metadata_or_action_effects() {
    let mut store = MetadataStore::new(StoredIronwoodMetadata::default());
    store.fail_write = true;
    let request = store.pending[0];
    let record = metadata_record(request, Some(10_000), 100, false);
    assert_eq!(
        validate_and_apply_record(&mut store, request, &record),
        Err("action write failed")
    );
    assert_eq!(store.known, Some(StoredIronwoodMetadata::default()));
    assert_eq!(store.pending.len(), 2);
    assert!(store.applied.is_empty());
    assert!(!store.lwd_required);
}

#[test]
fn custom_store_transparent_routing_does_not_store_conflicting_metadata() {
    let known = StoredIronwoodMetadata {
        fee_zatoshis: Some(0),
        expiry_height: Some(0),
    };
    let mut store = MetadataStore::new(known);
    let request = store.pending[0];
    let record = metadata_record(request, Some(10_000), 100, true);
    assert_eq!(
        validate_and_apply_record(&mut store, request, &record),
        Ok(EnhancePirStoreResult::LwdRequired)
    );
    assert_eq!(store.known, Some(known));
    assert!(store.lwd_required);
}

#[test]
fn custom_store_missing_transaction_or_fee_never_commits() {
    let mut store = MetadataStore::new(StoredIronwoodMetadata::default());
    let request = store.pending[0];
    let no_fee = metadata_record(request, None, 100, false);
    assert_eq!(
        validate_and_apply_record(&mut store, request, &no_fee),
        Ok(EnhancePirStoreResult::Rejected)
    );
    store.known = None;
    let valid = metadata_record(request, Some(10_000), 100, false);
    assert_eq!(
        validate_and_apply_record(&mut store, request, &valid),
        Ok(EnhancePirStoreResult::AlreadyResolved)
    );
    assert_eq!(store.commit_calls, 0);
    assert_eq!(store.pending.len(), 2);
}
