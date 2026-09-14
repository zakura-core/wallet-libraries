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

    fn apply_ironwood_enhancement(
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
