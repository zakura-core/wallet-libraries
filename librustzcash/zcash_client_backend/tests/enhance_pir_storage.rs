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
        let (request, has_transparent, _, _) = enhancement.into_parts();
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
