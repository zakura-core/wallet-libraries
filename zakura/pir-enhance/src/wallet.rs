//! Optional adapters for applying decoded records to wallet backends.

use zcash_client_backend::data_api::enhance_pir::{
    EnhancePirRequest, EnhancePirStoreResult, EnhancePirWrite, IronwoodEnhanceRecord,
    decrypt_and_store_ironwood_memo, recover_and_store_ironwood_outgoing,
};

use crate::EnhanceRecord;

/// Results of applying one decoded record to both kinds of work at its position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyRecordResult {
    pub incoming: EnhancePirStoreResult,
    pub outgoing: EnhancePirStoreResult,
}

/// Converts the wire record into the wallet backend's authenticated record type.
pub fn wallet_record(record: &EnhanceRecord) -> IronwoodEnhanceRecord {
    IronwoodEnhanceRecord::from_parts(
        *record.ephemeral_key(),
        *record.enc_ciphertext(),
        *record.cv_net(),
        *record.out_ciphertext(),
    )
}

/// Authenticates and applies a record to all pending work at `position`.
///
/// A position can represent both an incoming memo and an outgoing recovery, so
/// callers should use this helper instead of selecting only one completion path.
pub fn apply_record<DbT: EnhancePirWrite>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &EnhanceRecord,
) -> Result<ApplyRecordResult, DbT::Error> {
    let record = wallet_record(record);
    let incoming = decrypt_and_store_ironwood_memo(db, request, &record)?;
    let outgoing = recover_and_store_ironwood_outgoing(db, request, &record)?;
    Ok(ApplyRecordResult { incoming, outgoing })
}
