//! Optional adapters for applying decoded records to wallet backends.

use zcash_client_backend::data_api::enhance_pir::{
    EnhancePirRequest, EnhancePirStoreResult, EnhancePirWrite, IronwoodEnhanceRecord,
    apply_ironwood_enhance_record,
};

use crate::EnhanceRecord;

/// Atomic result for all work at one action.
pub type ApplyRecordResult = EnhancePirStoreResult;

/// Converts validated wire fields, including trusted (not authenticated) shape flags.
pub fn wallet_record(record: &EnhanceRecord) -> IronwoodEnhanceRecord {
    IronwoodEnhanceRecord::from_parts(
        *record.ephemeral_key(),
        *record.enc_ciphertext(),
        *record.cv_net(),
        *record.out_ciphertext(),
        record
            .has_transparent_inputs()
            .expect("record validated by PIR client"),
        record
            .has_transparent_outputs()
            .expect("record validated by PIR client"),
    )
}

/// Binds the record to the locally captured request, then applies it atomically.
///
/// Only the request's position is sent to the PIR server; its identity is local.
pub fn apply_record<DbT: EnhancePirWrite>(
    db: &mut DbT,
    request: EnhancePirRequest,
    record: &EnhanceRecord,
) -> Result<ApplyRecordResult, DbT::Error> {
    apply_ironwood_enhance_record(db, request, &wallet_record(record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnhanceRecordParts;

    #[test]
    fn forwards_both_shape_flags_and_all_ciphertext_fields() {
        for (inputs, outputs) in [(false, false), (true, false), (false, true), (true, true)] {
            let wire = EnhanceRecord::from_parts(EnhanceRecordParts {
                ephemeral_key: [1; 32],
                enc_ciphertext: [2; 580],
                cv_net: [3; 32],
                out_ciphertext: [4; 80],
                has_transparent_inputs: inputs,
                has_transparent_outputs: outputs,
            });
            let record = wallet_record(&wire);
            assert_eq!(record.has_transparent(), inputs || outputs);
            assert_eq!(record.ephemeral_key(), &[1; 32]);
            assert_eq!(record.ciphertext(), &[2; 580]);
            assert_eq!(record.cv_net(), &[3; 32]);
            assert_eq!(record.out_ciphertext(), &[4; 80]);
        }
    }
}
