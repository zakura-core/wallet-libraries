# zakura-pir-enhance-types

Shared schema-11 record types for private Ironwood compact-action enhancement.
Release candidate `0.0.1-rc0` uses a fixed 653-byte encoding and has no external
dependencies. The minimum supported Rust version is 1.91.

`EnhanceRecord::from_bytes` validates the record encoding, including reserved
flags, expiry-height bounds, fee bounds, and zero payloads for absent fees.
`EnhanceRecordParts` and `EnhanceTransactionMetadata` support construction and
access to the encrypted-note fields and transaction metadata.

```rust
use zakura_pir_enhance_types::{EnhanceRecord, RECORD_BYTES};

let record = EnhanceRecord::from_bytes([0; RECORD_BYTES])?;
assert_eq!(record.as_bytes().len(), 653);
# Ok::<(), zakura_pir_enhance_types::InvalidEnhanceRecord>(())
```

Encoding validation is not cryptographic authentication. The wallet must
validate request identity and authenticate decrypted notes. Transaction
metadata is trusted indexer data, and send-only association can require trust
in the server when decryption cannot authenticate the action.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
