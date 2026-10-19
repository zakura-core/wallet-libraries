//! Private status observations and explicit source policy.
//! Queries go through the accepted-anchor transport; the raw selector stays private.
//! ```compile_fail
//! use zakura_pir_client::status::Client;
//! ```
//! ```compile_fail
//! use zakura_pir_client::status::decode_row;
//! ```
pub use zakura_pir_protocol::status::{
    AcceptedAnchor, AcceptedAnchors, AnchorVerifier, COLS, Error, HEADER_BYTES, Hash, ITEM_BITS,
    LocalCoverageContext, MAX_AGE_MS, MAX_ENTRIES, MAX_FUTURE_SKEW_MS, Manifest, Observation,
    PROTOCOL, QUERY_MAGIC, ROW_BYTES, ROWS, Record, SLOT_BYTES, SLOTS, bucket, native_packing_seed,
    native_setup_seed,
};
use zakura_pir_protocol::status::{anchor_accepted, decode_row};
pub mod policy;
pub mod transport;
use rand::{Rng, rngs::OsRng};
use sha2::{Digest, Sha256};
/// Exact length of the public session material: both 29-bit masks per column.
pub(crate) fn session_len() -> Result<usize, Error> {
    Ok(crate::native::public_len(COLS))
}
/// Exact length of a query response, including the echoed header.
pub(crate) fn response_len() -> Result<usize, Error> {
    Ok(HEADER_BYTES + crate::native::response_len(COLS))
}
/// Exact length of a query body, including the header: one uploaded key and a
/// selection dithered to [`crate::native::DITHERED_QUERY_BITS`].
#[cfg(test)]
pub(crate) fn request_len() -> usize {
    HEADER_BYTES + crate::native::request_len_bits(ROWS, crate::native::DITHERED_QUERY_BITS)
}
/// `body` may be moved into the transport; decoding uses the retained header.
pub(crate) struct Query {
    pub(crate) body: Vec<u8>,
    header: [u8; HEADER_BYTES],
    secret: crate::native::NativeSecret,
    txid: Hash,
    earliest: Option<u32>,
}
pub(crate) struct Client {
    manifest: Manifest,
    packing: crate::native::NativeSetup,
    masks: Vec<Vec<u64>>,
    public: Vec<u8>,
}
impl Client {
    /// The manifest accepted by [`Client::new`]; it cannot be replaced without
    /// repeating anchor acceptance and setup.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// Checks shared by every profile before the row selector is encrypted.
    fn envelope(
        &self,
        txid: &[u8],
        coverage: LocalCoverageContext,
        now_ms: u64,
    ) -> Result<(Hash, Vec<u8>), Error> {
        let txid: Hash = txid.try_into().map_err(|_| Error::Malformed)?;
        self.manifest.fresh(now_ms)?;
        coverage.validate(&self.manifest)?;
        let mut body = QUERY_MAGIC.to_vec();
        body.extend(self.manifest.id());
        body.extend(OsRng.r#gen::<[u8; 16]>());
        Ok((txid, body))
    }
    /// Checks shared by every profile before the response body is decrypted.
    /// A query prepared under another manifest is `Stale`, even when that
    /// manifest shares this client's public setup.
    fn check_response(
        &self,
        header: &[u8; HEADER_BYTES],
        response: &[u8],
        now_ms: u64,
    ) -> Result<(), Error> {
        self.manifest.fresh(now_ms)?;
        if header[4..36] != self.manifest.id() {
            return Err(Error::Stale);
        }
        if response.len() != response_len()? || response[..HEADER_BYTES] != header[..] {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
impl Client {
    pub fn new(
        manifest: Manifest,
        public: &[u8],
        accepted: &dyn AnchorVerifier,
    ) -> Result<Self, Error> {
        manifest.validate()?;
        if !anchor_accepted(&manifest, accepted) {
            return Err(Error::Malformed);
        }
        if public.len() != session_len()?
            || Hash::from(Sha256::digest(public)) != manifest.public_digest
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            packing: crate::native::packing_setup(native_packing_seed(
                &manifest.network,
                &manifest.salt,
            )),
            masks: crate::native::public_query_masks(
                native_setup_seed(&manifest.network, &manifest.salt),
                ROWS,
                COLS,
            ),
            public: public.to_vec(),
            manifest,
        })
    }
    pub fn prepare(
        &self,
        txid: &[u8],
        coverage: LocalCoverageContext,
        now_ms: u64,
    ) -> Result<Query, Error> {
        let (txid, mut body) = self.envelope(txid, coverage, now_ms)?;
        let row = bucket(&self.manifest.network, &self.manifest.salt, &txid);
        let (secret, payload) =
            crate::native::prepare_dithered(&self.packing, &self.masks, ROWS, row)
                .map_err(|_| Error::Pir)?;
        body.extend(payload);
        Ok(Query {
            header: body[..HEADER_BYTES].try_into().unwrap(),
            body,
            secret,
            txid,
            earliest: coverage.earliest_possible_inclusion,
        })
    }
    pub fn decode(&self, query: Query, response: &[u8], now_ms: u64) -> Result<Observation, Error> {
        self.check_response(&query.header, response, now_ms)?;
        let row = crate::native::decode_cols(
            &query.secret,
            &self.public,
            &response[HEADER_BYTES..],
            COLS,
        )
        .map_err(|_| Error::Pir)?;
        decode_row(&self.manifest, &query.txid, query.earliest, &row)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Manifest {
        Manifest {
            protocol: PROTOCOL.into(),
            network: [1; 32],
            salt: [2; 32],
            generation: 1,
            recovery_epoch: 0,
            coverage_start: 10,
            anchor_height: 20,
            anchor_hash: [3; 32],
            observed_ms: 1000,
            entries: 1,
            rows_digest: [4; 32],
            public_digest: [5; 32],
        }
    }
    #[test]
    fn row_geometry_and_retired_protocol_rejection() {
        assert_eq!((ROWS, SLOTS, SLOT_BYTES, ROW_BYTES), (8192, 256, 40, 12288));
        assert_eq!(ROWS * ROW_BYTES, 96 * 1024 * 1024);
        let mut m = manifest();
        for retired in ["status-pir-v1-q48", "status-pir-v2-q48"] {
            m.protocol = retired.into();
            assert_eq!(m.validate(), Err(Error::Unsupported));
        }
        assert_eq!(Record::decode(&[0; 80]), Err(Error::Malformed));
    }
    #[test]
    fn native_setup_domains_match_independent_python_vectors() {
        assert_eq!(
            hex::encode(native_setup_seed(&[1; 32], &[2; 32])),
            "c8cb85010ef6544f65566f275551a3c62616692e6f0a88429176fb83a16aeccf"
        );
        assert_eq!(
            hex::encode(native_packing_seed(&[1; 32], &[2; 32])),
            "7f99c2ef04dab7c859432bb188475a9e2680b06f8cd7eae099ed24f9a0698af5"
        );
        assert_ne!(
            native_setup_seed(&[1; 32], &[2; 32]),
            native_packing_seed(&[1; 32], &[2; 32])
        );
    }
    #[test]
    fn native_wire_identity_and_exact_lengths() {
        assert_eq!(PROTOCOL, "status-pir-v3-native-two-mask-m29");
        assert_eq!(QUERY_MAGIC, b"SPN1");
        assert_eq!(COLS, 6144);
        // Two 29-bit masks per column.
        assert_eq!(session_len(), Ok(44_544));
        // Echoed header plus 6144 22-bit coefficients.
        assert_eq!(response_len(), Ok(HEADER_BYTES + 16_896));
        // Header, one uploaded key and a 44-bit dithered selection over 8192
        // rows; servers also accept the 49-bit selection, so the two lengths
        // must differ.
        assert_eq!(crate::native::KEY_BYTES, 27_648);
        assert_eq!(crate::native::DITHERED_QUERY_BITS, 44);
        assert_eq!(request_len(), HEADER_BYTES + 27_648 + 45_056);
        assert_eq!(request_len(), 72_756);
        assert_eq!(crate::native::request_len(ROWS), 27_648 + 50_176);
    }
    #[test]
    fn independent_python_hash_vector() {
        let txid = std::array::from_fn(|i| i as u8);
        assert_eq!(bucket(&[1; 32], &[2; 32], &txid), 6818);
    }
    #[test]
    fn slot_codec_rejects_reserved_bytes_empty_garbage_and_invalid_states() {
        for (tag, height) in [(1, 0), (2, 10), (3, 10)] {
            let r = Record {
                txid: [4; 32],
                tag,
                height,
            };
            let bytes = r.encode().unwrap();
            assert_eq!(Record::decode(&bytes), Ok(Some(r)));
            let mut bad = bytes;
            bad[33] = 1;
            assert_eq!(Record::decode(&bad), Err(Error::Malformed));
            let mut bad = bytes;
            bad[32] = 4;
            assert_eq!(Record::decode(&bad), Err(Error::Malformed));
        }
        let mut empty = [0; SLOT_BYTES];
        empty[0] = 1;
        assert_eq!(Record::decode(&empty), Err(Error::Malformed));
        assert!(
            Record {
                txid: [0; 32],
                tag: 1,
                height: 1,
            }
            .encode()
            .is_err()
        );
        assert!(
            Record {
                txid: [0; 32],
                tag: 2,
                height: 0,
            }
            .encode()
            .is_err()
        );
    }
    #[test]
    fn missing_reconfirmation_record_requires_creation_evidence_and_retained_coverage() {
        let mut snapshot = manifest();
        snapshot.coverage_start = 15;
        let empty_row = vec![0; ROW_BYTES];
        // Previously observed inclusion at 12 is now outside the retained window.
        // It is not a trustworthy creation bound and cannot turn missing history into absence.
        assert_eq!(
            decode_row(&snapshot, &[9; 32], None, &empty_row),
            Err(Error::CoverageIncomplete)
        );
        assert_eq!(
            decode_row(&snapshot, &[9; 32], Some(12), &empty_row),
            Err(Error::CoverageIncomplete)
        );
        // Only actual conservative creation evidence covered by the snapshot supports absence.
        assert_eq!(
            decode_row(&snapshot, &[9; 32], Some(15), &empty_row),
            Ok(Observation::NotFound)
        );
        assert_eq!(
            LocalCoverageContext {
                earliest_possible_inclusion: Some(15),
                required_through: Some(snapshot.anchor_height + 1)
            }
            .validate(&snapshot),
            Err(Error::CoverageIncomplete)
        );
    }

    #[test]
    fn freshness_coverage_and_binding_are_separate() {
        let m = manifest();
        let row = vec![0; ROW_BYTES];
        assert_eq!(m.fresh(21_000), Ok(()));
        assert_eq!(m.fresh(21_001), Err(Error::Stale));
        assert_eq!(m.fresh(999), Ok(()));
        assert_eq!(
            LocalCoverageContext {
                earliest_possible_inclusion: Some(10),
                required_through: Some(21),
            }
            .validate(&m),
            Err(Error::CoverageIncomplete)
        );
        assert_eq!(
            LocalCoverageContext {
                earliest_possible_inclusion: None,
                required_through: Some(20),
            }
            .validate(&m),
            Ok(())
        );
        for earliest in [None, Some(9), Some(21)] {
            assert_eq!(
                decode_row(&m, &[9; 32], earliest, &row),
                Err(Error::CoverageIncomplete)
            );
        }
        for earliest in [10, 20] {
            assert_eq!(
                decode_row(&m, &[9; 32], Some(earliest), &row),
                Ok(Observation::NotFound)
            );
        }
        for through in [19, 20] {
            assert_eq!(
                LocalCoverageContext {
                    earliest_possible_inclusion: Some(10),
                    required_through: Some(through)
                }
                .validate(&m),
                Ok(())
            );
        }
        let id = m.id();
        let mut changed = m.clone();
        changed.observed_ms += 1;
        assert_ne!(changed.id(), id);
        let mut changed = m.clone();
        changed.recovery_epoch += 1;
        assert_ne!(changed.id(), id);
        let mut changed = m.clone();
        changed.coverage_start += 1;
        assert_ne!(changed.id(), id);
        let mut changed = m;
        changed.protocol = "other".into();
        assert_eq!(changed.validate(), Err(Error::Unsupported));
    }
    #[test]
    fn freshness_tolerates_bounded_future_skew() {
        let mut m = manifest();
        m.observed_ms = 10_000;
        assert_eq!(m.fresh(10_000 - 4_000), Ok(()));
        assert_eq!(m.fresh(10_000 - MAX_FUTURE_SKEW_MS), Ok(()));
        assert_eq!(
            m.fresh(10_000 - MAX_FUTURE_SKEW_MS - 1),
            Err(Error::Malformed)
        );
        assert_eq!(m.fresh(10_000 - 6_000), Err(Error::Malformed));
        assert_eq!(m.fresh(10_000 + MAX_AGE_MS), Ok(()));
        assert_eq!(m.fresh(10_000 + 20_001), Err(Error::Stale));
    }
    #[test]
    fn anchor_verifiers_bind_network_height_and_hash() {
        let m = manifest();
        let exact = AcceptedAnchor {
            network: m.network,
            height: m.anchor_height,
            hash: m.anchor_hash,
        };
        assert!(anchor_accepted(&m, &exact));
        assert!(!anchor_accepted(
            &m,
            &AcceptedAnchor {
                height: m.anchor_height - 1,
                ..exact
            }
        ));
        assert!(!anchor_accepted(
            &m,
            &AcceptedAnchor {
                hash: [7; 32],
                ..exact
            }
        ));
        assert!(!anchor_accepted(
            &m,
            &AcceptedAnchor {
                network: [8; 32],
                ..exact
            }
        ));
        let window = AcceptedAnchors {
            network: m.network,
            known: vec![(19, [9; 32]), (20, m.anchor_hash), (21, [10; 32])],
        };
        assert!(anchor_accepted(&m, &window));
        assert!(anchor_accepted(&m, &&window));
        let mut other = m.clone();
        other.anchor_height = 19;
        other.anchor_hash = [9; 32];
        assert!(anchor_accepted(&other, &window));
        other.anchor_hash = m.anchor_hash;
        assert!(!anchor_accepted(&other, &window));
        let wrong_network = AcceptedAnchors {
            network: [8; 32],
            known: window.known.clone(),
        };
        assert!(!anchor_accepted(&m, &wrong_network));
        let empty = AcceptedAnchors {
            network: m.network,
            known: Vec::new(),
        };
        assert!(!anchor_accepted(&m, &empty));
        let public = vec![0; session_len().unwrap()];
        let mut m = m;
        m.public_digest = Sha256::digest(&public).into();
        assert!(Client::new(m.clone(), &public, &window).is_ok());
        assert_eq!(
            Client::new(m, &public, &empty).err(),
            Some(Error::Malformed)
        );
    }
    #[test]
    fn complete_row_is_validated_even_after_a_match() {
        let m = manifest();
        let txid = [9; 32];
        let r = Record {
            txid,
            tag: 2,
            height: 11,
        };
        let mut row = vec![0; ROW_BYTES];
        row[..SLOT_BYTES].copy_from_slice(&r.encode().unwrap());
        assert_eq!(
            decode_row(&m, &txid, None, &row),
            Ok(Observation::Mined(11))
        );
        row[ROW_BYTES - 1] = 1;
        assert_eq!(decode_row(&m, &txid, None, &row), Err(Error::Malformed));
        row[ROW_BYTES - 1] = 0;
        row[SLOT_BYTES..SLOT_BYTES * 2].copy_from_slice(&r.encode().unwrap());
        assert_eq!(decode_row(&m, &txid, None, &row), Err(Error::Malformed));
    }
    fn single(tag: u8, height: u32) -> Vec<u8> {
        let mut row = vec![0; ROW_BYTES];
        let r = Record {
            txid: [9; 32],
            tag,
            height,
        };
        row[..SLOT_BYTES].copy_from_slice(&r.encode().unwrap());
        row
    }
    #[test]
    fn row_cannot_hold_more_records_than_the_manifest() {
        let mut m = manifest();
        let row = single(2, 11);
        assert_eq!(
            decode_row(&m, &[9; 32], None, &row),
            Ok(Observation::Mined(11))
        );
        m.entries = 0;
        assert_eq!(decode_row(&m, &[9; 32], None, &row), Err(Error::Malformed));
    }
    #[test]
    fn records_at_the_anchor_are_status_observations() {
        let m = manifest();
        for (tag, expected) in [
            (2, Ok(Observation::Mined(20))),
            (3, Ok(Observation::Forked)),
        ] {
            let row = single(tag, m.anchor_height);
            assert_eq!(decode_row(&m, &[9; 32], None, &row), expected);
        }
    }

    #[test]
    fn match_below_local_inclusion_bound_is_malformed() {
        let m = manifest();
        for (tag, height, earliest, expected) in [
            (2, 11, Some(15), Err(Error::Malformed)),
            (2, 11, Some(11), Ok(Observation::Mined(11))),
            (3, 11, Some(15), Err(Error::Malformed)),
            (1, 0, Some(15), Ok(Observation::Mempool)),
        ] {
            let row = single(tag, height);
            assert_eq!(decode_row(&m, &[9; 32], earliest, &row), expected);
        }
    }
    #[test]
    fn oversized_snapshot_is_a_capacity_error() {
        let mut m = manifest();
        m.entries = MAX_ENTRIES;
        assert_eq!(m.validate(), Ok(()));
        m.entries += 1;
        assert_eq!(m.validate(), Err(Error::Capacity));
    }
    fn client(m: &Manifest) -> Client {
        let public = vec![0; session_len().unwrap()];
        let mut m = m.clone();
        m.public_digest = Sha256::digest(&public).into();
        let accepted = AcceptedAnchor {
            network: m.network,
            height: m.anchor_height,
            hash: m.anchor_hash,
        };
        Client::new(m, &public, &accepted).unwrap()
    }
    #[test]
    fn decode_uses_the_retained_header_after_body_is_moved() {
        let c = client(&manifest());
        let mut query = c
            .prepare(&[9; 32], LocalCoverageContext::default(), 1000)
            .unwrap();
        let header = query.body[..HEADER_BYTES].to_vec();
        drop(std::mem::take(&mut query.body));
        let mut response = vec![0; response_len().unwrap()];
        response[..HEADER_BYTES].copy_from_slice(&header);
        response[HEADER_BYTES - 1] ^= 1;
        assert_eq!(c.decode(query, &response, 1000), Err(Error::Malformed));
    }
    #[test]
    fn query_from_another_manifest_is_stale() {
        let a = manifest();
        let mut b = a.clone();
        b.generation += 1;
        let (a, b) = (client(&a), client(&b));
        let query = a
            .prepare(&[9; 32], LocalCoverageContext::default(), 1000)
            .unwrap();
        let mut response = vec![0; response_len().unwrap()];
        response[..HEADER_BYTES].copy_from_slice(&query.body[..HEADER_BYTES]);
        assert_eq!(b.decode(query, &response, 1000), Err(Error::Stale));
    }
}
