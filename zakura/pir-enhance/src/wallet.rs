//! Synchronous wallet acceptance and identity capture. No network I/O or writes.
use crate::{
    AcceptedAnchor, ClientError, ClientResourceLimits, EnhanceRecord, GenerationAcceptance,
    Manifest,
};
use std::collections::BTreeMap;
use zcash_client_backend::data_api::enhance_pir::{
    EnhancePirRead, EnhancePirRequest, EnhancePirSnapshotAnchor, EnhancePirSnapshotStatus,
    EnhancePirWork,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};

/// One decoded row, retaining every requested wallet identity in input order.
#[derive(Clone, Debug)]
pub struct RowQueryResult {
    pub row: u64,
    pub slots: Vec<(EnhancePirRequest, EnhanceRecord)>,
}

pub enum Acceptance {
    Accepted(GenerationAcceptance),
    WaitingForScanning,
    Mismatch,
}

pub fn snapshot_anchor(manifest: &Manifest) -> Result<EnhancePirSnapshotAnchor, ClientError> {
    manifest
        .coverage
        .validate(manifest.geometry)
        .map_err(ClientError::Generation)?;
    let height = u32::try_from(manifest.anchor_height)
        .map_err(|_| ClientError::Generation("anchor height exceeds wallet range".into()))?;
    let mut hash: [u8; 32] = hex::decode(&manifest.anchor_block_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ClientError::Generation("invalid anchor block hash".into()))?;
    hash.reverse();
    Ok(EnhancePirSnapshotAnchor {
        height: BlockHeight::from(height),
        block_hash: BlockHash::from_slice(&hash),
        ironwood_tree_size: manifest.coverage.records,
    })
}

/// Checks locally scanned state before creating client acceptance. Storage
/// errors are returned separately from protocol errors; neither permits setup.
/// Network and NU6.3 activation come from the wallet's trusted consensus
/// parameters, never from the advertised generation. An unscheduled activation
/// rejects the generation. Pass the same parameters used to open/scan the wallet.
pub fn acceptance<D: EnhancePirRead>(
    db: &D,
    manifest: &Manifest,
    params: &impl Parameters,
    limits: ClientResourceLimits,
) -> Result<Result<Acceptance, ClientError>, D::Error> {
    let network = match params.network_type() {
        NetworkType::Main => "main",
        NetworkType::Test => "test",
        NetworkType::Regtest => "regtest",
    };
    let Some(activation) = params.activation_height(NetworkUpgrade::Nu6_3) else {
        return Ok(Err(ClientError::Generation(
            "NU6.3 activation unavailable".into(),
        )));
    };
    let activation_height = u64::from(u32::from(activation));
    let anchor = match snapshot_anchor(manifest) {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    let mut display_hash = anchor.block_hash.0;
    display_hash.reverse();
    let accepted = GenerationAcceptance::new(
        network,
        activation_height,
        AcceptedAnchor::new(
            manifest.anchor_height,
            display_hash,
            manifest.coverage.records,
        ),
        limits,
    );
    if let Err(e) = accepted.validate(manifest) {
        return Ok(Err(e));
    }
    Ok(Ok(match db.enhance_pir_snapshot_status(anchor)? {
        EnhancePirSnapshotStatus::Accepted => Acceptance::Accepted(accepted),
        EnhancePirSnapshotStatus::NotYetScanned => Acceptance::WaitingForScanning,
        EnhancePirSnapshotStatus::Mismatch => Acceptance::Mismatch,
    }))
}

/// Original identities survive duplicate positions and must be passed unchanged
/// to EnhancePirWrite, which rejects stale identities after a rewind.
#[derive(Default)]
pub struct PreparedWork {
    requests: BTreeMap<u64, Vec<EnhancePirRequest>>,
    pub rediscover:
        Vec<zcash_client_backend::data_api::enhance_pir::IronwoodEnhanceDiscoveryRequest>,
    pub suspended: usize,
}
impl PreparedWork {
    pub fn new(work: impl IntoIterator<Item = EnhancePirWork>) -> Self {
        let mut prepared = Self::default();
        for item in work {
            match item {
                EnhancePirWork::Query(request) => {
                    let requests = prepared
                        .requests
                        .entry(u64::from(request.position()))
                        .or_default();
                    if !requests.contains(&request) {
                        requests.push(request);
                    }
                }
                EnhancePirWork::Rediscover(request) => prepared.rediscover.push(request),
                EnhancePirWork::Suspended(_) => prepared.suspended += 1,
            }
        }
        prepared
    }
    /// Groups active requests without changing discovery ordering or identities.
    pub fn batches_by_tx_and_row(
        &self,
    ) -> BTreeMap<(zcash_primitives::transaction::TxId, u64), Vec<EnhancePirRequest>> {
        let mut batches: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (&position, requests) in &self.requests {
            for request in requests {
                batches
                    .entry((
                        request.request_id().txid(),
                        position / crate::RECORDS_PER_ROW as u64,
                    ))
                    .or_default()
                    .push(*request);
            }
        }
        batches
    }

    pub fn positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.requests.keys().copied()
    }
    pub fn query_count(&self) -> usize {
        self.requests.values().map(Vec::len).sum()
    }
    pub fn incomplete_count(&self) -> usize {
        self.query_count() + self.rediscover.len() + self.suspended
    }
    pub fn map_record(
        &self,
        position: u64,
        record: EnhanceRecord,
    ) -> impl Iterator<Item = (EnhancePirRequest, EnhanceRecord)> + '_ {
        self.requests
            .get(&position)
            .into_iter()
            .flatten()
            .map(move |request| (*request, record.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Position;
    use zcash_client_backend::data_api::enhance_pir::{
        EnhancePirSuspension, IronwoodEnhanceRequestId,
    };
    use zcash_primitives::transaction::TxId;
    #[test]
    fn keeps_original_identities_when_positions_are_reused() {
        let old = EnhancePirRequest::new(
            Position::from(7),
            IronwoodEnhanceRequestId::new(TxId::from_bytes([1; 32]), 0),
        );
        let new = EnhancePirRequest::new(
            Position::from(7),
            IronwoodEnhanceRequestId::new(TxId::from_bytes([2; 32]), 0),
        );
        let work = PreparedWork::new([
            EnhancePirWork::Query(old),
            EnhancePirWork::Query(old),
            EnhancePirWork::Suspended(EnhancePirSuspension::OutgoingNotRecoverable(new)),
        ]);
        assert_eq!(work.positions().collect::<Vec<_>>(), [7]);
        assert_eq!(work.incomplete_count(), 2);
        let record = EnhanceRecord::from_bytes([0; crate::RECORD_BYTES]).unwrap();
        let mapped = work.map_record(7, record).collect::<Vec<_>>();
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].0, old);
        assert_ne!(mapped[0].0, new);
    }
    #[test]
    fn batches_preserve_identities_at_row_boundaries() {
        let txid = TxId::from_bytes([1; 32]);
        let other = TxId::from_bytes([2; 32]);
        let request = |position, txid| {
            EnhancePirRequest::new(
                Position::from(position),
                IronwoodEnhanceRequestId::new(txid, position as u32),
            )
        };
        let a = request(32, txid);
        let b = request(33, txid);
        let c = request(34, other);
        let prepared = PreparedWork::new([b, a, c, a].map(EnhancePirWork::Query));
        let batches = prepared.batches_by_tx_and_row();
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[&(txid, 0)], [a]);
        assert_eq!(batches[&(txid, 1)], [b]);
        assert_eq!(batches[&(other, 1)], [c]);
        assert_eq!(prepared.positions().collect::<Vec<_>>(), [32, 33, 34]);
    }

    #[test]
    fn suspensions_are_incomplete_without_active_queries() {
        let request = EnhancePirRequest::new(
            Position::from(0),
            IronwoodEnhanceRequestId::new(TxId::from_bytes([1; 32]), 0),
        );
        let work = PreparedWork::new([EnhancePirWork::Suspended(
            EnhancePirSuspension::OutgoingNotRecoverable(request),
        )]);
        assert_eq!(work.query_count(), 0);
        assert_eq!(work.incomplete_count(), 1);
    }
}

#[cfg(test)]
mod acceptance_tests {
    use super::*;
    use crate::types::Lifecycle;
    use crate::*;
    use sha2::{Digest, Sha256};
    use zcash_client_backend::data_api::{WalletRead, testing::TestBuilder};
    use zcash_client_sqlite::testing::{BlockCache, db::TestDbFactory};
    use zcash_protocol::local_consensus::LocalNetwork;
    #[test]
    fn snapshot_anchor_uses_v4_coverage_and_scanned_wallet_state() {
        let activation = BlockHeight::from_u32(100_000);
        let network = LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };
        let mut state = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let (height, _) = state.generate_empty_block();
        let geometry = Geometry::default();
        let coverage = Lifecycle::default().coverage(1, geometry).unwrap();
        let shard = &coverage.shards[0];
        let shard_id = shard.id;
        let shard_logical_rows = shard.logical_rows;
        let unit_identities = BTreeMap::from([(
            shard.id,
            shard
                .units
                .iter()
                .map(|unit| UnitIdentity {
                    recovery_epoch: 0,
                    table: "enhance".into(),
                    shard_id: shard.id,
                    local_row_start: unit.local_row_start,
                    allocated_rows: unit.allocated_rows,
                    setup_sha256: hex::encode(Sha256::digest(setup_seed(shard.id))),
                    parameter_id: unit_parameter_id(unit.allocated_rows).unwrap(),
                    content_sha256: "00".repeat(32),
                })
                .collect(),
        )]);
        let mut manifest = Manifest {
            recovery_epoch: 0,
            placement_revision: 1,
            domain_recovery_epochs: [(0, "0".into())].into(),
            schema_version: SCHEMA_VERSION,
            protocol_revision: PROTOCOL_REVISION.into(),
            network: "main".into(),
            pool: POOL.into(),
            generation: 1,
            anchor_height: u64::from(u32::from(height)),
            anchor_block_hash: "00".repeat(32),
            geometry,
            coverage,
            sessions: vec![SessionRef {
                shard_id,
                public_params_sha256: "00".repeat(32),
                parameter_id: parameter_id(shard_logical_rows).unwrap(),
            }],
            unit_identities,
        };
        manifest.validate().unwrap();
        assert!(matches!(
            state
                .wallet()
                .db()
                .enhance_pir_snapshot_status(snapshot_anchor(&manifest).unwrap()),
            Ok(EnhancePirSnapshotStatus::NotYetScanned)
        ));
        state.scan_cached_blocks(height, 1);
        let metadata = state.wallet().db().block_metadata(height).unwrap().unwrap();
        manifest.anchor_block_hash = metadata.block_hash().to_string();
        assert!(matches!(
            state
                .wallet()
                .db()
                .enhance_pir_snapshot_status(snapshot_anchor(&manifest).unwrap()),
            Ok(EnhancePirSnapshotStatus::Mismatch)
        ));
        assert_eq!(
            snapshot_anchor(&manifest).unwrap().block_hash,
            metadata.block_hash()
        );
        assert_eq!(
            snapshot_anchor(&manifest).unwrap().ironwood_tree_size,
            manifest.coverage.records
        );
        let mut actual = snapshot_anchor(&manifest).unwrap();
        actual.ironwood_tree_size = u64::from(metadata.ironwood_tree_size().unwrap());
        assert!(matches!(
            state.wallet().db().enhance_pir_snapshot_status(actual),
            Ok(EnhancePirSnapshotStatus::Accepted)
        ));
        // The v4 wire contract is mainnet-only, so a local test network cannot
        // accept even an anchor that its database recognizes.
        assert!(
            acceptance(
                state.wallet().db(),
                &manifest,
                &network,
                ClientResourceLimits::new(65_536)
            )
            .unwrap()
            .is_err()
        );
        let disabled = LocalNetwork {
            nu6_3: None,
            ..network
        };
        assert!(
            acceptance(
                state.wallet().db(),
                &manifest,
                &disabled,
                ClientResourceLimits::new(65_536)
            )
            .unwrap()
            .is_err()
        );
        manifest.anchor_block_hash = "01".repeat(32);
        assert!(matches!(
            state
                .wallet()
                .db()
                .enhance_pir_snapshot_status(snapshot_anchor(&manifest).unwrap()),
            Ok(EnhancePirSnapshotStatus::Mismatch)
        ));
        manifest.coverage.records = 0;
        assert!(matches!(
            snapshot_anchor(&manifest),
            Err(ClientError::Generation(_))
        ));
    }
}
