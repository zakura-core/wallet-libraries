//! Synchronous wallet acceptance and identity capture. No network I/O or writes.
use crate::{
    AcceptedAnchor, ClientError, ClientResourceLimits, EnhanceGeneration, EnhanceRecord,
    GenerationAcceptance,
};
use std::collections::BTreeMap;
use zcash_client_backend::data_api::enhance_pir::{
    EnhancePirRead, EnhancePirRequest, EnhancePirSnapshotAnchor, EnhancePirSnapshotStatus,
    EnhancePirWork,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};

pub enum Acceptance {
    Accepted(GenerationAcceptance),
    WaitingForScanning,
    Mismatch,
}

pub fn snapshot_anchor(
    generation: &EnhanceGeneration,
) -> Result<EnhancePirSnapshotAnchor, ClientError> {
    let height = u32::try_from(generation.anchor_height)
        .map_err(|_| ClientError::Generation("anchor height exceeds wallet range".into()))?;
    let mut hash: [u8; 32] = hex::decode(&generation.anchor_block_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ClientError::Generation("invalid anchor block hash".into()))?;
    hash.reverse();
    Ok(EnhancePirSnapshotAnchor {
        height: BlockHeight::from(height),
        block_hash: BlockHash::from_slice(&hash),
        ironwood_tree_size: generation.ironwood_tree_size,
    })
}

/// Checks locally scanned state before creating client acceptance. Storage
/// errors are returned separately from protocol errors; neither permits setup.
/// Network and NU6.3 activation come from the wallet's trusted consensus
/// parameters, never from the advertised generation. An unscheduled activation
/// rejects the generation. Pass the same parameters used to open/scan the wallet.
pub fn acceptance<D: EnhancePirRead>(
    db: &D,
    generation: &EnhanceGeneration,
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
    let anchor = match snapshot_anchor(generation) {
        Ok(a) => a,
        Err(e) => return Ok(Err(e)),
    };
    let mut display_hash = anchor.block_hash.0;
    display_hash.reverse();
    let accepted = GenerationAcceptance::new(
        network,
        activation_height,
        AcceptedAnchor::new(
            generation.anchor_height,
            display_hash,
            generation.ironwood_tree_size,
        ),
        limits,
    );
    if let Err(e) = accepted.validate(generation) {
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
    use crate::*;
    use zcash_client_backend::data_api::{WalletRead, testing::TestBuilder};
    use zcash_client_sqlite::testing::{BlockCache, db::TestDbFactory};
    use zcash_protocol::local_consensus::LocalNetwork;
    #[test]
    fn wallet_scanning_and_hash_agreement_gate_acceptance() {
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
        let mut generation = EnhanceGeneration {
            schema_version: SCHEMA_VERSION,
            protocol_revision: PROTOCOL_REVISION.into(),
            network: "regtest".into(),
            pool: POOL.into(),
            anchor_height: u64::from(u32::from(height)),
            anchor_block_hash: "00".repeat(32),
            ironwood_tree_size: 0,
            generation: 1,
            record_bytes: RECORD_BYTES as u32,
            records_per_row: RECORDS_PER_ROW as u32,
            row_bytes: ROW_BYTES as u32,
            shard_rows: SHARD_ROWS as u32,
            used_rows: 0,
            logical_rows: checked_logical_rows_for(0).unwrap(),
            parameter_id: "fixture".into(),
            setup_seed: ENHANCE_SETUP_SEED,
            public_params_epoch: "00".repeat(8),
            public_params_sha256: "00".repeat(32),
            shards: vec![],
        };
        let check = |generation: &EnhanceGeneration, db: &_| {
            acceptance(db, generation, &network, ClientResourceLimits::new(65_536))
                .unwrap()
                .unwrap()
        };
        assert!(matches!(
            check(&generation, state.wallet().db()),
            Acceptance::WaitingForScanning
        ));
        state.scan_cached_blocks(height, 1);
        let metadata = state.wallet().db().block_metadata(height).unwrap().unwrap();
        generation.anchor_block_hash = metadata.block_hash().to_string();
        generation.ironwood_tree_size = u64::from(metadata.ironwood_tree_size().unwrap());
        assert!(matches!(
            check(&generation, state.wallet().db()),
            Acceptance::Accepted(_)
        ));
        assert_eq!(
            snapshot_anchor(&generation).unwrap().block_hash,
            metadata.block_hash()
        );
        // These advertised policies cannot be made self-approving, even though
        // the database accepts this exact block anchor and tree size.
        let accepted_generation = generation.clone();
        generation.network = "main".into();
        assert!(
            acceptance(
                state.wallet().db(),
                &generation,
                &network,
                ClientResourceLimits::new(65_536)
            )
            .unwrap()
            .is_err()
        );
        generation = accepted_generation.clone();
        let future_activation = LocalNetwork {
            nu6_3: Some(height + 1),
            ..network
        };
        assert!(
            acceptance(
                state.wallet().db(),
                &generation,
                &future_activation,
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
                &generation,
                &disabled,
                ClientResourceLimits::new(65_536)
            )
            .unwrap()
            .is_err()
        );
        let at_anchor = LocalNetwork {
            nu6_3: Some(height),
            ..network
        };
        assert!(matches!(
            acceptance(
                state.wallet().db(),
                &generation,
                &at_anchor,
                ClientResourceLimits::new(65_536)
            )
            .unwrap()
            .unwrap(),
            Acceptance::Accepted(_)
        ));
        generation.anchor_block_hash = "01".repeat(32);
        assert!(matches!(
            check(&generation, state.wallet().db()),
            Acceptance::Mismatch
        ));
    }
}
