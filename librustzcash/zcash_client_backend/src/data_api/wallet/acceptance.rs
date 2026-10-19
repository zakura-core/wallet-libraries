//! Wallet policy for accepting a transaction for sending at a candidate block height.
//!
//! The same rules apply to a finished [`Transaction`] and to a PCZT before its proofs and
//! signatures are finalized, so that a PCZT can be refused before any expensive work.

use std::io::Cursor;

use zcash_primitives::transaction::{Transaction, TxVersion, builder::check_shielded_budget};
use zcash_protocol::consensus::{self, BlockHeight, BranchId};

use crate::data_api::error::AcceptanceError;

/// The fields of a transaction that the acceptance policy reads.
struct Candidate {
    declared_branch: u32,
    version: Option<TxVersion>,
    version_header: u32,
    expiry_height: u32,
    sapling_spends: usize,
    sapling_outputs: usize,
    orchard_actions: usize,
    ironwood_actions: usize,
}

fn check(
    params: &impl consensus::Parameters,
    target_height: BlockHeight,
    candidate: Candidate,
) -> Result<(), AcceptanceError> {
    let current = BranchId::for_height(params, target_height);
    if candidate.declared_branch != u32::from(current) {
        return Err(AcceptanceError::ObsoleteConsensusBranch {
            declared: candidate.declared_branch,
            current,
        });
    }
    if !candidate
        .version
        .is_some_and(|version| version.valid_in_branch(current))
    {
        return Err(AcceptanceError::UnsupportedVersion {
            version: candidate.version_header & 0x7FFF_FFFF,
            current,
        });
    }
    let expiry_height = BlockHeight::from_u32(candidate.expiry_height);
    if expiry_height != consensus::H0 && expiry_height < target_height {
        return Err(AcceptanceError::Expired {
            expiry_height,
            target_height,
        });
    }
    check_shielded_budget(
        params,
        target_height,
        candidate.sapling_spends,
        candidate.sapling_outputs,
        candidate.orchard_actions,
        candidate.ironwood_actions,
    )
    .map_err(AcceptanceError::ShieldedBudget)
}

/// Checks whether this wallet may send a finished transaction for inclusion at
/// `target_height`.
///
/// `params` must identify the wallet's network, and `target_height` should be one more than
/// a freshly synchronized chain tip; a stale local tip cannot detect a network upgrade it has
/// not learned about. The transaction is acceptable when it commits to the consensus branch
/// active at `target_height`, uses a transaction version valid in that branch, has an expiry
/// height of zero (no expiry) or at least `target_height`, and its shielded bundles fit the
/// NU7 per-pool and combined block budgets when NU7 is active at `target_height`.
///
/// This is a wallet sending policy, not consensus validation. It does not check that the
/// candidate height is current on the network, that proofs or signatures are valid, that the
/// inputs exist and are unspent, or any other consensus rule. Recheck against a fresh chain
/// tip immediately before broadcast.
pub fn validate_transaction_for_target(
    params: &impl consensus::Parameters,
    target_height: BlockHeight,
    transaction: &Transaction,
) -> Result<(), AcceptanceError> {
    let version = transaction.version();
    check(
        params,
        target_height,
        Candidate {
            declared_branch: u32::from(transaction.consensus_branch_id()),
            version: Some(version),
            version_header: version.header(),
            expiry_height: u32::from(transaction.expiry_height()),
            sapling_spends: transaction
                .sapling_bundle()
                .map_or(0, |b| b.shielded_spends().len()),
            sapling_outputs: transaction
                .sapling_bundle()
                .map_or(0, |b| b.shielded_outputs().len()),
            orchard_actions: transaction
                .orchard_bundle()
                .map_or(0, |b| b.actions().len()),
            ironwood_actions: transaction
                .ironwood_bundle()
                .map_or(0, |b| b.actions().len()),
        },
    )
}

/// Applies the [`validate_transaction_for_target`] policy to a PCZT, so that a stale or
/// oversized PCZT is refused before its proofs and signatures are finalized.
///
/// The same limits apply: this does not check proofs, signatures, input availability or
/// network freshness. Its bundle counts are the PCZT's final, padded counts.
#[cfg(feature = "pczt")]
pub fn validate_pczt_for_target(
    params: &impl consensus::Parameters,
    target_height: BlockHeight,
    pczt: &pczt::Pczt,
) -> Result<(), AcceptanceError> {
    let global = pczt.global();
    // PCZTs only represent overwintered transaction formats.
    let version_header = *global.tx_version() | (1 << 31);
    let mut encoded = Vec::with_capacity(8);
    encoded.extend_from_slice(&version_header.to_le_bytes());
    encoded.extend_from_slice(&global.version_group_id().to_le_bytes());
    check(
        params,
        target_height,
        Candidate {
            declared_branch: *global.consensus_branch_id(),
            version: TxVersion::read(Cursor::new(encoded)).ok(),
            version_header,
            expiry_height: *global.expiry_height(),
            sapling_spends: pczt.sapling().spends().len(),
            sapling_outputs: pczt.sapling().outputs().len(),
            orchard_actions: pczt.orchard().actions().len(),
            ironwood_actions: pczt.ironwood().actions().len(),
        },
    )
}

#[cfg(test)]
mod tests {
    use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion};
    use zcash_protocol::consensus::{
        BlockHeight, BranchId, NU7_GLOBAL_SHIELDED_BUDGET, NU7_ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT,
        NU7_SAPLING_BLOCK_IO_LIMIT, NetworkUpgrade, Parameters, TEST_NETWORK,
    };

    use super::{Candidate, check, validate_transaction_for_target};
    use crate::data_api::error::AcceptanceError;

    fn finished(version: TxVersion, branch: BranchId, expiry_height: BlockHeight) -> Transaction {
        TransactionData::<Authorized>::from_parts(
            version,
            branch,
            0,
            expiry_height,
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap()
    }

    fn nu7_activation() -> BlockHeight {
        TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap()
    }

    #[test]
    fn finished_transaction_is_accepted_through_its_expiry_height() {
        let activation = nu7_activation();
        let tx = finished(TxVersion::V6, BranchId::Nu7, activation + 120);
        for target in [activation, activation + 120] {
            assert_eq!(
                validate_transaction_for_target(&TEST_NETWORK, target, &tx),
                Ok(())
            );
        }
        assert_eq!(
            validate_transaction_for_target(&TEST_NETWORK, activation + 121, &tx),
            Err(AcceptanceError::Expired {
                expiry_height: activation + 120,
                target_height: activation + 121,
            })
        );
    }

    #[test]
    fn finished_transaction_with_zero_expiry_never_expires() {
        let activation = nu7_activation();
        let tx = finished(TxVersion::V6, BranchId::Nu7, BlockHeight::from_u32(0));
        assert_eq!(
            validate_transaction_for_target(&TEST_NETWORK, activation + 100_000, &tx),
            Ok(())
        );
    }

    #[test]
    fn finished_transaction_signed_for_the_previous_branch_is_refused() {
        let activation = nu7_activation();
        let tx = finished(TxVersion::V6, BranchId::Nu6_3, activation + 40);
        assert_eq!(
            validate_transaction_for_target(&TEST_NETWORK, activation - 1, &tx),
            Ok(())
        );
        assert_eq!(
            validate_transaction_for_target(&TEST_NETWORK, activation, &tx),
            Err(AcceptanceError::ObsoleteConsensusBranch {
                declared: u32::from(BranchId::Nu6_3),
                current: BranchId::Nu7,
            })
        );
    }

    #[test]
    fn finished_version_4_transaction_is_refused_once_nu7_is_active() {
        let activation = nu7_activation();
        let tx = finished(TxVersion::V4, BranchId::Nu7, activation + 120);
        assert_eq!(
            validate_transaction_for_target(&TEST_NETWORK, activation, &tx),
            Err(AcceptanceError::UnsupportedVersion {
                version: 4,
                current: BranchId::Nu7,
            })
        );
    }

    #[test]
    fn padded_counts_are_refused_only_above_the_combined_budget() {
        let activation = nu7_activation();
        // Fill every pool within its own limit, so only the combined budget can refuse.
        let candidate = |extra: usize| {
            let sapling = NU7_SAPLING_BLOCK_IO_LIMIT.min(NU7_GLOBAL_SHIELDED_BUDGET);
            let remaining = NU7_GLOBAL_SHIELDED_BUDGET - sapling + extra;
            let orchard = remaining.min(NU7_ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT);
            let ironwood = remaining - orchard;
            assert!(ironwood <= NU7_ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT);
            Candidate {
                declared_branch: u32::from(BranchId::Nu7),
                version: Some(TxVersion::V6),
                version_header: TxVersion::V6.header(),
                expiry_height: 0,
                sapling_spends: sapling / 2,
                sapling_outputs: sapling - sapling / 2,
                orchard_actions: orchard,
                ironwood_actions: ironwood,
            }
        };
        assert_eq!(check(&TEST_NETWORK, activation, candidate(0)), Ok(()));
        assert!(matches!(
            check(&TEST_NETWORK, activation, candidate(1)),
            Err(AcceptanceError::ShieldedBudget(_))
        ));
        // Before NU7 the budget does not apply.
        let mut before = candidate(1);
        before.declared_branch = u32::from(BranchId::Nu6_3);
        assert_eq!(check(&TEST_NETWORK, activation - 1, before), Ok(()));
    }
}
