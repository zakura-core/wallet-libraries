use std::{collections::HashSet, convert::TryFrom, hash::Hash};

use incrementalmerkletree::Retention;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain};
use subtle::ConditionallySelectable;

use tracing::{debug, trace};
use zcash_note_encryption::batch;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight, NetworkUpgrade, TxIndex},
};

use super::{Nullifiers, PositionTracker, ScanError, ScanningKeys, find_received, find_spent};
use crate::{
    data_api::{BlockMetadata, ScannedBlock, ScannedBundles},
    proto::compact_formats::{ChainMetadata, CompactBlock, CompactTx},
    scan::{Batch, BatchRunner, CompactDecryptor, Tasks},
    wallet::{WalletSpend, WalletTx},
};

#[cfg(feature = "orchard")]
use {
    super::IronwoodDomain,
    orchard::{
        note_encryption::{CompactAction, OrchardDomain},
        tree::MerkleHashOrchard,
    },
};

#[cfg(not(feature = "orchard"))]
use std::marker::PhantomData;

#[cfg(feature = "zakura-pir-enhance")]
use crate::data_api::enhance_pir::is_ironwood_pir_candidate;

type TaggedSaplingBatch<IvkTag> = Batch<
    IvkTag,
    SaplingDomain,
    sapling::note_encryption::CompactOutputDescription,
    CompactDecryptor,
>;
type TaggedSaplingBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    SaplingDomain,
    sapling::note_encryption::CompactOutputDescription,
    CompactDecryptor,
    Tasks,
>;

#[cfg(feature = "orchard")]
type TaggedOrchardBatch<IvkTag> =
    Batch<IvkTag, OrchardDomain, orchard::note_encryption::CompactAction, CompactDecryptor>;
#[cfg(feature = "orchard")]
type TaggedOrchardBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    OrchardDomain,
    orchard::note_encryption::CompactAction,
    CompactDecryptor,
    Tasks,
>;

// Ironwood outputs are decrypted under the Ironwood note-encryption domain, which is distinct from
// the Orchard domain (it accepts version 3 note plaintexts), so an Ironwood batch is a distinct
// type from an Orchard batch and requires its own task type.
#[cfg(feature = "orchard")]
type TaggedIronwoodBatch<IvkTag> =
    Batch<IvkTag, IronwoodDomain, orchard::note_encryption::CompactAction, CompactDecryptor>;
#[cfg(feature = "orchard")]
type TaggedIronwoodBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    IronwoodDomain,
    orchard::note_encryption::CompactAction,
    CompactDecryptor,
    Tasks,
>;

pub(crate) trait SaplingTasks<IvkTag>: Tasks<TaggedSaplingBatch<IvkTag>> {}
impl<IvkTag, T: Tasks<TaggedSaplingBatch<IvkTag>>> SaplingTasks<IvkTag> for T {}

#[cfg(not(feature = "orchard"))]
pub(crate) trait OrchardTasks<IvkTag> {}
#[cfg(not(feature = "orchard"))]
impl<IvkTag, T> OrchardTasks<IvkTag> for T {}

#[cfg(feature = "orchard")]
pub(crate) trait OrchardTasks<IvkTag>: Tasks<TaggedOrchardBatch<IvkTag>> {}
#[cfg(feature = "orchard")]
impl<IvkTag, T: Tasks<TaggedOrchardBatch<IvkTag>>> OrchardTasks<IvkTag> for T {}

#[cfg(not(feature = "orchard"))]
pub(crate) trait IronwoodTasks<IvkTag> {}
#[cfg(not(feature = "orchard"))]
impl<IvkTag, T> IronwoodTasks<IvkTag> for T {}

#[cfg(feature = "orchard")]
pub(crate) trait IronwoodTasks<IvkTag>: Tasks<TaggedIronwoodBatch<IvkTag>> {}
#[cfg(feature = "orchard")]
impl<IvkTag, T: Tasks<TaggedIronwoodBatch<IvkTag>>> IronwoodTasks<IvkTag> for T {}

pub(crate) struct BatchRunners<
    IvkTag,
    TS: SaplingTasks<IvkTag>,
    TO: OrchardTasks<IvkTag>,
    TI: IronwoodTasks<IvkTag>,
> {
    sapling: TaggedSaplingBatchRunner<IvkTag, TS>,
    #[cfg(feature = "orchard")]
    orchard: TaggedOrchardBatchRunner<IvkTag, TO>,
    #[cfg(feature = "orchard")]
    ironwood: TaggedIronwoodBatchRunner<IvkTag, TI>,
    #[cfg(not(feature = "orchard"))]
    orchard: PhantomData<(TO, TI)>,
}

impl<IvkTag, TS, TO, TI> BatchRunners<IvkTag, TS, TO, TI>
where
    IvkTag: Clone + Send + 'static,
    TS: SaplingTasks<IvkTag>,
    TO: OrchardTasks<IvkTag>,
    TI: IronwoodTasks<IvkTag>,
{
    pub(crate) fn for_keys<AccountId>(
        batch_size_threshold: usize,
        scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    ) -> Self {
        BatchRunners {
            sapling: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .sapling()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(feature = "orchard")]
            orchard: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .orchard()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(feature = "orchard")]
            ironwood: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .ironwood()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(not(feature = "orchard"))]
            orchard: PhantomData,
        }
    }

    pub(crate) fn flush(&mut self) {
        self.sapling.flush();
        #[cfg(feature = "orchard")]
        self.orchard.flush();
        #[cfg(feature = "orchard")]
        self.ironwood.flush();
    }

    #[tracing::instrument(skip_all, fields(height = block.height))]
    pub(crate) fn add_block<P>(&mut self, params: &P, block: CompactBlock) -> Result<(), ScanError>
    where
        P: consensus::Parameters + Send + 'static,
        IvkTag: Copy + Send + 'static,
    {
        let block_hash = block.hash();
        let block_height = block.height();
        let zip212_enforcement = zip212_enforcement(params, block_height);

        for tx in block.vtx.into_iter() {
            let txid = tx.txid();

            self.sapling.add_outputs(
                block_hash,
                txid,
                |_| SaplingDomain::new(zip212_enforcement),
                tx.outputs
                    .iter()
                    .enumerate()
                    .map(|(i, output)| {
                        CompactOutputDescription::try_from(output).map_err(|_| {
                            ScanError::EncodingInvalid {
                                at_height: block_height,
                                txid,
                                pool_type: ShieldedPool::Sapling,
                                index: i,
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            #[cfg(feature = "orchard")]
            self.orchard.add_outputs(
                block_hash,
                txid,
                OrchardDomain::for_compact_action,
                tx.actions
                    .iter()
                    .enumerate()
                    .map(|(i, action)| {
                        CompactAction::try_from(action).map_err(|_| ScanError::EncodingInvalid {
                            at_height: block_height,
                            txid,
                            pool_type: ShieldedPool::Orchard,
                            index: i,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            #[cfg(feature = "orchard")]
            self.ironwood.add_outputs(
                block_hash,
                txid,
                IronwoodDomain::for_compact_action,
                tx.ironwood_actions
                    .iter()
                    .enumerate()
                    .map(|(i, action)| {
                        CompactAction::try_from(action).map_err(|_| ScanError::EncodingInvalid {
                            at_height: block_height,
                            txid,
                            pool_type: ShieldedPool::Ironwood,
                            index: i,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        Ok(())
    }
}

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn scan_block_with_runners<P, AccountId, IvkTag, TS, TO, TI>(
    params: &P,
    block: CompactBlock,
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    nullifiers: &Nullifiers<AccountId>,
    prior_block_metadata: Option<&BlockMetadata>,
    mut batch_runners: Option<&mut BatchRunners<IvkTag, TS, TO, TI>>,
) -> Result<ScannedBlock<AccountId>, ScanError>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + Eq + Hash + ConditionallySelectable + Send + Sync + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
    TS: SaplingTasks<IvkTag> + Sync,
    TO: OrchardTasks<IvkTag> + Sync,
    TI: IronwoodTasks<IvkTag> + Sync,
{
    fn check_hash_continuity(
        block: &CompactBlock,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Option<ScanError> {
        if let Some(prev) = prior_block_metadata {
            if block.height() != prev.block_height() + 1 {
                debug!(
                    "Block height discontinuity at {:?}, previous was {:?} ",
                    block.height(),
                    prev.block_height()
                );
                return Some(ScanError::BlockHeightDiscontinuity {
                    prev_height: prev.block_height(),
                    new_height: block.height(),
                });
            }

            if block.prev_hash() != prev.block_hash() {
                debug!("Block hash discontinuity at {:?}", block.height());
                return Some(ScanError::PrevHashMismatch {
                    at_height: block.height(),
                });
            }
        }

        None
    }

    if let Some(scan_error) = check_hash_continuity(&block, prior_block_metadata) {
        return Err(scan_error);
    }

    trace!("Block continuity okay at {:?}", block.height());

    let cur_height = block.height();
    let cur_hash = block.hash();
    let zip212_enforcement = zip212_enforcement(params, cur_height);

    let mut pos_tracker = PositionTracker::for_compact_block(params, &block, prior_block_metadata)?;

    let mut wtxs: Vec<WalletTx<AccountId>> = vec![];

    let mut sapling_nullifier_map = Vec::with_capacity(block.vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];

    #[cfg(feature = "orchard")]
    let mut orchard_nullifier_map = Vec::with_capacity(block.vtx.len());
    #[cfg(feature = "orchard")]
    let mut orchard_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];

    #[cfg(feature = "orchard")]
    let mut ironwood_nullifier_map = Vec::with_capacity(block.vtx.len());
    #[cfg(feature = "orchard")]
    let mut ironwood_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];

    for tx in block.vtx.into_iter() {
        let txid = tx.txid();
        let tx_index =
            TxIndex::try_from(tx.index).expect("Cannot fit more than 2^16 transactions in a block");

        // A compact spend carries its nullifier as raw bytes; validate them up front so that a
        // malformed (wrong-length) nullifier from an untrusted server yields a handleable
        // `ScanError` rather than panicking the scanner.
        let sapling_spend_nfs = tx
            .spends
            .iter()
            .enumerate()
            .map(|(index, spend)| {
                spend.nf().map_err(|_| ScanError::EncodingInvalid {
                    at_height: cur_height,
                    txid,
                    pool_type: ShieldedPool::Sapling,
                    index,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (sapling_spends, sapling_unlinked_nullifiers) = find_spent(
            &sapling_spend_nfs,
            &nullifiers.sapling,
            |nf| *nf,
            WalletSpend::from_parts,
        );

        sapling_nullifier_map.push((tx_index, txid, sapling_unlinked_nullifiers));

        #[cfg(feature = "orchard")]
        let orchard_spends = {
            let orchard_spend_nfs = tx
                .actions
                .iter()
                .enumerate()
                .map(|(index, spend)| {
                    spend.nf().map_err(|_| ScanError::EncodingInvalid {
                        at_height: cur_height,
                        txid,
                        pool_type: ShieldedPool::Orchard,
                        index,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (orchard_spends, orchard_unlinked_nullifiers) = find_spent(
                &orchard_spend_nfs,
                &nullifiers.orchard,
                |nf| *nf,
                WalletSpend::from_parts,
            );
            orchard_nullifier_map.push((tx_index, txid, orchard_unlinked_nullifiers));
            orchard_spends
        };

        #[cfg(feature = "orchard")]
        let ironwood_spends = {
            let ironwood_spend_nfs = tx
                .ironwood_actions
                .iter()
                .enumerate()
                .map(|(index, spend)| {
                    spend.nf().map_err(|_| ScanError::EncodingInvalid {
                        at_height: cur_height,
                        txid,
                        pool_type: ShieldedPool::Ironwood,
                        index,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (ironwood_spends, ironwood_unlinked_nullifiers) = find_spent(
                &ironwood_spend_nfs,
                &nullifiers.ironwood,
                |nf| *nf,
                WalletSpend::from_parts,
            );
            ironwood_nullifier_map.push((tx_index, txid, ironwood_unlinked_nullifiers));
            ironwood_spends
        };

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts = sapling_spends.iter().map(|spend| spend.account_id());
        #[cfg(feature = "orchard")]
        let spent_from_accounts =
            spent_from_accounts.chain(orchard_spends.iter().map(|spend| spend.account_id()));
        #[cfg(feature = "orchard")]
        let spent_from_accounts =
            spent_from_accounts.chain(ironwood_spends.iter().map(|spend| spend.account_id()));
        let spent_from_accounts = spent_from_accounts.copied().collect::<HashSet<_>>();

        #[cfg(feature = "zakura-pir-enhance")]
        // Explicit non-Ironwood fields require LWD. Empty transparent lists are
        // only provisional: schema-v6 PIR flags may reveal an omitted bundle.
        // The compact source must include every shielded pool, not filter to Ironwood.
        let ironwood_pir_eligible = is_ironwood_pir_candidate(&tx);
        let (sapling_outputs, mut sapling_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_sapling_outputs_in_block(&tx),
            txid,
            |output_idx| pos_tracker.sapling_note_position(output_idx),
            &scanning_keys.sapling,
            &spent_from_accounts,
            &tx.outputs
                .iter()
                .enumerate()
                .map(|(i, output)| {
                    Ok((
                        SaplingDomain::new(zip212_enforcement),
                        CompactOutputDescription::try_from(output).map_err(|_| {
                            ScanError::EncodingInvalid {
                                at_height: cur_height,
                                txid,
                                pool_type: ShieldedPool::Sapling,
                                index: i,
                            }
                        })?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.sapling.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| sapling::Node::from_cmu(&output.cmu),
            |note| note,
        );
        sapling_note_commitments.append(&mut sapling_nc);
        let has_sapling = !(sapling_spends.is_empty() && sapling_outputs.is_empty());

        #[cfg(feature = "orchard")]
        let (orchard_outputs, mut orchard_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_orchard_actions_in_block(&tx),
            txid,
            |output_idx| pos_tracker.orchard_note_position(output_idx),
            &scanning_keys.orchard,
            &spent_from_accounts,
            &tx.actions
                .iter()
                .enumerate()
                .map(|(i, action)| {
                    let action = CompactAction::try_from(action).map_err(|_| {
                        ScanError::EncodingInvalid {
                            at_height: cur_height,
                            txid,
                            pool_type: ShieldedPool::Orchard,
                            index: i,
                        }
                    })?;
                    Ok((OrchardDomain::for_compact_action(&action), action))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.orchard.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| MerkleHashOrchard::from_cmx(&output.cmx()),
            |note| (note, orchard::ValuePool::Orchard),
        );
        #[cfg(feature = "orchard")]
        orchard_note_commitments.append(&mut orchard_nc);

        #[cfg(feature = "orchard")]
        let (ironwood_outputs, mut ironwood_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_ironwood_actions_in_block(&tx),
            txid,
            |output_idx| pos_tracker.ironwood_note_position(output_idx),
            &scanning_keys.ironwood,
            &spent_from_accounts,
            &tx.ironwood_actions
                .iter()
                .enumerate()
                .map(|(i, action)| {
                    let action = CompactAction::try_from(action).map_err(|_| {
                        ScanError::EncodingInvalid {
                            at_height: cur_height,
                            txid,
                            pool_type: ShieldedPool::Ironwood,
                            index: i,
                        }
                    })?;
                    Ok((IronwoodDomain::for_compact_action(&action), action))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.ironwood.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| MerkleHashOrchard::from_cmx(&output.cmx()),
            |note| (note, orchard::ValuePool::Ironwood),
        );
        #[cfg(feature = "orchard")]
        ironwood_note_commitments.append(&mut ironwood_nc);

        // Actions the wallet decrypted for itself — including change, which compact scanning
        // finds because `ScanningKeys` covers the internal scope as well as the external one.
        // These are served by the incoming memo queue, so they must not also become outgoing
        // candidates: change is encrypted under the internal OVK and outgoing recovery only
        // holds the external one, so an outgoing entry for such a position could never be
        // resolved. It would keep its transaction protected, and therefore un-enhanced, forever.
        #[cfg(feature = "zakura-pir-enhance")]
        let ironwood_enhance_candidates = if spent_from_accounts.is_empty()
            || !ironwood_pir_eligible
        {
            vec![]
        } else {
            let received_indices = ironwood_outputs
                .iter()
                .map(|output| output.index())
                .collect::<HashSet<_>>();
            tx.ironwood_actions
                .iter()
                .enumerate()
                .filter(|(index, _)| !received_indices.contains(index))
                .map(|(index, raw)| {
                    let action =
                        CompactAction::try_from(raw).map_err(|_| ScanError::EncodingInvalid {
                            at_height: cur_height,
                            txid,
                            pool_type: ShieldedPool::Ironwood,
                            index,
                        })?;
                    Ok(crate::wallet::IronwoodEnhanceCandidate::from_parts(
                        pos_tracker.ironwood_note_position(index),
                        index,
                        action.nullifier().to_bytes(),
                        action.cmx().to_bytes(),
                        raw.ephemeral_key
                            .as_slice()
                            .try_into()
                            .expect("CompactAction validation enforces ephemeral-key length"),
                        raw.ciphertext
                            .as_slice()
                            .try_into()
                            .expect("CompactAction validation enforces ciphertext length"),
                        spent_from_accounts.iter().copied().collect(),
                    ))
                })
                .collect::<Result<Vec<_>, ScanError>>()?
        };

        #[cfg(feature = "orchard")]
        let has_orchard = !(orchard_spends.is_empty() && orchard_outputs.is_empty());
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;

        #[cfg(feature = "orchard")]
        let has_ironwood = !(ironwood_spends.is_empty() && ironwood_outputs.is_empty());
        #[cfg(not(feature = "orchard"))]
        let has_ironwood = false;

        if has_sapling || has_orchard || has_ironwood {
            let wallet_tx = WalletTx::new(
                txid,
                tx_index,
                // TODO: Scan transparent data in CompactTx if present.
                // https://github.com/zcash/librustzcash/issues/2187
                vec![],
                sapling_spends,
                sapling_outputs,
                #[cfg(feature = "orchard")]
                orchard_spends,
                #[cfg(feature = "orchard")]
                orchard_outputs,
                #[cfg(feature = "orchard")]
                ironwood_spends,
                #[cfg(feature = "orchard")]
                ironwood_outputs,
            );
            #[cfg(feature = "zakura-pir-enhance")]
            let wallet_tx = wallet_tx.with_ironwood_enhance_candidates(
                ironwood_enhance_candidates,
                ironwood_pir_eligible,
            );
            wtxs.push(wallet_tx);
        }

        pos_tracker.increment_over_compact_tx(&tx);
    }

    pos_tracker.check_end_of_compact_block_consistency(cur_height, block.chain_metadata)?;

    Ok(ScannedBlock::from_parts(
        cur_height,
        cur_hash,
        block.time,
        wtxs,
        ScannedBundles::new(
            pos_tracker.sapling_final_tree_size,
            sapling_note_commitments,
            sapling_nullifier_map,
        ),
        #[cfg(feature = "orchard")]
        ScannedBundles::new(
            pos_tracker.orchard_final_tree_size,
            orchard_note_commitments,
            orchard_nullifier_map,
        ),
        #[cfg(feature = "orchard")]
        ScannedBundles::new(
            pos_tracker.ironwood_final_tree_size,
            ironwood_note_commitments,
            ironwood_nullifier_map,
        ),
    ))
}

impl PositionTracker {
    fn for_compact_block<P>(
        params: &P,
        block: &CompactBlock,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Result<Self, ScanError>
    where
        P: consensus::Parameters,
    {
        /// Returns the size of the given shielded protocol's note commitment tree before and
        /// after the application of the given block.
        #[allow(clippy::too_many_arguments)]
        fn tree_sizes_around<P>(
            params: &P,
            block: &CompactBlock,
            prior_block_metadata: Option<&BlockMetadata>,
            protocol: ShieldedPool,
            activation_nu: NetworkUpgrade,
            prior_tree_size: impl Fn(&BlockMetadata) -> Option<u32>,
            tx_output_count: impl Fn(&CompactTx) -> usize,
            final_tree_size: impl Fn(&ChainMetadata) -> u32,
        ) -> Result<(u32, u32), ScanError>
        where
            P: consensus::Parameters,
        {
            let at_height = block.height();

            let start_tree_size = prior_block_metadata.and_then(prior_tree_size).map_or_else(
                || {
                    block.chain_metadata.as_ref().map_or_else(
                        || {
                            // If we're below the protocol's activation height, or it is
                            // not set, the tree size is zero.
                            params.activation_height(activation_nu).map_or_else(
                                || Ok(0),
                                |activation_height| {
                                    if at_height < activation_height {
                                        Ok(0)
                                    } else {
                                        Err(ScanError::TreeSizeUnknown {
                                            protocol,
                                            at_height,
                                        })
                                    }
                                },
                            )
                        },
                        |m| {
                            let output_count: u32 = block
                                .vtx
                                .iter()
                                .map(&tx_output_count)
                                .sum::<usize>()
                                .try_into()
                                .expect("Shielded output count cannot exceed a u32");

                            // The default for `final_tree_size(m)` is zero, so we need to
                            // check that the subtraction will not underflow; if it would
                            // do so, we were given invalid chain metadata for a block
                            // with outputs in this shielded protocol.
                            final_tree_size(m).checked_sub(output_count).ok_or(
                                ScanError::TreeSizeInvalid {
                                    protocol,
                                    at_height,
                                },
                            )
                        },
                    )
                },
                Ok,
            )?;

            // We pre-compute the end tree size here so we can determine when we reach the
            // last transaction in the block that adds notes to the tree. This enables us
            // to correctly set the tree checkpoint in `find_received`.
            let end_tree_size = start_tree_size
                + block
                    .vtx
                    .iter()
                    .map(tx_output_count)
                    .map(|tx_outputs| u32::try_from(tx_outputs).unwrap())
                    .sum::<u32>();

            Ok((start_tree_size, end_tree_size))
        }

        let (sapling_prior_tree_size, sapling_final_tree_size) = tree_sizes_around(
            params,
            block,
            prior_block_metadata,
            ShieldedPool::Sapling,
            NetworkUpgrade::Sapling,
            |m| m.sapling_tree_size(),
            |tx| tx.outputs.len(),
            |m| m.sapling_commitment_tree_size,
        )?;

        #[cfg(feature = "orchard")]
        let (orchard_prior_tree_size, orchard_final_tree_size) = tree_sizes_around(
            params,
            block,
            prior_block_metadata,
            ShieldedPool::Orchard,
            NetworkUpgrade::Nu5,
            |m| m.orchard_tree_size(),
            |tx| tx.actions.len(),
            |m| m.orchard_commitment_tree_size,
        )?;

        #[cfg(feature = "orchard")]
        let (ironwood_prior_tree_size, ironwood_final_tree_size) = tree_sizes_around(
            params,
            block,
            prior_block_metadata,
            ShieldedPool::Ironwood,
            NetworkUpgrade::Nu6_3,
            |m| m.ironwood_tree_size(),
            |tx| tx.ironwood_actions.len(),
            |m| m.ironwood_commitment_tree_size,
        )?;

        Ok(Self {
            sapling_tree_position: sapling_prior_tree_size,
            sapling_final_tree_size,
            #[cfg(feature = "orchard")]
            orchard_tree_position: orchard_prior_tree_size,
            #[cfg(feature = "orchard")]
            orchard_final_tree_size,
            #[cfg(feature = "orchard")]
            ironwood_tree_position: ironwood_prior_tree_size,
            #[cfg(feature = "orchard")]
            ironwood_final_tree_size,
        })
    }

    fn compact_tx_contains_last_sapling_outputs_in_block(&self, tx: &CompactTx) -> bool {
        self.sapling_tree_position
            + u32::try_from(tx.outputs.len()).expect("Sapling output count cannot exceed a u32")
            == self.sapling_final_tree_size
    }

    #[cfg(feature = "orchard")]
    fn compact_tx_contains_last_orchard_actions_in_block(&self, tx: &CompactTx) -> bool {
        self.orchard_tree_position
            + u32::try_from(tx.actions.len()).expect("Orchard action count cannot exceed a u32")
            == self.orchard_final_tree_size
    }

    #[cfg(feature = "orchard")]
    fn compact_tx_contains_last_ironwood_actions_in_block(&self, tx: &CompactTx) -> bool {
        self.ironwood_tree_position
            + u32::try_from(tx.ironwood_actions.len())
                .expect("Ironwood action count cannot exceed a u32")
            == self.ironwood_final_tree_size
    }

    fn increment_over_compact_tx(&mut self, tx: &CompactTx) {
        self.sapling_tree_position +=
            u32::try_from(tx.outputs.len()).expect("Sapling output count cannot exceed a u32");
        #[cfg(feature = "orchard")]
        {
            self.orchard_tree_position +=
                u32::try_from(tx.actions.len()).expect("Orchard action count cannot exceed a u32");
            self.ironwood_tree_position += u32::try_from(tx.ironwood_actions.len())
                .expect("Ironwood action count cannot exceed a u32");
        }
    }

    fn check_end_of_compact_block_consistency(
        &self,
        at_height: BlockHeight,
        chain_metadata: Option<ChainMetadata>,
    ) -> Result<(), ScanError> {
        // It is a programming error to construct `PositionTracker` from a `CompactBlock`
        // and then not call `PositionTracker::increment_over_tx` on every transaction
        // within the block.
        assert_eq!(self.sapling_tree_position, self.sapling_final_tree_size);
        #[cfg(feature = "orchard")]
        assert_eq!(self.orchard_tree_position, self.orchard_final_tree_size);
        #[cfg(feature = "orchard")]
        assert_eq!(self.ironwood_tree_position, self.ironwood_final_tree_size);

        if let Some(chain_meta) = chain_metadata {
            if chain_meta.sapling_commitment_tree_size != self.sapling_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    protocol: ShieldedPool::Sapling,
                    at_height,
                    given: chain_meta.sapling_commitment_tree_size,
                    computed: self.sapling_tree_position,
                });
            }

            #[cfg(feature = "orchard")]
            if chain_meta.orchard_commitment_tree_size != self.orchard_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    protocol: ShieldedPool::Orchard,
                    at_height,
                    given: chain_meta.orchard_commitment_tree_size,
                    computed: self.orchard_tree_position,
                });
            }

            #[cfg(feature = "orchard")]
            if chain_meta.ironwood_commitment_tree_size != self.ironwood_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    protocol: ShieldedPool::Ironwood,
                    at_height,
                    given: chain_meta.ironwood_commitment_tree_size,
                    computed: self.ironwood_tree_position,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "zakura-pir-enhance")]
    #[test]
    fn pir_candidate_rejects_every_explicit_non_ironwood_field() {
        use crate::proto::compact_formats::CompactTx;
        let empty = CompactTx::default();
        assert!(!super::is_ironwood_pir_candidate(&empty));
        let pure = CompactTx {
            ironwood_actions: vec![Default::default()],
            ..empty
        };
        assert!(super::is_ironwood_pir_candidate(&pure));
        for field in 0..5 {
            let mut mixed = pure.clone();
            match field {
                0 => mixed.vin.push(Default::default()),
                1 => mixed.vout.push(Default::default()),
                2 => mixed.spends.push(Default::default()),
                3 => mixed.outputs.push(Default::default()),
                4 => mixed.actions.push(Default::default()),
                _ => unreachable!(),
            }
            assert!(!super::is_ironwood_pir_candidate(&mixed), "field {field}");
        }
    }

    use std::convert::Infallible;

    #[cfg(feature = "orchard")]
    use {
        super::ScanError,
        crate::proto::compact_formats::{
            ChainMetadata, CompactBlock, CompactOrchardAction, CompactTx,
        },
        orchard::{
            keys::Scope,
            note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
            note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
            value::NoteValue,
        },
        pasta_curves::{
            group::ff::{Field, PrimeField},
            pallas,
        },
        proptest::prelude::*,
        rand::{Rng, rand_core::UnwrapErr, rngs::SysRng},
        zcash_note_encryption::Domain,
        zcash_protocol::ShieldedPool,
    };

    #[cfg(feature = "orchard")]
    #[allow(non_upper_case_globals)]
    const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);

    use incrementalmerkletree::{Marking, Position, Retention};
    use sapling::Nullifier;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{
        consensus::{BlockHeight, Network},
        value::Zatoshis,
    };
    use zip32::AccountId;

    use super::{BatchRunners, scan_block_with_runners};
    use crate::{
        data_api::BlockMetadata,
        scanning::{Nullifiers, ScanningKeys, scan_block, testing::fake_compact_block},
    };

    #[test]
    fn scan_block_with_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                Zatoshis::const_from_u64(5),
                false,
                None,
            );
            assert_eq!(cb.vtx.len(), 2);

            let mut batch_runners = if scan_multithreaded {
                let mut runners = BatchRunners::<_, (), (), ()>::for_keys(10, &scanning_keys);
                runners
                    .add_block(&Network::TestNetwork, cb.clone())
                    .unwrap();
                runners.flush();

                Some(runners)
            } else {
                None
            };

            let scanned_block = scan_block_with_runners(
                &network,
                cb,
                &scanning_keys,
                &Nullifiers::empty(),
                Some(&BlockMetadata::from_parts(
                    BlockHeight::from(0),
                    BlockHash([0u8; 32]),
                    Some(0),
                    #[cfg(feature = "orchard")]
                    Some(0),
                    #[cfg(feature = "orchard")]
                    Some(0),
                )),
                batch_runners.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1.into());
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &account);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);
            assert_eq!(
                tx.sapling_outputs()[0].note_commitment_tree_position(),
                Position::from(1)
            );

            assert_eq!(scanned_block.sapling().final_tree_size(), 2);
            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        marking: Marking::Marked
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[cfg(feature = "orchard")]
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(24))]

        /// An Ironwood output (a version 3 note in `tx.ironwood_actions`) is detected by the
        /// scanner using the account's Orchard viewing key under the Ironwood note-encryption
        /// domain, and is reported as an Ironwood output distinct from the Orchard pool. This
        /// exercises the fix that decrypts Ironwood notes with `IronwoodDomain` rather than
        /// `OrchardDomain` (which, accepting only version 2 plaintexts, would silently fail to
        /// detect the note). Fuzzing the value, diversified address index, and key scope covers a
        /// range of notes the wallet must detect.
        #[test]
        fn scan_block_detects_ironwood_note(
            value in 1u64..=1_000_000_000u64,
            diversifier_index in 0u32..8,
            internal in proptest::bool::ANY,
        ) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let orchard_fvk = ufvk.orchard().expect("Orchard key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let scope = if internal { Scope::Internal } else { Scope::External };
            let mut rng = OsRng;
            let recipient = orchard_fvk.address_at(diversifier_index, scope);

            // Build a version 3 (Ironwood) compact action. `rho` is derived from the revealed
            // nullifier exactly as the crate does internally (`Rho::from_nf_old(nf) ==
            // Rho(nf.inner())`, which `Rho::from_bytes(&nf.to_bytes())` reconstructs), so the domain
            // the scanner builds via `IronwoodDomain::for_compact_action` will match and decryption
            // will succeed.
            let nf_old =
                orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                    .unwrap();
            let rho = Rho::from_bytes(&nf_old.to_bytes()).unwrap();
            let rseed = loop {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                if let Some(rseed) = Option::from(RandomSeed::from_bytes(bytes, &rho)) {
                    break rseed;
                }
            };
            let note = Note::from_parts(
                recipient,
                NoteValue::from_raw(value),
                rho,
                rseed,
                NoteVersion::V3,
            )
            .unwrap();
            let encryptor = IronwoodNoteEncryption::new(
                Some(orchard_fvk.to_ovk(Scope::External)),
                note,
                [0u8; 512],
            );
            let cmx = ExtractedNoteCommitment::from(note.commitment());
            let ephemeral_key = IronwoodDomain::epk_bytes(encryptor.epk());
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let action = CompactOrchardAction {
                nullifier: nf_old.to_bytes().to_vec(),
                cmx: cmx.to_bytes().to_vec(),
                ephemeral_key: ephemeral_key.0.to_vec(),
                ciphertext: enc_ciphertext[..52].to_vec(),
            };

            let mut ctx = CompactTx::default();
            let mut txid = vec![0u8; 32];
            rng.fill_bytes(&mut txid);
            ctx.txid = txid;
            ctx.ironwood_actions.push(action);

            let mut cb = CompactBlock {
                hash: {
                    let mut hash = vec![0u8; 32];
                    rng.fill_bytes(&mut hash);
                    hash
                },
                prev_hash: vec![0u8; 32],
                height: 1,
                ..Default::default()
            };
            cb.vtx.push(ctx);
            // The block contains a single Ironwood action and no Sapling or Orchard outputs, so
            // only the Ironwood tree grows (from 0 to 1).
            cb.chain_metadata = Some(ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: 1,
            });

            let mut runners = BatchRunners::<_, (), (), ()>::for_keys(10, &scanning_keys);
            runners.add_block(&network, cb.clone()).unwrap();
            runners.flush();

            let scanned_block = scan_block_with_runners(
                &network,
                cb,
                &scanning_keys,
                &Nullifiers::empty(),
                Some(&BlockMetadata::from_parts(
                    BlockHeight::from(0),
                    BlockHash([0u8; 32]),
                    Some(0),
                    Some(0),
                    Some(0),
                )),
                Some(&mut runners),
            )
            .unwrap();

            let txs = scanned_block.transactions();
            prop_assert_eq!(txs.len(), 1);
            let tx = &txs[0];
            // The note appears as an Ironwood output, not an Orchard one.
            prop_assert_eq!(tx.orchard_outputs().len(), 0);
            prop_assert_eq!(tx.ironwood_outputs().len(), 1);
            prop_assert_eq!(tx.ironwood_outputs()[0].account_id(), &account);
            prop_assert_eq!(tx.ironwood_outputs()[0].note().0.value().inner(), value);
            prop_assert_eq!(
                tx.ironwood_outputs()[0].note_commitment_tree_position(),
                Position::from(0)
            );

            prop_assert_eq!(scanned_block.ironwood().final_tree_size(), 1);
            prop_assert_eq!(scanned_block.orchard().final_tree_size(), 0);
        }
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn malformed_compact_ironwood_spend_nullifier_is_a_scan_error() {
        let network = Network::TestNetwork;
        let account = AccountId::ZERO;
        let usk = UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
        let scanning_keys =
            ScanningKeys::from_account_ufvks([(account, usk.to_unified_full_viewing_key())]);

        // A compact Ironwood action whose revealed nullifier is not 32 bytes, as a buggy or
        // malicious lightwalletd might serve. The output fields are well-formed, so it is the
        // spend-side nullifier validation that must reject the block (rather than panicking).
        let action = CompactOrchardAction {
            nullifier: vec![0u8; 31],
            cmx: vec![0u8; 32],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; 52],
        };
        let mut ctx = CompactTx {
            txid: vec![0u8; 32],
            ..Default::default()
        };
        ctx.ironwood_actions.push(action);
        let mut cb = CompactBlock {
            hash: vec![0u8; 32],
            prev_hash: vec![0u8; 32],
            height: 1,
            ..Default::default()
        };
        cb.vtx.push(ctx);
        cb.chain_metadata = Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: 1,
        });

        // Single-threaded scan (no batch runners); the spend-side nullifier check runs first.
        let result = scan_block_with_runners::<_, _, _, (), (), ()>(
            &network,
            cb,
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&BlockMetadata::from_parts(
                BlockHeight::from(0),
                BlockHash([0u8; 32]),
                Some(0),
                Some(0),
                Some(0),
            )),
            None,
        );
        assert!(
            matches!(
                result,
                Err(ScanError::EncodingInvalid {
                    pool_type: ShieldedPool::Ironwood,
                    index: 0,
                    ..
                })
            ),
            "a malformed Ironwood spend nullifier must produce a handleable ScanError",
        );
    }

    #[cfg(feature = "zakura-pir-enhance")]
    #[test]
    fn owned_ironwood_spend_captures_every_action_for_outgoing_recovery() {
        let network = Network::TestNetwork;
        let account = AccountId::try_from(12).unwrap();
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let mut rng = OsRng;
        let owned_nullifier =
            orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                .unwrap();
        let other_nullifier =
            orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                .unwrap();
        let cmx_0 = pallas::Base::random(&mut rng).to_repr();
        let cmx_1 = pallas::Base::random(&mut rng).to_repr();
        let actions =
            [(owned_nullifier, cmx_0), (other_nullifier, cmx_1)].map(|(nullifier, cmx)| {
                CompactOrchardAction {
                    nullifier: nullifier.to_bytes().to_vec(),
                    cmx: cmx.to_vec(),
                    ephemeral_key: vec![0; 32],
                    ciphertext: vec![0; 52],
                }
            });
        let mut tx = CompactTx {
            txid: vec![7; 32],
            ..Default::default()
        };
        tx.ironwood_actions.extend(actions);
        let mut mixed_tx = tx.clone();
        mixed_tx.actions.push(mixed_tx.ironwood_actions[0].clone());
        let mut block = CompactBlock {
            hash: vec![1; 32],
            prev_hash: vec![0; 32],
            height: 1,
            ..Default::default()
        };
        block.vtx.push(tx);
        block.chain_metadata = Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: 7,
        });
        let nullifiers = Nullifiers::new(vec![], vec![], vec![(account, owned_nullifier)]);

        let scanned = scan_block_with_runners::<_, _, _, (), (), ()>(
            &network,
            block,
            &scanning_keys,
            &nullifiers,
            Some(&BlockMetadata::from_parts(
                BlockHeight::from(0),
                BlockHash([0; 32]),
                Some(0),
                Some(0),
                Some(5),
            )),
            None,
        )
        .unwrap();

        let tx = &scanned.transactions()[0];
        assert_eq!(tx.ironwood_spends().len(), 1);
        assert_eq!(tx.ironwood_enhance_candidates().len(), 2);
        for (index, candidate) in tx.ironwood_enhance_candidates().iter().enumerate() {
            assert_eq!(candidate.position(), Position::from(5 + index as u64));
            assert_eq!(candidate.output_index(), index);
            assert_eq!(candidate.funding_accounts(), &[account]);
            assert_eq!(candidate.ephemeral_key(), &[0; 32]);
            assert_eq!(candidate.compact_ciphertext(), &[0; 52]);
        }
        assert_eq!(
            tx.ironwood_enhance_candidates()[0].nullifier(),
            &owned_nullifier.to_bytes()
        );
        assert_eq!(tx.ironwood_enhance_candidates()[0].cmx(), &cmx_0);
        assert_eq!(
            tx.ironwood_enhance_candidates()[1].nullifier(),
            &other_nullifier.to_bytes()
        );
        assert_eq!(tx.ironwood_enhance_candidates()[1].cmx(), &cmx_1);
        assert!(tx.ironwood_pir_eligible());

        let mut mixed_block = CompactBlock {
            hash: vec![2; 32],
            prev_hash: vec![0; 32],
            height: 1,
            ..Default::default()
        };
        mixed_block.vtx.push(mixed_tx);
        mixed_block.chain_metadata = Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 1,
            ironwood_commitment_tree_size: 7,
        });
        let mixed_scanned = scan_block_with_runners::<_, _, _, (), (), ()>(
            &network,
            mixed_block,
            &scanning_keys,
            &nullifiers,
            Some(&BlockMetadata::from_parts(
                BlockHeight::from(0),
                BlockHash([0; 32]),
                Some(0),
                Some(0),
                Some(5),
            )),
            None,
        )
        .unwrap();
        let mixed_tx = &mixed_scanned.transactions()[0];
        assert!(!mixed_tx.ironwood_pir_eligible());
        assert!(
            mixed_tx.ironwood_enhance_candidates().is_empty(),
            "mixed-pool transactions must remain on standard txid enhancement"
        );
    }

    /// A wallet-owned Ironwood output — in particular change, which is found because
    /// `ScanningKeys` covers the internal scope — is served by the incoming memo queue. It must
    /// not also be emitted as an outgoing candidate: change is encrypted under the internal OVK
    /// while outgoing recovery holds only the external one, so such an entry could never be
    /// resolved and would keep its transaction protected, and so un-enhanced, forever.
    #[cfg(feature = "zakura-pir-enhance")]
    #[test]
    fn wallet_owned_ironwood_outputs_are_not_outgoing_candidates() {
        let network = Network::TestNetwork;
        let account = AccountId::try_from(0).unwrap();
        let usk = UnifiedSpendingKey::from_seed(&network, &[0; 32], account).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let fvk = ufvk.orchard().expect("Orchard key is present").clone();
        let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);
        let mut rng = OsRng;

        // Action 0 spends a note the wallet owns and pays change back to the wallet's own
        // internal address, so the scanner decrypts it as a received note.
        let owned_nf =
            orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                .unwrap();
        let rho = Rho::from_bytes(&owned_nf.to_bytes()).unwrap();
        let rseed = loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            if let Some(rseed) = Option::from(RandomSeed::from_bytes(bytes, &rho)) {
                break rseed;
            }
        };
        let change = Note::from_parts(
            fvk.address_at(0u32, Scope::Internal),
            NoteValue::from_raw(1000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        // Change carries the internal OVK, exactly as the builder writes it.
        let encryptor =
            IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::Internal)), change, [0; 512]);
        let change_action = CompactOrchardAction {
            nullifier: owned_nf.to_bytes().to_vec(),
            cmx: ExtractedNoteCommitment::from(change.commitment())
                .to_bytes()
                .to_vec(),
            ephemeral_key: IronwoodDomain::epk_bytes(encryptor.epk()).0.to_vec(),
            ciphertext: encryptor.encrypt_note_plaintext()[..52].to_vec(),
        };

        // Action 1 pays someone else, so the wallet cannot decrypt it and it stays a candidate.
        let other_nf =
            orchard::note::Nullifier::from_bytes(&pallas::Base::random(&mut rng).to_repr())
                .unwrap();
        let external_cmx = pallas::Base::random(&mut rng).to_repr();
        let external_action = CompactOrchardAction {
            nullifier: other_nf.to_bytes().to_vec(),
            cmx: external_cmx.to_vec(),
            ephemeral_key: vec![0; 32],
            ciphertext: vec![0; 52],
        };

        let mut tx = CompactTx {
            txid: vec![3; 32],
            ..Default::default()
        };
        tx.ironwood_actions.push(change_action);
        tx.ironwood_actions.push(external_action);
        let mut block = CompactBlock {
            hash: vec![1; 32],
            prev_hash: vec![0; 32],
            height: 1,
            ..Default::default()
        };
        block.vtx.push(tx);
        block.chain_metadata = Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: 2,
        });

        let scanned = scan_block_with_runners::<_, _, _, (), (), ()>(
            &network,
            block,
            &scanning_keys,
            &Nullifiers::new(vec![], vec![], vec![(account, owned_nf)]),
            Some(&BlockMetadata::from_parts(
                BlockHeight::from(0),
                BlockHash([0; 32]),
                Some(0),
                Some(0),
                Some(0),
            )),
            None,
        )
        .unwrap();

        let tx = &scanned.transactions()[0];
        assert!(tx.ironwood_pir_eligible());
        assert_eq!(
            tx.ironwood_outputs().len(),
            1,
            "the change output should be received by the wallet"
        );
        assert_eq!(tx.ironwood_outputs()[0].index(), 0);
        // Dropping the outgoing candidate also drops the `sent_notes` row that would have been
        // written for this output, and with it `flag_previously_received_change`. That repair is
        // only needed for notes scanned before their transaction's spends were linkable — which
        // an Enhance PIR candidate never is, since it exists only when the wallet already
        // recognised the spend. So `is_change` has to be right here, at scan time.
        assert!(
            tx.ironwood_outputs()[0].is_change(),
            "change must be flagged during scanning, with no later repair to rely on"
        );

        let candidates = tx.ironwood_enhance_candidates();
        assert_eq!(
            candidates.len(),
            1,
            "only the output the wallet cannot decrypt needs outgoing recovery"
        );
        assert_eq!(candidates[0].output_index(), 1);
        assert_eq!(candidates[0].nullifier(), &other_nf.to_bytes());
    }

    #[test]
    fn scan_block_with_txs_after_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                Zatoshis::const_from_u64(5),
                true,
                Some((0, 0)),
            );
            assert_eq!(cb.vtx.len(), 3);

            let mut batch_runners = if scan_multithreaded {
                let mut runners = BatchRunners::<_, (), (), ()>::for_keys(10, &scanning_keys);
                runners
                    .add_block(&Network::TestNetwork, cb.clone())
                    .unwrap();
                runners.flush();

                Some(runners)
            } else {
                None
            };

            let scanned_block = scan_block_with_runners(
                &network,
                cb,
                &scanning_keys,
                &Nullifiers::empty(),
                None,
                batch_runners.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1.into());
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &AccountId::ZERO);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);

            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Marked,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        marking: Marking::None
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[test]
    fn scan_block_with_my_spend() {
        let network = Network::TestNetwork;
        let account = AccountId::try_from(12).unwrap();
        let usk = UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
        let ufvk = usk.to_unified_full_viewing_key();
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();

        let nf = Nullifier([7; 32]);
        let nullifiers = Nullifiers::new(
            vec![(account, nf)],
            #[cfg(feature = "orchard")]
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
        );

        let cb = fake_compact_block(
            1u32.into(),
            BlockHash([0; 32]),
            nf,
            ufvk.sapling().unwrap(),
            Zatoshis::const_from_u64(5),
            false,
            Some((0, 0)),
        );
        assert_eq!(cb.vtx.len(), 2);

        let scanned_block = scan_block(&network, cb, &scanning_keys, &nullifiers, None).unwrap();
        let txs = scanned_block.transactions();
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.block_index(), 1.into());
        assert_eq!(tx.sapling_spends().len(), 1);
        assert_eq!(tx.sapling_outputs().len(), 0);
        assert_eq!(tx.sapling_spends()[0].index(), 0);
        assert_eq!(tx.sapling_spends()[0].nf(), &nf);
        assert_eq!(tx.sapling_spends()[0].account_id(), &account);

        assert_eq!(
            scanned_block
                .sapling()
                .commitments()
                .iter()
                .map(|(_, retention)| *retention)
                .collect::<Vec<_>>(),
            vec![
                Retention::Ephemeral,
                Retention::Checkpoint {
                    id: scanned_block.height(),
                    marking: Marking::None
                }
            ]
        );
    }
}
