use std::collections::HashMap;

use sapling::note_encryption::{PreparedIncomingViewingKey, SaplingDomain};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_primitives::{
    transaction::Transaction, transaction::components::sapling::zip212_enforcement,
};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::MemoBytes,
    value::Zatoshis,
};
use zip32::Scope;

use crate::data_api::DecryptedTransaction;

#[cfg(feature = "orchard")]
use orchard::note_encryption::{
    DomainVersion, IronwoodVersion, NoteEncryptionDomain, OrchardVersion,
};

#[cfg(feature = "one-time-ivk")]
use {
    crate::scanning::one_time_ivk::OneTimeScanningKey, std::hash::Hash, zakura_one_time_ivk::KeyId,
};

/// The prepared one-time IVKs of an account, with their key identities.
#[cfg(feature = "one-time-ivk")]
type OneTimeIvks = [(KeyId, orchard::keys::PreparedIncomingViewingKey)];

/// An enumeration of the possible relationships a TXO can have to the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferType {
    /// The output was received on one of the wallet's external addresses via decryption using the
    /// associated incoming viewing key, or at one of the wallet's transparent addresses.
    Incoming,
    /// The output is internal to a single wallet account, e.g. change: the recipient and the
    /// funder are the same wallet account. For shielded outputs, this corresponds to decryption
    /// using the account's internal incoming viewing key.
    AccountInternal,
    /// The output is internal to the wallet but spans accounts: a wallet account funded the
    /// transaction and a different wallet account received the output. Only produced for
    /// transparent outputs; shielded cross-account transfers are observed as separate `Outgoing`
    /// (from the funder) and `Incoming` (to the recipient) outputs.
    WalletInternal,
    /// The output was decrypted using one of the wallet's outgoing viewing keys, or was created
    /// in a transaction constructed by this wallet.
    Outgoing,
}

/// A decrypted shielded output.
pub struct DecryptedOutput<Note, AccountId> {
    index: usize,
    note: Note,
    value_pool: ShieldedPool,
    account: AccountId,
    memo: MemoBytes,
    transfer_type: TransferType,
    #[cfg(feature = "one-time-ivk")]
    one_time_key_id: Option<zakura_one_time_ivk::KeyId>,
}

impl<Note, AccountId> DecryptedOutput<Note, AccountId> {
    pub fn new(
        index: usize,
        note: Note,
        value_pool: ShieldedPool,
        account: AccountId,
        memo: MemoBytes,
        transfer_type: TransferType,
    ) -> Self {
        Self {
            index,
            note,
            value_pool,
            account,
            memo,
            transfer_type,
            #[cfg(feature = "one-time-ivk")]
            one_time_key_id: None,
        }
    }

    /// Retains the derived receiving key used for authenticated note decryption.
    #[cfg(feature = "one-time-ivk")]
    fn with_one_time_key_id(mut self, key_id: Option<KeyId>) -> Self {
        self.one_time_key_id = key_id;
        self
    }

    /// Derived receiving key, relative to the owning account.
    #[cfg(feature = "one-time-ivk")]
    pub fn one_time_key_id(&self) -> Option<zakura_one_time_ivk::KeyId> {
        self.one_time_key_id
    }

    /// The index of the output within the shielded outputs of the Sapling bundle or the actions of
    /// the Orchard bundle, depending upon the type of [`Self::note`].
    pub fn index(&self) -> usize {
        self.index
    }

    /// The note within the output.
    pub fn note(&self) -> &Note {
        &self.note
    }
    /// Returns the value pool to which the note contributes its value.
    pub fn value_pool(&self) -> ShieldedPool {
        self.value_pool
    }
    /// The account that decrypted the note.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The memo bytes included with the note.
    pub fn memo(&self) -> &MemoBytes {
        &self.memo
    }

    /// Returns a [`TransferType`] value that is determined based upon what type of key was used to
    /// decrypt the transaction.
    pub fn transfer_type(&self) -> TransferType {
        self.transfer_type
    }
}

impl<A> DecryptedOutput<sapling::Note, A> {
    pub fn note_value(&self) -> Zatoshis {
        Zatoshis::from_u64(self.note.value().inner())
            .expect("Sapling note value is expected to have been validated by consensus.")
    }
}

#[cfg(feature = "orchard")]
impl<A> DecryptedOutput<orchard::note::Note, A> {
    pub fn note_value(&self) -> Zatoshis {
        Zatoshis::from_u64(self.note.value().inner())
            .expect("Orchard note value is expected to have been validated by consensus.")
    }
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`UnifiedFullViewingKey`]s.
///
/// # Parameters
/// - `params`: The network parameters corresponding to the network the transaction
///   was created for.
/// - `mined_height`: The height at which the transaction was mined, or `None` for
///   unmined transactions.
/// - `chain_tip_height`: The current chain tip height, if known. This parameter
///   will be unused if `mined_height.is_some()`.
/// - `tx`: The transaction to decrypt.
/// - `ufvks`: The [`UnifiedFullViewingKey`]s to use in trial decryption, keyed
///   by the identifiers for the wallet accounts they correspond to.
pub fn decrypt_transaction<'a, P: consensus::Parameters, AccountId: Copy>(
    params: &P,
    mined_height: Option<BlockHeight>,
    chain_tip_height: Option<BlockHeight>,
    tx: &'a Transaction,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> DecryptedTransaction<'a, Transaction, AccountId> {
    decrypt_transaction_inner(
        params,
        mined_height,
        chain_tip_height,
        tx,
        ufvks,
        #[cfg(feature = "one-time-ivk")]
        &|_| &[],
    )
}

/// [`decrypt_transaction`], also trial-decrypting Ironwood actions with one-time keys.
///
/// Each key is tried after its account's ordinary incoming viewing keys and before its
/// outgoing viewing key, so an output paid to it is one incoming output carrying its
/// [`DecryptedOutput::one_time_key_id`], even when the account also funded it. A key whose
/// account has no Orchard key in `ufvks` is not tried. The result reports
/// [`DecryptedTransaction::one_time_ivks_applied`].
#[cfg(feature = "one-time-ivk")]
pub fn decrypt_transaction_with_one_time_ivks<
    'a,
    P: consensus::Parameters,
    AccountId: Copy + Eq + Hash,
>(
    params: &P,
    mined_height: Option<BlockHeight>,
    chain_tip_height: Option<BlockHeight>,
    tx: &'a Transaction,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    one_time_keys: impl IntoIterator<Item = OneTimeScanningKey<AccountId>>,
) -> DecryptedTransaction<'a, Transaction, AccountId> {
    let mut by_account = HashMap::<_, Vec<_>>::new();
    for key in one_time_keys {
        let ivk = key.full_viewing_key().to_ivk(Scope::External);
        by_account.entry(*key.account_id()).or_default().push((
            key.key_id(),
            orchard::keys::PreparedIncomingViewingKey::new(&ivk),
        ));
    }
    decrypt_transaction_inner(
        params,
        mined_height,
        chain_tip_height,
        tx,
        ufvks,
        &|account| by_account.get(account).map_or(&[], Vec::as_slice),
    )
    .with_one_time_ivks_applied()
}

/// The trial decryption shared by [`decrypt_transaction`] and, with `one_time_ivks`
/// returning each account's one-time keys, [`decrypt_transaction_with_one_time_ivks`].
fn decrypt_transaction_inner<
    'a,
    #[cfg(feature = "one-time-ivk")] 'k,
    P: consensus::Parameters,
    AccountId: Copy,
>(
    params: &P,
    mined_height: Option<BlockHeight>,
    chain_tip_height: Option<BlockHeight>,
    tx: &'a Transaction,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
    #[cfg(feature = "one-time-ivk")] one_time_ivks: &dyn Fn(&AccountId) -> &'k OneTimeIvks,
) -> DecryptedTransaction<'a, Transaction, AccountId> {
    let zip212_enforcement = zip212_enforcement(
        params,
        // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
        // for mempool transactions. We fall back to Sapling activation if we have no other
        // information.
        mined_height.unwrap_or_else(|| {
            chain_tip_height
                .map(|max_height| max_height + 1) // "mempool height"
                .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
                // Fall back to the genesis block in regtest mode.
                .unwrap_or_else(|| BlockHeight::from(0))
        }),
    );
    let sapling_bundle = tx.sapling_bundle();
    let sapling_outputs = sapling_bundle
        .iter()
        .flat_map(|bundle| {
            ufvks
                .iter()
                .flat_map(|(account, ufvk)| ufvk.sapling().into_iter().map(|dfvk| (*account, dfvk)))
                .flat_map(|(account, dfvk)| {
                    let sapling_domain = SaplingDomain::new(zip212_enforcement);
                    let ivk_external =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External));
                    let ivk_internal =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));
                    let ovk = dfvk.fvk().ovk;

                    bundle
                        .shielded_outputs()
                        .iter()
                        .enumerate()
                        .flat_map(move |(index, output)| {
                            try_note_decryption(&sapling_domain, &ivk_external, output)
                                .map(|ret| (ret, TransferType::Incoming))
                                .or_else(|| {
                                    try_note_decryption(&sapling_domain, &ivk_internal, output)
                                        .map(|ret| (ret, TransferType::AccountInternal))
                                })
                                .or_else(|| {
                                    try_output_recovery_with_ovk(
                                        &sapling_domain,
                                        &ovk,
                                        output,
                                        output.cv(),
                                        output.out_ciphertext(),
                                    )
                                    .map(|ret| (ret, TransferType::Outgoing))
                                })
                                .into_iter()
                                .map(move |((note, _, memo), transfer_type)| {
                                    DecryptedOutput::new(
                                        index,
                                        note,
                                        ShieldedPool::Sapling,
                                        account,
                                        MemoBytes::from_bytes(&memo).expect("correct length"),
                                        transfer_type,
                                    )
                                })
                        })
                })
        })
        .collect();

    // Trial-decrypt an Orchard-family (Orchard or Ironwood) bundle. The two bundle kinds are
    // protocol-equivalent for trial decryption: both are Orchard-shaped and use the account's
    // Orchard viewing keys. They differ only in the note plaintext version their domain accepts
    // (selected by `V`: version 2 for [`OrchardVersion`], version 3 for [`IronwoodVersion`]) and
    // in the value pool their notes belong to. Decrypting a bundle under the other kind's domain
    // would silently detect nothing.
    // An account's `one_time_ivks` are tried after its ordinary incoming viewing keys.
    #[cfg(feature = "orchard")]
    fn decrypt_orchard_protocol_bundle<
        #[cfg(feature = "one-time-ivk")] 'k,
        V: DomainVersion,
        AccountId: Copy,
    >(
        ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
        bundle: &orchard::bundle::Bundle<
            orchard::bundle::Authorized,
            zcash_protocol::value::ZatBalance,
        >,
        pool: orchard::ValuePool,
        #[cfg(feature = "one-time-ivk")] one_time_ivks: &dyn Fn(&AccountId) -> &'k OneTimeIvks,
    ) -> impl Iterator<Item = DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>> {
        let shielded_pool = crate::wallet::shielded_pool_for_value_pool(pool);
        ufvks
            .iter()
            .flat_map(|(account, ufvk)| ufvk.orchard().into_iter().map(|fvk| (*account, fvk)))
            .flat_map(move |(account, fvk)| {
                let ivk_external =
                    orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
                let ivk_internal =
                    orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal));
                let ovk = fvk.to_ovk(Scope::External);

                bundle
                    .actions()
                    .iter()
                    .enumerate()
                    .flat_map(move |(index, action)| {
                        let domain = NoteEncryptionDomain::<V>::for_action(action);
                        let decrypted = try_note_decryption(&domain, &ivk_external, action)
                            .map(|ret| (ret, TransferType::Incoming))
                            .or_else(|| {
                                try_note_decryption(&domain, &ivk_internal, action)
                                    .map(|ret| (ret, TransferType::AccountInternal))
                            });
                        #[cfg(feature = "one-time-ivk")]
                        let mut one_time_key_id = None;
                        #[cfg(feature = "one-time-ivk")]
                        let decrypted = decrypted.or_else(|| {
                            one_time_ivks(&account).iter().find_map(|(key_id, ivk)| {
                                let ret = try_note_decryption(&domain, ivk, action)?;
                                one_time_key_id = Some(*key_id);
                                Some((ret, TransferType::Incoming))
                            })
                        });
                        decrypted
                            .or_else(|| {
                                try_output_recovery_with_ovk(
                                    &domain,
                                    &ovk,
                                    action,
                                    action.cv_net(),
                                    &action.encrypted_note().out_ciphertext,
                                )
                                .map(|ret| (ret, TransferType::Outgoing))
                            })
                            .into_iter()
                            .map(move |((note, _, memo), transfer_type)| {
                                let output = DecryptedOutput::new(
                                    index,
                                    (note, pool),
                                    shielded_pool,
                                    account,
                                    MemoBytes::from_bytes(&memo).expect("correct length"),
                                    transfer_type,
                                );
                                #[cfg(feature = "one-time-ivk")]
                                let output = output.with_one_time_key_id(one_time_key_id);
                                output
                            })
                    })
            })
    }

    #[cfg(feature = "orchard")]
    let orchard_outputs = tx
        .orchard_bundle()
        .iter()
        .flat_map(|bundle| {
            decrypt_orchard_protocol_bundle::<OrchardVersion, _>(
                ufvks,
                bundle,
                orchard::ValuePool::Orchard,
                #[cfg(feature = "one-time-ivk")]
                &|_| &[],
            )
        })
        .collect();

    #[cfg(feature = "orchard")]
    let ironwood_outputs = tx
        .ironwood_bundle()
        .iter()
        .flat_map(|bundle| {
            decrypt_orchard_protocol_bundle::<IronwoodVersion, _>(
                ufvks,
                bundle,
                orchard::ValuePool::Ironwood,
                #[cfg(feature = "one-time-ivk")]
                one_time_ivks,
            )
        })
        .collect();

    DecryptedTransaction::new(
        mined_height,
        tx,
        sapling_outputs,
        #[cfg(feature = "orchard")]
        orchard_outputs,
        #[cfg(feature = "orchard")]
        ironwood_outputs,
    )
}

#[cfg(all(test, feature = "one-time-ivk"))]
mod tests {
    use std::collections::HashMap;

    use orchard::{
        Anchor, Proof,
        builder::{Builder, BundleType},
        bundle::{Authorized, BundleVersion},
        keys::{FullViewingKey, Scope},
        primitives::redpallas::Signature,
        value::NoteValue,
    };
    use zakura_one_time_ivk::{KeyId, Purpose};
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::transaction::{Transaction, TransactionData};
    use zcash_protocol::{
        consensus::{BranchId, MAIN_NETWORK},
        value::ZatBalance,
    };

    use super::{TransferType, decrypt_transaction, decrypt_transaction_with_one_time_ivks};
    use crate::scanning::one_time_ivk::OneTimeScanningKey;

    /// An Ironwood transaction paying `outputs`, with placeholder proof and signatures.
    fn ironwood_tx(
        outputs: &[(Option<orchard::keys::OutgoingViewingKey>, orchard::Address)],
    ) -> Transaction {
        let version = BundleVersion::ironwood_v3();
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            Anchor::empty_tree(),
        )
        .unwrap();
        for (ovk, recipient) in outputs {
            builder
                .add_output(
                    ovk.clone(),
                    *recipient,
                    NoteValue::from_raw(10_000),
                    [7; 512],
                )
                .unwrap();
        }
        let (bundle, _) = builder.build::<ZatBalance>(rand::rng()).unwrap().unwrap();
        let bundle = bundle.map_authorization(
            &mut (),
            |_, _, _| Signature::from([0; 64]),
            |_, _| Authorized::from_parts(Proof::new(vec![]), Signature::from([0; 64])),
        );
        TransactionData::from_parts_v6(
            BranchId::Nu6_3,
            0,
            0u32.into(),
            None,
            None,
            None,
            Some(bundle),
        )
        .freeze()
        .unwrap()
    }

    #[test]
    fn one_time_keys_tag_payments_and_self_payments() {
        let usk =
            UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &[1; 32], zip32::AccountId::ZERO).unwrap();
        let fvk = FullViewingKey::from(usk.orchard());
        let ufvks = HashMap::from([(0u32, usk.to_unified_full_viewing_key())]);
        let refund = KeyId::new(Purpose::Refund, 3);
        let receive = KeyId::new(Purpose::Receive, 5);
        let address = |id: KeyId| id.derive(&fvk).unwrap().address_at(0u32, Scope::External);
        // An external payment to `refund`, and a self-payment to `receive` that the
        // account's OVK also recovers.
        let tx = ironwood_tx(&[
            (None, address(refund)),
            (Some(fvk.to_ovk(Scope::External)), address(receive)),
        ]);

        let plain = decrypt_transaction(&MAIN_NETWORK, None, None, &tx, &ufvks);
        assert!(!plain.one_time_ivks_applied());
        let outputs = plain.ironwood_outputs();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].note().0.recipient(), address(receive));
        assert_eq!(outputs[0].transfer_type(), TransferType::Outgoing);
        assert_eq!(outputs[0].one_time_key_id(), None);

        let keys = [refund, receive].map(|id| OneTimeScanningKey::derive(0u32, id, &fvk).unwrap());
        let decrypted =
            decrypt_transaction_with_one_time_ivks(&MAIN_NETWORK, None, None, &tx, &ufvks, keys);
        assert!(decrypted.one_time_ivks_applied());
        let outputs = decrypted.ironwood_outputs();
        assert_eq!(outputs.len(), 2);
        for id in [refund, receive] {
            let output = outputs
                .iter()
                .find(|o| o.note().0.recipient() == address(id))
                .unwrap();
            assert_eq!(output.one_time_key_id(), Some(id));
            assert_eq!(output.transfer_type(), TransferType::Incoming);
            assert_eq!(output.account(), &0);
            assert_eq!(output.memo().as_array(), &[7; 512]);
        }
    }
}
