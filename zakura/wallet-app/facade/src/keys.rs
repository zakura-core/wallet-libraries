//! Deriving spending keys from a seed.
//!
//! The store derives an account from a seed and then drops it, keeping only the
//! viewing key, so the ability to spend never sits in the same file as the
//! ability to see. The consequence is that spending needs the seed supplied
//! again, and something has to bridge the store's account back to the
//! `orchard::keys::SpendingKey` the builder wants. Nothing in the core does.
//!
//! The check in [`spending_keys`] is the point of this module. Deriving a key
//! from the wrong seed produces a perfectly valid key that owns nothing, and a
//! transaction signed with it would fail at consensus with no useful
//! explanation. Comparing the derived viewing key against the stored one turns
//! that into a clear error before anything expensive happens.

use zakura_wallet_store::WalletDb;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Parameters;
use zeroize::Zeroizing;

use crate::error::Error;

/// Derives the spending keys for an account from its seed.
///
/// Fails with [`Error::WatchOnly`] if the account has no ZIP 32 index — it was
/// imported from a viewing key and there is nothing to derive — and with
/// [`Error::WrongSeed`] if the derived viewing key is not the one stored.
pub(crate) fn spending_keys<P: Parameters>(
    db: &WalletDb,
    params: &P,
    account: zakura_wallet_core::AccountId,
    seed: &Zeroizing<Vec<u8>>,
) -> Result<zakura_wallet_tx::Keys, Error> {
    let stored = db
        .account(params, account)?
        .ok_or(Error::NoSuchAccount(account.0))?;

    if !stored.has_spend_key {
        return Err(Error::WatchOnly);
    }
    let index = stored.hd_account_index.ok_or(Error::WatchOnly)?;
    let index = zip32::AccountId::try_from(index).map_err(|_| Error::WatchOnly)?;

    let usk = UnifiedSpendingKey::from_seed(params, seed.as_slice(), index)
        .map_err(|_| Error::WrongSeed)?;
    let keys = zakura_wallet_tx::Keys::from_spending_key(*usk.orchard());

    // The seed could be anybody's. A key derived from the wrong one is still a
    // valid key; it simply owns none of this account's notes, and every proof
    // built with it would be rejected for reasons that name nothing useful.
    if &keys.fvk != stored.orchard_fvk()? {
        return Err(Error::WrongSeed);
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use zakura_wallet_core::{KeyScope, pool::PoolId};
    use zakura_wallet_scan::{
        NullifierSnapshot, ScanKeys, detect_batch,
        testing::{ChainBuilder, IRONWOOD_ACTIVATION, test_params},
    };
    use zakura_wallet_store::{WalletDb, testing::test_db};
    use zcash_protocol::consensus::BlockHeight;
    use zeroize::Zeroizing;

    use super::*;
    use crate::error::ErrorCode;

    const SEED: [u8; 32] = [9u8; 32];
    const START: u32 = IRONWOOD_ACTIVATION + 10;

    fn seed(bytes: [u8; 32]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(bytes.to_vec())
    }

    fn account(db: &mut WalletDb) -> zakura_wallet_core::AccountId {
        db.create_account(
            &test_params(),
            &SEED,
            zip32::AccountId::try_from(0).unwrap(),
            BlockHeight::from_u32(START),
        )
        .expect("the account is created")
    }

    /// The seam the rest of the suite has never covered.
    ///
    /// The store derives an account from a seed and keeps only the viewing key;
    /// the builder needs a spending key derived from that same seed. Every
    /// other spend test in this workspace constructs a `SpendingKey` directly,
    /// so nothing has ever checked that the two derivations agree. If they did
    /// not, the wallet would sign with a key owning nothing and learn about it
    /// from a rejected proof.
    #[test]
    fn a_seed_derives_the_keys_of_the_account_it_created() {
        let mut db = test_db().unwrap();
        let id = account(&mut db);

        let derived = spending_keys(&db, &test_params(), id, &seed(SEED))
            .expect("the seed derives the account it created");

        let stored = db
            .account(&test_params(), id)
            .unwrap()
            .unwrap()
            .orchard_fvk()
            .unwrap()
            .clone();
        assert_eq!(derived.fvk, stored, "the two derivations must agree");
    }

    /// And the key that agrees is the one that finds the money.
    ///
    /// Equality of viewing keys is necessary but not sufficient: this pays a
    /// note to the key derived from the seed and asserts the wallet, scanning
    /// with the key it stored, sees it.
    #[test]
    fn notes_paid_to_a_seed_derived_key_are_found_by_the_stored_one() {
        let mut db = test_db().unwrap();
        let id = account(&mut db);

        let derived = spending_keys(&db, &test_params(), id, &seed(SEED)).unwrap();

        let mut chain = ChainBuilder::new(START);
        chain.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &derived.fvk, KeyScope::External, 400_000);
            });
        });
        chain.empty_blocks(2);

        let stored_fvk = db
            .account(&test_params(), id)
            .unwrap()
            .unwrap()
            .orchard_fvk()
            .unwrap()
            .clone();
        let batch = detect_batch(
            &test_params(),
            &ScanKeys::from_accounts([(id, stored_fvk)]),
            &NullifierSnapshot::default(),
            &chain.anchor(),
            chain.blocks(),
        )
        .expect("the chain scans");
        db.put_batch(&test_params(), &batch).unwrap();

        assert_eq!(db.total_balance(id).unwrap().total().into_u64(), 400_000);
    }

    /// A different seed derives a valid key that owns nothing, and the failure
    /// has to be named before anything is signed with it.
    #[test]
    fn the_wrong_seed_is_refused_rather_than_used() {
        let mut db = test_db().unwrap();
        let id = account(&mut db);

        let result = spending_keys(&db, &test_params(), id, &seed([1u8; 32]));
        let error = result.err().map(|e| e.code());
        assert_eq!(error, Some(ErrorCode::WrongSeed));
    }

    #[test]
    fn an_unknown_account_is_not_a_wrong_seed() {
        let db = test_db().unwrap();
        let result = spending_keys(
            &db,
            &test_params(),
            zakura_wallet_core::AccountId(42),
            &seed(SEED),
        );
        let error = result.err().map(|e| e.code());
        assert_eq!(error, Some(ErrorCode::NoSuchAccount));
    }

    /// A watch-only account has no index to derive from, and must say so rather
    /// than reporting the seed as wrong.
    #[test]
    fn a_watch_only_account_cannot_spend() {
        let mut db = test_db().unwrap();
        let id = account(&mut db);
        let ufvk = db
            .account(&test_params(), id)
            .unwrap()
            .unwrap()
            .ufvk
            .clone();

        let mut other = test_db().unwrap();
        let imported = other
            .import_account(&test_params(), &ufvk, BlockHeight::from_u32(START))
            .expect("the viewing key imports");

        let result = spending_keys(&other, &test_params(), imported, &seed(SEED));
        let error = result.err().map(|e| e.code());
        assert_eq!(error, Some(ErrorCode::WatchOnly));
    }
}
