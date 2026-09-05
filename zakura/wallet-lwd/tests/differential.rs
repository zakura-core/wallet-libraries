//! Checks that the new wallet core and the forked one agree.
//!
//! Performance told us the rewrite is not slower. This asks the question that
//! actually matters: does it find the *same notes*? Both stacks are given the
//! same viewing key and byte-identical blocks, and their conclusions are
//! compared field by field.
//!
//! The blocks are synthetic, because they have to be: a key that owns nothing
//! makes the comparison vacuous, and no key we can generate owns anything on
//! mainnet. They carry real encrypted notes built with the real note-encryption
//! domains, so the cryptography under test is the same one that runs against
//! the chain.
//!
//! It needs no network — the chain is synthetic — so it runs in the default
//! suite and stays a gate rather than a thing someone remembers to run.

use std::{collections::BTreeSet, sync::Mutex};

use prost::Message;
use rand::SeedableRng;
use zakura_wallet_core::pool::PoolId;
use zakura_wallet_lwd::testing::to_wire;
use zakura_wallet_scan::{
    AccountId, KeyScope, NullifierSnapshot, ScanKeys, TransparentWatch, detect_batch,
    testing::{ChainBuilder, IRONWOOD_ACTIVATION, fvk_from_seed, test_params, test_rng},
};
use zakura_wallet_store::WalletDb as NewDb;
use zcash_protocol::consensus::BlockHeight;

use zcash_client_backend::{
    data_api::{
        AccountBirthday, WalletWrite,
        chain::{BlockSource, ChainState, scan_cached_blocks},
    },
    proto::compact_formats::CompactBlock as ForkBlock,
};
use zcash_client_sqlite::WalletDb as ForkDb;
use secrecy::SecretVec;
use zcash_keys::keys::UnifiedSpendingKey;

/// The Orchard full viewing key a ZIP 32 seed derives at account zero.
///
/// Both stacks use this, one directly and one by deriving it from the same
/// seed, so they are looking for exactly the same notes.
fn orchard_fvk(seed: &[u8; 32]) -> orchard::keys::FullViewingKey {
    UnifiedSpendingKey::from_seed(&test_params(), seed, zip32::AccountId::ZERO)
        .expect("the seed derives a spending key")
        .to_unified_full_viewing_key()
        .orchard()
        .expect("the derived key covers Orchard")
        .clone()
}

const START: u32 = IRONWOOD_ACTIVATION + 10;

struct InMemory(Mutex<Vec<ForkBlock>>);

impl BlockSource for InMemory {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(
            ForkBlock,
        ) -> Result<
            (),
            zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>,
        >,
    {
        let blocks = self.0.lock().unwrap();
        let from = from_height.map_or(0, u32::from);
        for block in blocks
            .iter()
            .filter(|b| b.height as u32 >= from)
            .take(limit.unwrap_or(usize::MAX))
        {
            with_block(block.clone())?;
        }
        Ok(())
    }
}

/// A note's identity: what both implementations must agree on exactly.
///
/// If these differ, one of them is wrong about what the chain contains.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NoteId {
    pool: &'static str,
    value: u64,
    position: u64,
    nullifier: String,
    /// 0 external, 1 internal.
    scope: i64,
}

/// A note as one implementation understood it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Note {
    id: NoteId,
    is_change: bool,
}

/// Runs both implementations over `blocks` and returns what each concluded.
fn compare(
    seed: &[u8; 32],
    anchor: &zakura_wallet_core::BlockAnchor,
    blocks: &[zakura_wallet_core::CompactBlock],
) -> Result<(BTreeSet<Note>, BTreeSet<Note>), Box<dyn std::error::Error>> {
    let alice = &orchard_fvk(seed);
    let params = test_params();
    // The fork's wallet does not expose its connection, so its results are read
    // back through a second connection to a real file. Each comparison gets its
    // own, because these run in parallel and a shared file would let one test's
    // notes appear in another's results.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let fork_dir = std::env::temp_dir().join(format!(
        "zakura-differential-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&fork_dir)?;
    let fork_path = fork_dir.join("wallet.db");

    let wire: Vec<ForkBlock> = blocks
        .iter()
        .map(|b| ForkBlock::decode(&to_wire(b).encode_to_vec()[..]).expect("shared wire format"))
        .collect();


    // ------------------------------------------------------------- the fork
    let fork_notes = {
        let mut db = ForkDb::for_path(
            &fork_path,
            params,
            zcash_client_sqlite::util::SystemClock,
            rand::rngs::Xoshiro256PlusPlus::seed_from_u64(0),
        )?;
        zcash_client_sqlite::wallet::init::WalletMigrator::new()
            .init_or_migrate(&mut db)
            .map_err(|e| format!("migrating the fork's wallet: {e:?}"))?;

        let chain_state = ChainState::empty(
            anchor.height,
            zcash_primitives::block::BlockHash(anchor.hash.0),
        );
        let birthday = AccountBirthday::from_parts(chain_state.clone(), None);

        // Both stacks derive their keys from the same seed rather than one
        // being handed the other's. That also keeps this independent of which
        // key-crate features the build happens to enable, since the shape of
        // `UnifiedFullViewingKey::new` depends on them.
        db.create_account("differential", &SecretVec::new(seed.to_vec()), &birthday, None)
            .map_err(|e| format!("creating the account: {e:?}"))?;

        let cache = InMemory(Mutex::new(wire));
        scan_cached_blocks(
            &params,
            &cache,
            &mut db,
            anchor.height + 1,
            &chain_state,
            blocks.len(),
        )
        .map_err(|e| format!("the fork failed to scan: {e:?}"))?;

        drop(db);
        read_fork_notes(&fork_path)?
    };

    // ---------------------------------------------------------- the new core
    let new_notes = {
        let mut db = NewDb::in_memory()?;
        db.set_birthday(anchor.height + 1)?;
        let keys = ScanKeys::from_accounts([(AccountId(1), alice.clone())]);

        let batch = detect_batch(
            &params,
            &keys,
            &TransparentWatch::default(),
            &NullifierSnapshot::default(),
            anchor,
            blocks,
        )?;
        db.put_batch(&params, &batch)?;

        read_new_notes(&db)?
    };

    Ok((fork_notes, new_notes))
}

fn read_fork_notes(path: &std::path::Path) -> Result<BTreeSet<Note>, Box<dyn std::error::Error>> {
    let conn = rusqlite::Connection::open(path)?;
    let mut out = BTreeSet::new();
    for (table, pool) in [
        ("orchard_received_notes", "Orchard"),
        ("ironwood_received_notes", "Ironwood"),
    ] {
        let mut stmt = conn.prepare(&format!(
            "SELECT value, commitment_tree_position, is_change, nf, recipient_key_scope
             FROM {table}"
        ))?;
        let rows = stmt.query_map([], |r| {
            Ok(Note {
                id: NoteId {
                    pool,
                    value: r.get::<_, i64>(0)? as u64,
                    position: r.get::<_, i64>(1)? as u64,
                    nullifier: hex::encode(r.get::<_, Vec<u8>>(3)?),
                    scope: r.get(4)?,
                },
                is_change: r.get(2)?,
            })
        })?;
        for note in rows {
            out.insert(note?);
        }
    }
    Ok(out)
}

fn read_new_notes(db: &NewDb) -> Result<BTreeSet<Note>, Box<dyn std::error::Error>> {
    let mut stmt = db.connection().prepare(
        "SELECT pool, value, commitment_tree_position, is_change, nf, key_scope
         FROM cache.received_notes",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Note {
            id: NoteId {
                pool: if r.get::<_, u8>(0)? == PoolId::Orchard.code() {
                    "Orchard"
                } else {
                    "Ironwood"
                },
                value: r.get::<_, i64>(1)? as u64,
                position: r.get::<_, i64>(2)? as u64,
                nullifier: hex::encode(r.get::<_, Vec<u8>>(4)?),
                scope: r.get(5)?,
            },
            is_change: r.get(3)?,
        })
    })?;
    let mut out = BTreeSet::new();
    for note in rows {
        out.insert(note?);
    }
    Ok(out)
}

/// Asserts the two implementations agree, allowing only the documented
/// difference in how change is recognised.
fn assert_agreement(fork: &BTreeSet<Note>, new: &BTreeSet<Note>) {
    let fork_ids: BTreeSet<NoteId> = fork.iter().map(|n| n.id.clone()).collect();
    let new_ids: BTreeSet<NoteId> = new.iter().map(|n| n.id.clone()).collect();

    // Identity must match exactly. A difference here means one implementation
    // is wrong about what the chain contains: a mis-derived nullifier, a note
    // attributed to the wrong pool, or — worst — a position off by one, which
    // would make every witness built from it invalid and would surface only
    // when a spend proof was rejected.
    let mismatched: Vec<_> = fork_ids.symmetric_difference(&new_ids).collect();
    assert!(
        mismatched.is_empty(),
        "the implementations disagree about which notes exist: {mismatched:#?}"
    );

    // `is_change` is the one place they deliberately differ. The fork marks a
    // note as change only when the receiving account also spent in the same
    // transaction. This wallet adds a second rule: a note received on the
    // account's *internal* address is change regardless, because that address
    // is never handed out.
    //
    // The addition is not cosmetic. Under descending recovery a change note is
    // scanned before the note that funded it, so the spend cannot be linked yet
    // and the fork's rule alone reports genuine change as an incoming payment.
    // The scope-based rule does not depend on scan order.
    for n in new {
        let f = fork.iter().find(|f| f.id == n.id).expect("identities match");
        let expected = f.is_change || n.id.scope == 1;
        assert_eq!(
            n.is_change, expected,
            "change differs beyond the known rule difference for {:?}",
            n.id
        );
    }
}

#[test]
fn both_implementations_find_the_same_notes() {
    let seed = [1u8; 32];
    let alice = orchard_fvk(&seed);
    let bob = fvk_from_seed(9);
    let mut rng = test_rng(77);
    let stranger_nf = zakura_wallet_scan::testing::random_nullifier(&mut rng);

    // Everything worth disagreeing about: notes in both pools, on both scopes,
    // somebody else's notes, padding, a spend of a note we do not hold, and
    // blocks with nothing in them at all.
    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 100_000);
            t.decoy(PoolId::Ironwood, 5);
        });
        b.tx(|t| {
            t.receive(PoolId::Orchard, &alice, KeyScope::External, 250_000);
            t.receive(PoolId::Orchard, &bob, KeyScope::External, 1);
        });
    });
    chain.empty_blocks(2);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::Internal, 42_000);
            t.decoy(PoolId::Orchard, 7);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            t.spend(PoolId::Ironwood, stranger_nf);
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 7_777);
        });
        b.tx(|t| {
            t.decoy(PoolId::Ironwood, 3);
            t.receive(PoolId::Orchard, &alice, KeyScope::Internal, 999);
        });
    });

    let anchor = chain.anchor();
    let blocks = chain.into_blocks();
    let (fork, new) = compare(&seed, &anchor, &blocks).expect("both stacks scan");

    assert_eq!(new.len(), 5, "five of the planted notes belong to Alice");
    assert_agreement(&fork, &new);
}

#[test]
fn both_implementations_agree_about_change_the_wallet_funded() {
    // The case where the fork's own rule fires: a transaction that spends a
    // note the wallet holds and pays some of it back. Both should call the
    // returned note change, by the same rule, so this checks the agreement
    // rather than the exception.
    let seed = [3u8; 32];
    let alice = orchard_fvk(&seed);

    // Learn the nullifier the way the wallet will. The builder is deterministic
    // for a given start height, so rebuilding reproduces this block exactly.
    let mut probe = ChainBuilder::new(START);
    probe.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 500_000);
        });
    });
    let funding_nf = detect_batch(
        &test_params(),
        &ScanKeys::from_accounts([(AccountId(1), alice.clone())]),
        &TransparentWatch::default(),
        &NullifierSnapshot::default(),
        &probe.anchor(),
        probe.blocks(),
    )
    .expect("the probe scan succeeds")
    .received_notes()
    .next()
    .expect("the planted note is found")
    .nullifier;

    let mut chain = ChainBuilder::new(START);
    chain.block(|b| {
        b.tx(|t| {
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 500_000);
        });
    });
    chain.block(|b| {
        b.tx(|t| {
            // Spend it, and pay change back to an *external* address, so the
            // only thing that can make this change is the spend itself.
            t.spend(PoolId::Ironwood, funding_nf);
            t.receive(PoolId::Ironwood, &alice, KeyScope::External, 400_000);
        });
    });

    let anchor = chain.anchor();
    let blocks = chain.into_blocks();
    let (fork, new) = compare(&seed, &anchor, &blocks).expect("both stacks scan");

    assert_eq!(new.len(), 2);
    assert_agreement(&fork, &new);

    // And both agree it is change, without the scope rule being involved.
    let change = new
        .iter()
        .find(|n| n.id.value == 400_000)
        .expect("the returned note is there");
    assert!(change.is_change, "a note returned by a spend we funded is change");
    assert_eq!(change.id.scope, 0, "it arrived on the external address");
    assert!(
        fork.iter().find(|f| f.id == change.id).unwrap().is_change,
        "the fork should agree, by its own rule"
    );
}

#[test]
fn both_implementations_agree_on_a_wallet_that_owns_nothing() {
    // The degenerate case still has to agree: a key that owns nothing must find
    // nothing, in both, over a chain that is far from empty.
    // The seed the comparison scans with; nothing in the chain pays to it.
    let seed = [200u8; 32];
    let someone_else = fvk_from_seed(201);

    let mut chain = ChainBuilder::new(START);
    for _ in 0..4 {
        chain.block(|b| {
            b.tx(|t| {
                t.receive(PoolId::Ironwood, &someone_else, KeyScope::External, 10);
                t.decoy(PoolId::Orchard, 20);
            });
        });
    }

    let anchor = chain.anchor();
    let blocks = chain.into_blocks();
    let (fork, new) = compare(&seed, &anchor, &blocks).expect("both stacks scan");

    assert!(fork.is_empty());
    assert!(new.is_empty());
}

/// One action in a generated chain.
#[derive(Debug, Clone, Copy)]
enum Plant {
    Ours(PoolId, KeyScope),
    Theirs(PoolId),
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

    /// The two implementations agree over arbitrary chains, not just the three
    /// written by hand.
    ///
    /// This is the check with the most reach in the whole suite: it compares
    /// this wallet's detection against an independent implementation of the
    /// same protocol, on inputs neither author chose.
    #[test]
    fn the_implementations_agree_over_arbitrary_chains(
        layout in proptest::collection::vec(
            proptest::collection::vec(
                proptest::collection::vec(
                    proptest::prelude::prop_oneof![
                        proptest::prelude::Just(Plant::Ours(PoolId::Orchard, KeyScope::External)),
                        proptest::prelude::Just(Plant::Ours(PoolId::Orchard, KeyScope::Internal)),
                        proptest::prelude::Just(Plant::Ours(PoolId::Ironwood, KeyScope::External)),
                        proptest::prelude::Just(Plant::Ours(PoolId::Ironwood, KeyScope::Internal)),
                        proptest::prelude::Just(Plant::Theirs(PoolId::Orchard)),
                        proptest::prelude::Just(Plant::Theirs(PoolId::Ironwood)),
                    ],
                    0..4,
                ),
                0..3,
            ),
            1..5,
        ),
        value in 1u64..1_000_000,
    ) {
        let seed = [5u8; 32];
        let alice = orchard_fvk(&seed);
        let stranger = fvk_from_seed(6);

        let mut chain = ChainBuilder::new(START);
        for block in &layout {
            chain.block(|b| {
                for tx in block {
                    b.tx(|t| {
                        for plant in tx {
                            match *plant {
                                Plant::Ours(pool, scope) => {
                                    t.receive(pool, &alice, scope, value);
                                }
                                Plant::Theirs(pool) => {
                                    t.receive(pool, &stranger, KeyScope::External, value);
                                }
                            }
                        }
                    });
                }
            });
        }

        let anchor = chain.anchor();
        let blocks = chain.into_blocks();
        let (fork, new) = compare(&seed, &anchor, &blocks).expect("both stacks scan");

        let expected = layout
            .iter()
            .flatten()
            .flatten()
            .filter(|p| matches!(p, Plant::Ours(..)))
            .count();
        proptest::prop_assert_eq!(new.len(), expected, "the new core missed a planted note");
        assert_agreement(&fork, &new);
    }
}
