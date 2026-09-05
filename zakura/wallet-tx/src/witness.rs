//! Turning stored notes into spendable ones, with witnesses.

use std::collections::BTreeMap;

use incrementalmerkletree::Position;
use orchard::{
    Anchor,
    keys::{Diversifier, FullViewingKey, Scope},
    note::{Note, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use zakura_wallet_core::{AccountId, KeyScope, pool::PoolId};
use zakura_wallet_store::WalletDb;
use zcash_protocol::consensus::BlockHeight;

use crate::{Error, SpendableNote};

/// The anchor each pool's bundle will be proved against.
///
/// Both come from the same block. A transaction whose two bundles were anchored
/// at different heights would be claiming two different views of the chain.
#[derive(Debug, Clone, Copy)]
pub struct Anchors {
    /// The height both anchors describe.
    pub height: BlockHeight,
    /// The Orchard tree root at that height.
    pub orchard: Anchor,
    /// The Ironwood tree root at that height.
    pub ironwood: Anchor,
}

/// Returns the anchors to prove against, at the most recent height both trees
/// hold a checkpoint for.
pub fn anchors(db: &mut WalletDb) -> Result<Anchors, Error> {
    let height = db.common_anchor_height()?.ok_or(Error::NoAnchor)?;

    let mut roots = BTreeMap::new();
    for pool in PoolId::ALL {
        let root = db
            .with_tree_for(pool, |tree| Ok(tree.root_at_checkpoint_id(&height)?))?
            .ok_or(Error::NoAnchor)?;
        roots.insert(pool, Anchor::from(root));
    }

    Ok(Anchors {
        height,
        orchard: roots[&PoolId::Orchard],
        ironwood: roots[&PoolId::Ironwood],
    })
}

/// Returns the notes `account` can spend, each with the witness that proves it.
///
/// A note without a witness at the anchor is dropped rather than reported: it
/// is held but not yet spendable, which is a wait rather than an error. Asking
/// for it by name — through selection — is what produces
/// [`Error::NoWitness`].
pub fn spendable_notes(
    db: &mut WalletDb,
    account: AccountId,
    fvk: &FullViewingKey,
    anchors: &Anchors,
    require_stable: bool,
) -> Result<Vec<(SpendableNote, MerklePath)>, Error> {
    let stored = db.spendable_notes(account, require_stable)?;

    let mut out = Vec::new();
    for note in stored {
        let path = db.with_tree_for(note.pool, |tree| {
            Ok(tree.witness_at_checkpoint_id(note.position, &anchors.height)?)
        })?;

        let Some(path) = path else { continue };

        let Some(reconstructed) = reconstruct(&note, fvk) else {
            // A note whose stored parts no longer form a valid note is a
            // corrupt row, not an unspendable one. Skipping it silently would
            // present the wallet as poorer than it is, so it is surfaced.
            return Err(Error::Build(format!(
                "the note at position {} could not be reconstructed from storage",
                u64::from(note.position)
            )));
        };

        out.push((
            SpendableNote {
                pool: note.pool,
                account: note.account,
                scope: note.scope,
                note: reconstructed,
                position: note.position,
            },
            merkle_path(note.position, path),
        ));
    }

    Ok(out)
}

/// Rebuilds a note from the parts the database holds.
///
/// The database stores a note's diversifier rather than its whole address,
/// because the rest of the address is derivable: an address is a diversifier
/// plus a transmission key, and the transmission key follows from the owning
/// account's viewing key. Storing the derivable half would be storing the same
/// fact twice.
fn reconstruct(stored: &zakura_wallet_store::StoredNote, fvk: &FullViewingKey) -> Option<Note> {
    let recipient = fvk.address(
        Diversifier::from_bytes(stored.diversifier),
        match stored.scope {
            KeyScope::External => Scope::External,
            KeyScope::Internal => Scope::Internal,
        },
    );

    let rho = Option::from(Rho::from_bytes(&stored.rho))?;
    let rseed = Option::from(RandomSeed::from_bytes(stored.rseed, &rho))?;
    let version = match stored.note_version {
        0x02 => NoteVersion::V2,
        0x03 => NoteVersion::V3,
        _ => return None,
    };

    Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(stored.value),
        rho,
        rseed,
        version,
    ))
}

/// Converts a shardtree path into the one the bundle builder wants.
fn merkle_path(
    position: Position,
    path: incrementalmerkletree::MerklePath<MerkleHashOrchard, 32>,
) -> MerklePath {
    let auth: [MerkleHashOrchard; 32] = path
        .path_elems()
        .try_into()
        .expect("an Orchard-family witness has one sibling per level");
    MerklePath::from_parts(
        u32::try_from(u64::from(position)).expect("a note position fits in a u32"),
        auth,
    )
}
