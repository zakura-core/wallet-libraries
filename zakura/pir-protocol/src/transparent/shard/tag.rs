//! Salted script tags for private directory and page records.
//!
//! A tag is the first 14 bytes of a domain-separated SHA-256 of the complete
//! raw script, under a salt the revision's transactions cannot have predicted.
//! Placement and the choice table stay keyed on the raw script. The tag is
//! what a row stores and what a wallet compares.

use crate::transparent::filter::BlockHash;

/// Domain for the per-revision salt. The trailing NUL keeps this input from
/// being a prefix of another SHA-256 use.
pub const TAG_SALT_DOMAIN: &[u8] = b"transparent-shard-tag-salt-v1\0";

/// Domain for a page shard's salt.
pub const PAGE_TAG_SALT_DOMAIN: &[u8] = b"transparent-shard-page-tag-salt-v1\0";

/// Domain for the script tag itself.
pub const SCRIPT_TAG_DOMAIN: &[u8] = b"transparent-shard-script-tag-v2\0";

/// Bytes stored in place of a raw script.
pub const SCRIPT_TAG_BYTES: usize = crate::directory::tag::TAG_BYTES;

/// Counters tried before publication fails.
///
/// An honest shard collides with probability far below anything this limit
/// can see. The counter exists so a collision rebuilds the tags instead of
/// failing the shard or dropping a script.
pub const MAX_TAG_SALT_COUNTER: u32 = 8;

/// The salt for one revision.
///
/// `terminal` is the block at the revision's end, in internal byte order.
/// The wallet recomputes this from the manifest and never accepts a salt
/// supplied separately.
pub fn tag_salt(shard_id: u64, terminal: &BlockHash, counter: u32) -> [u8; 32] {
    let parts: [&[u8]; 3] = [
        &shard_id.to_le_bytes(),
        terminal.internal_bytes(),
        &counter.to_le_bytes(),
    ];
    crate::directory::tag::salt(TAG_SALT_DOMAIN, &parts)
}

/// The salt for one page shard of a directory shard.
///
/// Keyed on the page shard's own end height and terminal block rather than
/// the directory shard's: while the directory shard is open its terminal moves
/// every block, and salting children with it would re-tag page shards that
/// have already sealed and must never change. The wallet recomputes this from
/// the manifest's child entry.
pub fn page_tag_salt(
    shard_id: u64,
    child: u32,
    end_height: u64,
    terminal: &BlockHash,
    counter: u32,
) -> [u8; 32] {
    let parts: [&[u8]; 5] = [
        &shard_id.to_le_bytes(),
        &child.to_le_bytes(),
        &end_height.to_le_bytes(),
        terminal.internal_bytes(),
        &counter.to_le_bytes(),
    ];
    crate::directory::tag::salt(PAGE_TAG_SALT_DOMAIN, &parts)
}

/// The 14-byte tag of one raw script under `salt`.
pub fn script_tag(salt: &[u8; 32], script: &[u8]) -> [u8; SCRIPT_TAG_BYTES] {
    crate::directory::tag::tag(SCRIPT_TAG_DOMAIN, salt, script)
}

/// The counter whose tags are unique, and the salt at that counter.
///
/// `tag_of` is `script_tag` in production. Tests pass a function that
/// collides on the first salt so the counter has to move. On a collision
/// every tag is recomputed; no script is dropped.
pub fn resolve_tag_salt(
    shard_id: u64,
    terminal: &BlockHash,
    scripts: &[&[u8]],
    tag_of: impl FnMut(&[u8; 32], &[u8]) -> [u8; SCRIPT_TAG_BYTES],
) -> Result<(u32, [u8; 32]), String> {
    resolve_salt(
        shard_id,
        |counter| tag_salt(shard_id, terminal, counter),
        scripts,
        tag_of,
    )
}

/// [`resolve_tag_salt`] for one page shard, under [`page_tag_salt`].
pub fn resolve_page_tag_salt(
    shard_id: u64,
    child: u32,
    end_height: u64,
    terminal: &BlockHash,
    scripts: &[&[u8]],
    tag_of: impl FnMut(&[u8; 32], &[u8]) -> [u8; SCRIPT_TAG_BYTES],
) -> Result<(u32, [u8; 32]), String> {
    resolve_salt(
        shard_id,
        |counter| page_tag_salt(shard_id, child, end_height, terminal, counter),
        scripts,
        tag_of,
    )
}

fn resolve_salt(
    shard_id: u64,
    salt_at: impl Fn(u32) -> [u8; 32],
    scripts: &[&[u8]],
    tag_of: impl FnMut(&[u8; 32], &[u8]) -> [u8; SCRIPT_TAG_BYTES],
) -> Result<(u32, [u8; 32]), String> {
    crate::directory::tag::resolve_salt(0..=MAX_TAG_SALT_COUNTER, salt_at, scripts, tag_of)
        .ok_or_else(|| {
            format!("tag salt counter exceeded {MAX_TAG_SALT_COUNTER} for shard {shard_id}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal(byte: u8) -> BlockHash {
        BlockHash::from_internal_bytes([byte; 32])
    }

    #[test]
    fn the_salt_moves_with_the_terminal_block_and_the_counter() {
        let base = tag_salt(3, &terminal(1), 0);
        assert_ne!(tag_salt(3, &terminal(2), 0), base);
        assert_ne!(tag_salt(3, &terminal(1), 1), base);
        assert_ne!(tag_salt(4, &terminal(1), 0), base);
        assert_eq!(tag_salt(3, &terminal(1), 0), base);
    }

    /// A page shard's salt depends on its own identity, not its directory
    /// shard's terminal, and is distinct from the directory's salt.
    #[test]
    fn a_page_shard_salt_moves_with_the_page_shard_alone() {
        let base = page_tag_salt(3, 1, 500, &terminal(1), 0);
        assert_ne!(page_tag_salt(3, 2, 500, &terminal(1), 0), base);
        assert_ne!(page_tag_salt(3, 1, 501, &terminal(1), 0), base);
        assert_ne!(page_tag_salt(3, 1, 500, &terminal(2), 0), base);
        assert_ne!(page_tag_salt(3, 1, 500, &terminal(1), 1), base);
        assert_ne!(page_tag_salt(4, 1, 500, &terminal(1), 0), base);
        assert_ne!(tag_salt(3, &terminal(1), 0), base);
        let (counter, salt) =
            resolve_page_tag_salt(3, 1, 500, &terminal(1), &[b"a", b"b"], script_tag).unwrap();
        assert_eq!((counter, salt), (0, base));
    }

    #[test]
    fn a_tag_is_not_a_prefix_of_the_script() {
        let script = b"\x76\xa9identical-prefix-bytes!!";
        let tag = script_tag(&tag_salt(1, &terminal(9), 0), script);
        assert_ne!(&tag[..], &script[..SCRIPT_TAG_BYTES]);
        assert_eq!(tag.len(), SCRIPT_TAG_BYTES);
    }

    #[test]
    fn a_forced_collision_increments_the_counter_and_keeps_every_script() {
        let terminal = terminal(4);
        let scripts: [&[u8]; 2] = [b"one", b"two"];
        let (counter, salt) = resolve_tag_salt(1, &terminal, &scripts, |salt, script| {
            if salt == &tag_salt(1, &terminal, 0) {
                [9u8; SCRIPT_TAG_BYTES]
            } else {
                script_tag(salt, script)
            }
        })
        .unwrap();
        assert_eq!(counter, 1);
        let tags = [script_tag(&salt, scripts[0]), script_tag(&salt, scripts[1])];
        assert_ne!(tags[0], tags[1]);
    }

    #[test]
    fn a_tag_from_another_salt_is_not_the_one_the_wallet_derives() {
        let script = b"\x76\xa9wallet-script";
        let hash = terminal(7);
        let wallet = script_tag(&tag_salt(9, &hash, 0), script);
        let foreign = script_tag(&tag_salt(9, &hash, 1), script);
        assert_ne!(wallet, foreign);
    }

    /// A resolver whose tags collide under every counter below `last`.
    fn collide_below(
        last: u32,
        salt_at: impl Fn(u32) -> [u8; 32],
    ) -> impl FnMut(&[u8; 32], &[u8]) -> [u8; SCRIPT_TAG_BYTES] {
        move |salt, script| {
            if (0..last).any(|counter| *salt == salt_at(counter)) {
                [0; SCRIPT_TAG_BYTES]
            } else {
                script_tag(salt, script)
            }
        }
    }

    /// Salts and a tag at nonzero counters, pinned at the commit before tag
    /// resolution was shared, then success at the last counter and
    /// exhaustion after it, for directory and page salts.
    #[test]
    fn nonzero_counters_match_the_pinned_bytes() {
        let hash = terminal(5);
        let last_salt = tag_salt(3, &hash, MAX_TAG_SALT_COUNTER);
        let pinned = [
            hex::encode(tag_salt(3, &hash, 1)),
            hex::encode(last_salt),
            hex::encode(page_tag_salt(3, 2, 700, &hash, 1)),
            hex::encode(page_tag_salt(3, 2, 700, &hash, MAX_TAG_SALT_COUNTER)),
            hex::encode(script_tag(&last_salt, b"\x76\xa9pinned")),
        ];
        assert_eq!(
            pinned,
            [
                "b5470d910aa9312842563e986aaf9b0845b320dee382e8f42d0919bf8a09da82",
                "5dc2ed6f7fb122cad44e2d742de0fcf226526d4e02b31a7a9544384770dcdc7a",
                "716ca18209b5c30b6c6b817d2e82cd49d0c24401ce6aebef19b48bb3dcba5ae7",
                "9165c85112b4bfdcdd16ef6afae9976383c06da3db61add967d0686304c2a424",
                "b6e5123d22ec57c860a1897b7ba1",
            ]
        );

        let scripts: [&[u8]; 2] = [b"one", b"two"];
        let directory = |counter| tag_salt(3, &hash, counter);
        let page = |counter| page_tag_salt(3, 2, 700, &hash, counter);
        let last = MAX_TAG_SALT_COUNTER;
        assert_eq!(
            resolve_tag_salt(3, &hash, &scripts, collide_below(last, directory)),
            Ok((last, directory(last)))
        );
        assert_eq!(
            resolve_page_tag_salt(3, 2, 700, &hash, &scripts, collide_below(last, page)),
            Ok((last, page(last)))
        );
        let exhausted = Err(format!("tag salt counter exceeded {last} for shard 3"));
        assert_eq!(
            resolve_tag_salt(3, &hash, &scripts, collide_below(last + 1, directory)),
            exhausted
        );
        assert_eq!(
            resolve_page_tag_salt(3, 2, 700, &hash, &scripts, collide_below(last + 1, page)),
            exhausted
        );
    }
}
