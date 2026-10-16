//! Choosing the salt counter under which a revision's script tags are unique;
//! see [`zakura_transparent_private_shared::shard::tag`].

use zakura_transparent_private_shared::filter::BlockHash;
use zakura_transparent_private_shared::shard::tag::{
    page_tag_salt, tag_salt, MAX_TAG_SALT_COUNTER, SCRIPT_TAG_BYTES,
};

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
    mut tag_of: impl FnMut(&[u8; 32], &[u8]) -> [u8; SCRIPT_TAG_BYTES],
) -> Result<(u32, [u8; 32]), String> {
    for counter in 0..=MAX_TAG_SALT_COUNTER {
        let salt = salt_at(counter);
        let mut seen = std::collections::HashSet::with_capacity(scripts.len());
        let mut collision = false;
        for script in scripts {
            if !seen.insert(tag_of(&salt, script)) {
                collision = true;
                break;
            }
        }
        if !collision {
            return Ok((counter, salt));
        }
    }
    Err(format!(
        "tag salt counter exceeded {MAX_TAG_SALT_COUNTER} for shard {shard_id}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_transparent_private_shared::shard::tag::script_tag;

    fn terminal(byte: u8) -> BlockHash {
        BlockHash::from_internal_bytes([byte; 32])
    }

    #[test]
    fn a_page_shard_resolves_at_its_first_counter() {
        let base = page_tag_salt(3, 1, 500, &terminal(1), 0);
        let (counter, salt) =
            resolve_page_tag_salt(3, 1, 500, &terminal(1), &[b"a", b"b"], script_tag).unwrap();
        assert_eq!((counter, salt), (0, base));
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
}
