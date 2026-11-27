use core::num::NonZeroU32;

use transparent_pq_keys::KeyOrigin;

/// A contiguous run of child indices on one branch that the pool still needs.
///
/// Produced by the pool, never past index `u32::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRange {
    first: KeyOrigin,
    count: NonZeroU32,
}

impl KeyRange {
    pub(crate) fn new(first: KeyOrigin, count: NonZeroU32) -> Self {
        debug_assert!(u64::from(first.index()) + u64::from(count.get()) <= 1 << 32);
        Self { first, count }
    }

    /// The origin of the first missing key.
    pub fn first(self) -> KeyOrigin {
        self.first
    }

    /// The number of missing keys.
    pub fn count(self) -> NonZeroU32 {
        self.count
    }

    /// Every origin in the range, in index order.
    pub fn origins(self) -> impl Iterator<Item = KeyOrigin> {
        let first = self.first;
        (0..self.count.get()).map(move |offset| {
            KeyOrigin::new(
                first.parameters(),
                first.network(),
                first.account(),
                first.branch(),
                first.index() + offset,
            )
        })
    }
}
