//! Matching a wallet's scripts against an experimental parent filter; see
//! [`zakura_transparent_private_shared::filter::experimental_parent`].

use zakura_transparent_private_shared::filter::experimental_parent::Parent;
use zakura_transparent_private_shared::filter::{FilterError, ScriptBytes, ValidatedFilter};

/// Matching against a [`Parent`]'s validated filter.
pub trait ParentMatch {
    /// Whether any of `scripts` is in `filter`, the parent's validated filter.
    fn matches(&self, filter: &ValidatedFilter, scripts: &[Vec<u8>]) -> Result<bool, FilterError>;
}

impl ParentMatch for Parent {
    fn matches(&self, filter: &ValidatedFilter, scripts: &[Vec<u8>]) -> Result<bool, FilterError> {
        let owned: Vec<_> = scripts.iter().cloned().map(ScriptBytes::new).collect();
        Ok(
            crate::filter::matching::map_wallet_scripts_keyed(filter, self.keys()?, &owned)
                .iter()
                .any(|(v, _)| filter.values().binary_search(v).is_ok()),
        )
    }
}
