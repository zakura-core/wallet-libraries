//! ZIP 317 fees, for the shielded-only transactions this wallet builds.
//!
//! The rule is `marginal_fee × max(grace_actions, logical_actions)`, where the
//! logical action count for a shielded-only transaction is the total number of
//! actions across both Orchard-family bundles. This wallet does not yet build
//! transparent inputs or outputs, so the transparent terms of the full rule are
//! absent rather than zero — when they arrive they change the count, not this
//! shape.

use zcash_protocol::value::Zatoshis;

/// The fee charged per logical action.
pub const MARGINAL_FEE: Zatoshis = Zatoshis::const_from_u64(5_000);

/// The number of logical actions charged for even when fewer are present.
pub const GRACE_ACTIONS: usize = 2;

/// Returns the fee for a transaction with the given action counts.
pub fn required(orchard_actions: usize, ironwood_actions: usize) -> Zatoshis {
    let logical = std::cmp::max(GRACE_ACTIONS, orchard_actions + ironwood_actions);
    (MARGINAL_FEE * logical).expect("a fee for a buildable action count fits in a Zatoshis")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_transactions_pay_the_grace_minimum() {
        // Below the grace count the fee does not fall further: a one-action
        // transaction costs the same as a two-action one.
        assert_eq!(required(0, 0), Zatoshis::const_from_u64(10_000));
        assert_eq!(required(1, 0), Zatoshis::const_from_u64(10_000));
        assert_eq!(required(2, 0), Zatoshis::const_from_u64(10_000));
    }

    #[test]
    fn larger_transactions_pay_per_action() {
        assert_eq!(required(3, 0), Zatoshis::const_from_u64(15_000));
        assert_eq!(required(0, 5), Zatoshis::const_from_u64(25_000));
    }

    #[test]
    fn actions_are_counted_across_both_pools() {
        // The two pools are separate bundles but one transaction, so their
        // actions are charged together.
        assert_eq!(required(2, 1), required(3, 0));
        assert_eq!(required(1, 2), required(0, 3));
    }
}
