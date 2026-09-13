//! ZIP 317 fees.
//!
//! The rule is `marginal_fee × max(grace_actions, logical_actions)`, where the
//! logical actions are the shielded actions plus a transparent term.
//!
//! The transparent term is the subtle part, and it is why this module deals in
//! *byte totals* rather than input counts. ZIP 317 charges
//! `ceil(total_input_bytes / 150)`, which is not the same as the sum of each
//! input's own ceiling — two inputs cost one action's worth more than one only
//! when their combined size crosses the boundary. A count cannot express that.

use zcash_protocol::value::Zatoshis;

/// The fee charged per logical action.
pub const MARGINAL_FEE: Zatoshis = Zatoshis::const_from_u64(5_000);

/// The number of logical actions charged for even when fewer are present.
pub const GRACE_ACTIONS: usize = 2;

/// The size ZIP 317 charges for a P2PKH input, whatever its true length.
///
/// A real P2PKH input serialises one byte shorter than this. The standard size
/// is used anyway, and must be used by *both* the fee estimate and the builder:
/// if they disagree, a transaction with enough inputs to cross a
/// `ceil(bytes / 150)` boundary is proposed at one fee and built expecting
/// another, and fails as unbalanced after the proving is already paid for.
pub const P2PKH_STANDARD_INPUT_SIZE: usize = 150;

/// The size ZIP 317 charges for a P2PKH output.
pub const P2PKH_STANDARD_OUTPUT_SIZE: usize = 34;

/// The transparent size of a transaction, in bytes.
///
/// Byte totals rather than counts, because the ZIP 317 transparent term divides
/// the total and not each input. Constructed only through
/// [`TransparentSizes::p2pkh`], so there is exactly one place a transparent
/// input's size is decided and no way for two callers to decide differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransparentSizes {
    in_bytes: usize,
    out_bytes: usize,
}

impl TransparentSizes {
    /// No transparent parts at all.
    pub const EMPTY: Self = Self {
        in_bytes: 0,
        out_bytes: 0,
    };

    /// The sizes for a transaction with this many standard P2PKH inputs and
    /// outputs.
    pub fn p2pkh(inputs: usize, outputs: usize) -> Self {
        Self {
            in_bytes: inputs * P2PKH_STANDARD_INPUT_SIZE,
            out_bytes: outputs * P2PKH_STANDARD_OUTPUT_SIZE,
        }
    }

    /// The transparent contribution to the logical action count.
    fn logical_actions(&self) -> usize {
        std::cmp::max(
            self.in_bytes.div_ceil(P2PKH_STANDARD_INPUT_SIZE),
            self.out_bytes.div_ceil(P2PKH_STANDARD_OUTPUT_SIZE),
        )
    }
}

/// Returns the fee for a transaction with the given shielded action counts and
/// transparent size.
pub fn required_with(
    transparent: TransparentSizes,
    orchard_actions: usize,
    ironwood_actions: usize,
) -> Zatoshis {
    let logical = std::cmp::max(
        GRACE_ACTIONS,
        transparent.logical_actions() + orchard_actions + ironwood_actions,
    );
    (MARGINAL_FEE * logical).expect("a fee for a buildable action count fits in a Zatoshis")
}

/// Returns the fee for a transaction with no transparent parts.
pub fn required(orchard_actions: usize, ironwood_actions: usize) -> Zatoshis {
    required_with(TransparentSizes::EMPTY, orchard_actions, ironwood_actions)
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
    fn the_transparent_term_divides_the_total_not_each_input() {
        // The reason this module deals in byte totals. Each input is charged
        // 150 bytes, so three of them are exactly three actions — but the
        // division happens once, over the sum, and a version that took the
        // ceiling per input would agree here and diverge as soon as anything
        // is not a whole multiple.
        let three = TransparentSizes::p2pkh(3, 0);
        assert_eq!(three.logical_actions(), 3);

        // Outputs are counted the same way, and the transparent term is the
        // larger of the two sides rather than their sum.
        let mixed = TransparentSizes {
            in_bytes: 150,
            out_bytes: 34 * 5,
        };
        assert_eq!(mixed.logical_actions(), 5);
    }

    #[test]
    fn a_shielded_only_fee_is_unchanged_by_the_transparent_term() {
        // The existing shape must not move: `crossing::canonical_fee` depends
        // on it, and a crossing whose fee differs from everybody else's is a
        // crossing that identifies its sender.
        for orchard in 0..6 {
            for ironwood in 0..6 {
                assert_eq!(
                    required(orchard, ironwood),
                    required_with(TransparentSizes::EMPTY, orchard, ironwood),
                );
            }
        }
    }

    #[test]
    fn transparent_inputs_add_to_the_shielded_actions() {
        // One transparent input plus two Ironwood actions is three logical
        // actions, not two.
        assert_eq!(
            required_with(TransparentSizes::p2pkh(1, 0), 0, 2),
            Zatoshis::const_from_u64(15_000)
        );
    }

    #[test]
    fn actions_are_counted_across_both_pools() {
        // The two pools are separate bundles but one transaction, so their
        // actions are charged together.
        assert_eq!(required(2, 1), required(3, 0));
        assert_eq!(required(1, 2), required(0, 3));
    }
}
