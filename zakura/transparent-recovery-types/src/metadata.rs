use zcash_protocol::value::Zatoshis;

/// Fee for the entire transaction, independent of its attribution to an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WholeTransactionFee {
    /// All necessary inputs and pool balances establish the exact fee.
    Exact(Zatoshis),
    /// The observation cannot establish the fee. This is never zero by default.
    Unknown,
    /// Coinbase transactions have no applicable fee.
    NotApplicable,
}

/// Facts repeated on every event belonging to a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionMetadata {
    /// The whole-transaction fee.
    pub fee: WholeTransactionFee,
    /// All non-coinbase transparent inputs, including those owned by other accounts.
    pub transparent_input_count: u32,
    /// Whether any Sprout, Sapling, Orchard or Ironwood component is present.
    pub has_shielded_components: bool,
}

impl TransactionMetadata {
    /// Whether the assertions agree with the independently recovered coinbase classification.
    pub fn is_valid_for(self, coinbase: bool) -> bool {
        coinbase == matches!(self.fee, WholeTransactionFee::NotApplicable)
            && (!coinbase || self.transparent_input_count == 0)
    }
}
