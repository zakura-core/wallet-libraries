//! History completeness: what the wallet knows about one account's side of a transaction, and
//! what may still be missing.
//!
//! A history entry shows known activity honestly while discovery is incomplete. A missing output
//! or spend row does not mean the effect is absent, a missing fee is not zero, and a partial net
//! amount is not the transaction's final delta.

use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, consensus::BlockHeight, value::Zatoshis};

use super::{
    AccountMovement, AggregatePayment, PrivateTransparentDetail, TransactionMetadataEvidence,
};

/// Whether every effect of a transaction on an account within one pool is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectCompleteness {
    /// No owned output or spend in this pool can be missing.
    Complete,
    /// Public transparent discovery holds authority for this pool. The wallet treats its results
    /// as authoritative, but their completeness is not verified.
    PublicDiscovery,
    /// Discovery has not covered this transaction. Owned outputs or spends may be missing, so the
    /// known amounts are partial.
    Incomplete,
}

impl EffectCompleteness {
    /// Whether the known effects can be treated as final: complete, or authoritative under public
    /// discovery.
    pub fn is_settled(self) -> bool {
        match self {
            Self::Complete | Self::PublicDiscovery => true,
            Self::Incomplete => false,
        }
    }
}

/// An account's known effects within one pool of a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolEffect {
    /// The pool.
    pub pool: PoolType,
    /// The known value the account received in this pool, including change.
    pub received: Zatoshis,
    /// The known value of the account's outputs spent in this pool.
    pub spent: Zatoshis,
    /// Whether these amounts are all of the account's effects in this pool.
    pub completeness: EffectCompleteness,
}

/// Whether a transaction's payment details are known: its recipients, payment amounts, and
/// memos. [`EffectCompleteness`] covers the account's amounts in each pool instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DetailCompleteness {
    /// The wallet constructed and stored the transaction; or every effect is settled, every memo
    /// of the account's outputs has been retrieved, and either the account only received or the
    /// value it spent is accounted for by what it received back, its recorded outputs to others,
    /// and the fee. Stored transaction data alone does not suffice: outputs the wallet cannot
    /// decrypt are not recorded.
    Complete,
    /// Only discovered effects are known. Missing output rows do not mean there were no external
    /// payments, and a missing memo is not an empty one.
    Incomplete,
}

/// The fee of a transaction, as far as it concerns the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeState {
    /// The account spent funds in the transaction and paid its fee, which is recorded.
    Known(Zatoshis),
    /// The account spent funds in the transaction and the whole transaction's fee is exact, but
    /// the evidence does not establish the account's share of it: another party may have paid
    /// some or all of it. The account's movement includes whatever share it paid; no amount
    /// this history reports has the fee subtracted. Never a fee attributed to the account.
    Unattributed {
        /// The exact fee of the whole transaction, [`TransactionHistoryDetails::whole_fee`].
        whole: Zatoshis,
    },
    /// The account spent funds, or may have, and neither its fee nor the whole transaction's is
    /// established. Never zero.
    Unknown,
    /// The account provably spent nothing in the transaction, so it paid no fee.
    NotApplicable,
}

/// How the account's view of a transaction was established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HistoryClassification {
    /// The wallet created the transaction, so its local record states the intent. Creation
    /// evidence without stored construction details, such as an outbox, certifies no effect or
    /// detail by itself.
    LocalIntent,
    /// Reconstructed from discovered evidence that is settled in every pool, where the account
    /// only received or the value it spent is accounted for. A missing memo alone does not make a
    /// transaction provisional.
    Reconstructed,
    /// Reconstructed as a net movement only. Every effect is complete and the account's spent
    /// value equals its receipts plus the exact whole-transaction fee, so the account's movement
    /// is final; but the wallet lacks the full transaction, and no available evidence excludes
    /// another party's self-balanced shielded participation (a foreign shielded spend paying an
    /// equal foreign output that looks like padding). Whether the account's debit was the fee or
    /// a payment while the other party paid the fee is therefore not established. The fee is not
    /// attributed to the account and no aggregate payment is inferred. A privately recovered
    /// transparent-to-shielded self-transfer whose transparent inputs are all the account's is
    /// reported this way.
    NetReconstructed,
    /// Reconstructed from incomplete evidence. Later discovery or enhancement can change it; a
    /// provisional net debit is not a final payment amount.
    Provisional,
}

/// One output of a transaction: its pool and its index within that pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputRef {
    /// The pool.
    pub pool: PoolType,
    /// Its index within the pool's outputs (the action index for Orchard and Ironwood).
    pub index: u32,
}

/// The outputs one activity row counts, and their total value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityOutputs {
    /// The total value of [`Self::outputs`].
    pub amount: Zatoshis,
    /// The outputs, ordered by pool and index. A receipt of the row shows exactly these.
    pub outputs: Vec<OutputRef>,
}

/// The activity rows private recovery reconstructs for a transaction, for one account.
///
/// Derived from the entry's evidence and the account's outputs in the transaction, never from
/// txid display facts. A variant names the rows to show and the amounts and outputs they
/// count where recovered evidence, rather than the outputs the wallet can see, decides them.
/// Everything else stays the wallet's: shieldings, pool migrations, labels, the fee each row
/// shows, and grouping steps of one operation across transactions (a TEX funding step and its
/// payment, a swap). The rules are checked in this order; the first that applies decides.
///
/// A wallet classifies shieldings and Orchard-to-Ironwood moves itself, before it reads this
/// value, and ignores it for them. The rules do not recognize a shielding: one of the account's
/// own transparent funds into its shielded pools reads as [`Self::Outputs`] with its shielded
/// receipt as a received row, as an incoming payment would.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountActivity {
    /// The exact payment of a transparent-only debit the account alone funded, reconstructed
    /// from recovered metadata, with no visible output it sent. Its recipients are not known.
    /// One sent row.
    InferredPayment {
        /// The payment, excluding the fee.
        amount: Zatoshis,
    },
    /// A recovered transparent self-transfer with no visible output it sent: the exact
    /// payment outside the account is zero and the debit equals the whole fee, which is also
    /// the account's. One sent row whose amount is the fee.
    FeeOnly {
        /// The fee, which is the debit.
        fee: Zatoshis,
    },
    /// [`TransactionHistoryDetails::inferred_outgoing`], less the account's own internal and
    /// ephemeral transparent outputs, is zero and it received no other transparent output: a
    /// funding step with no row.
    HiddenFundingStep,
    /// [`TransactionHistoryDetails::inferred_outgoing`] with no visible output the account
    /// sent: a sent row of the outgoing value and, when the account received transparent
    /// outputs other than internal ones, a received row. Activity amounts under that field's
    /// funding convention, not payments.
    InferredOutgoing {
        /// The outgoing value less the account's internal and ephemeral transparent outputs, or
        /// the gross value when that leaves nothing positive.
        outgoing: Zatoshis,
        /// The received row, when there is one.
        received: Option<ActivityOutputs>,
        /// Whether the rows are final: every effect is settled, the transaction is mined, every
        /// owned transparent output's key scope is known, and the net outgoing value is
        /// positive and covers the transparent receipts.
        settled: bool,
    },
    /// A provisional debit with no visible output the account sent, known only as the
    /// account's balance movement less its attributed fee. One row; a zero amount has no
    /// destination to show.
    MovementDebit {
        /// The debit less [`FeeState::Known`], never negative.
        amount: Zatoshis,
    },
    /// The account's visible outputs, as private recovery links them: a sent row when it sent
    /// visible outputs (even of zero value), and a received row when it received a positive
    /// value, or zero-value outputs in a transaction that spent nothing or also has a sent row.
    /// An owned output no sent-note record links counts as sent only in a recovered
    /// self-transfer.
    Outputs {
        /// The sent row.
        sent: Option<ActivityOutputs>,
        /// The received row.
        received: Option<ActivityOutputs>,
    },
    /// None of the above: the wallet shows the transaction from its own records.
    Unknown,
}

/// One account's history view of one transaction, from one database read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionHistoryDetails {
    /// Display-only Enhance service assertion that the transaction contains transparent
    /// outputs. `None` means no assertion has been recovered. This transaction-wide fact
    /// can classify activity independently of payment-detail completeness; it does not
    /// establish recipients, output ownership, or account payment/fee attribution.
    pub has_transparent_outputs: Option<bool>,
    /// Whole-transaction facts, separate from the account-related fee.
    pub transaction_metadata: Option<TransactionMetadataEvidence>,
    /// The exact fee of the whole transaction, as far as the wallet's evidence establishes it:
    /// the stored fee (computed from the full transaction, recorded by local construction, or
    /// supplied by a validated Enhance PIR record) or the exact fee of qualified transparent
    /// metadata. `None` when neither establishes it or they disagree. Other funders may have
    /// shared it; the account's share is [`Self::fee`].
    pub whole_fee: Option<Zatoshis>,
    /// Aggregate outgoing amount with explicit completeness.
    pub aggregate_payment: AggregatePayment,
    /// Activity-only outgoing value of a transaction whose payment details cannot be recovered:
    /// the value of the account's spent shielded notes, less the shielded value returned to the
    /// account and the whole-transaction fee. Activity assumes this account funded the transaction
    /// and paid the whole fee unless recovered evidence identifies another contributor; possible
    /// unobserved contributors do not disable this default. It is inferred, not attributed,
    /// and may include outputs to the account's own transparent
    /// addresses, and it names no recipient. Present only for a mined transaction without full
    /// data for which Enhance asserted transparent outputs, whose shielded effects are complete,
    /// whose whole fee is known, and in which the account has no transparent spend, no recorded
    /// sent output, and no co-funding wallet account or transparent input in its evidence.
    /// Candidate ledgers and unqualified, suspended or differently placed spend observations
    /// do not veto the inference. Consumers may use the default for internal-output Activity
    /// grouping, but must not turn it into canonical sender or fee-payer attribution. It
    /// changes neither [`Self::aggregate_payment`], [`Self::payment_details`], [`Self::fee`],
    /// nor [`Self::classification`].
    pub inferred_outgoing: Option<Zatoshis>,
    /// Known account movement and whether every effect is established.
    pub account_movement: AccountMovement,
    /// The transaction.
    pub txid: TxId,
    /// The accepted-chain height the transaction is mined at, if any. This placement is
    /// independent of the completeness of the payment details.
    pub mined_height: Option<BlockHeight>,
    /// One entry for every pool this build supports, including pools without known effects.
    pub effects: Vec<PoolEffect>,
    /// Whether the transaction's recipients, payment amounts, and memos are known.
    pub payment_details: DetailCompleteness,
    /// The fee, as far as it concerns the account.
    pub fee: FeeState,
    /// How the account's view was established.
    pub classification: HistoryClassification,
    /// The activity rows private recovery reconstructs for the transaction.
    pub activity: AccountActivity,
    /// Transparent follow-on details for this transaction that the current policy withholds from
    /// public retrieval.
    pub pending_private_details: Vec<PrivateTransparentDetail>,
}
