use core::convert::Infallible;
use core::fmt;

use transparent::address::{Script, TransparentAddress};
use transparent::bundle::{OutPoint, TxOut};
use transparent_pq_keys::{Branch, KeyOrigin, ParameterSet, PublicKey};
use transparent_pq_pool::{AccountPool, Issued};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::output::{self, PqDestination};
use crate::transaction::{self, Header, UnsignedTransaction, VerifyError};
use crate::{PqSigner, SigningRequest};

/// Blocks after the target height at which an unmined transaction expires (ZIP 203).
const EXPIRY_DELTA: u32 = 40;

/// A PQ output the wallet can spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqUtxo {
    /// The output being spent.
    pub outpoint: OutPoint,
    /// Its value.
    pub value: Zatoshis,
    /// The key that controls it.
    pub origin: KeyOrigin,
    /// That key's public key, which determines the output script.
    pub public_key: PublicKey,
}

/// Where a payment goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recipient {
    /// A legacy transparent address.
    Transparent(TransparentAddress),
    /// A post-quantum commitment, as published by a PQ receiver. Read one from an address
    /// with [`crate::pq_recipient`].
    Pq {
        /// The parameter set the receiver's scheme names.
        parameters: ParameterSet,
        /// The commitment the receiver publishes.
        commitment: [u8; 32],
    },
}

impl Recipient {
    /// The output script that pays this recipient.
    pub fn script(&self) -> Script {
        match self {
            Self::Transparent(address) => address.script().into(),
            Self::Pq {
                parameters,
                commitment,
            } => output::output_script(*parameters, commitment),
        }
    }
}

/// An amount paid to a recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    /// The recipient.
    pub recipient: Recipient,
    /// The amount.
    pub value: Zatoshis,
}

/// A signed transaction ready to broadcast.
#[derive(Debug)]
pub struct SignedSpend {
    /// The transaction.
    pub transaction: Transaction,
    /// The fee it pays.
    pub fee: Zatoshis,
    /// The fresh change key it pays, if change was worth keeping.
    pub change: Option<Issued>,
    /// Every output the transaction spends, in input order, for [`crate::verify_inputs`].
    pub spent: Vec<TxOut>,
}

/// Why a spend could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum SpendError<E> {
    /// No inputs were supplied.
    NoInputs,
    /// The inputs do not cover the payments and the fee.
    InsufficientFunds {
        /// Total input value.
        available: Zatoshis,
        /// Payments plus the fee without change.
        required: Zatoshis,
    },
    /// An input's public key does not match its origin's parameter set.
    KeyMismatch(usize),
    /// The PQ rules are not in force at the target height, so a PQ output created there
    /// would be spendable by anyone until they are.
    NotActivated {
        /// The height the spend targets.
        target_height: BlockHeight,
        /// The height the PQ rules start applying at.
        activation: BlockHeight,
    },
    /// An amount overflowed.
    Overflow,
    /// The change pool refused to issue a key or to take the signer's refill.
    Pool(transparent_pq_pool::Error),
    /// The signer returned no key for the next change index. Change never goes to a
    /// key that was handed out before.
    ChangeKeyNotDerived,
    /// The signer refused or failed.
    Signer(E),
    /// The signer returned a different number of signatures than inputs.
    SignatureCount {
        /// Inputs in the transaction.
        expected: usize,
        /// Signatures returned.
        actual: usize,
    },
    /// A signed input failed verification.
    Verification(VerifyError),
    /// The finished transaction pays a different fee than was computed.
    FeeChanged,
    /// The transaction could not be serialized.
    Encoding(std::io::Error),
}

impl<E: fmt::Display> fmt::Display for SpendError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => f.write_str("no inputs to spend"),
            Self::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "inputs hold {} zatoshis but {} are required",
                u64::from(*available),
                u64::from(*required)
            ),
            Self::KeyMismatch(index) => {
                write!(f, "input {index}'s public key does not match its origin")
            }
            Self::NotActivated {
                target_height,
                activation,
            } => write!(
                f,
                "the PQ rules start at height {} and this spend targets {}",
                u32::from(*activation),
                u32::from(*target_height)
            ),
            Self::Overflow => f.write_str("amount overflow"),
            Self::Pool(error) => write!(f, "change pool: {error}"),
            Self::ChangeKeyNotDerived => f.write_str("the signer did not derive a change key"),
            Self::Signer(error) => write!(f, "signer: {error}"),
            Self::SignatureCount { expected, actual } => {
                write!(
                    f,
                    "signer returned {actual} signatures for {expected} inputs"
                )
            }
            Self::Verification(error) => write!(f, "{error}"),
            Self::FeeChanged => f.write_str("signed transaction size changed its fee"),
            Self::Encoding(error) => write!(f, "encoding: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for SpendError<E> {}

/// Spends `inputs` to `payments`, sending what remains to a fresh change key.
///
/// Change goes to a change key from `change_pool` that was never handed out before, and
/// is skipped when it would be dust. When the pool has no derived change key left, the
/// signer derives the missing ones first in a separate call. The pool also receives
/// the keys the signer returns for its refill ranges, which include the next change
/// key, so that separate call is needed only while the change branch is empty. Save the pool's state before
/// broadcasting. The fee uses Zakura's byte and verification-work policy.
///
/// `pq_activation` is the height the PQ rules start applying at, which the node reads as
/// `network.params.pq_activation_height`. Below it a PQ output is claimable by an empty
/// scriptSig, so this refuses to build the spend rather than create one.
pub fn build_spend<P: Parameters, S: PqSigner>(
    params: &P,
    target_height: BlockHeight,
    pq_activation: BlockHeight,
    inputs: &[PqUtxo],
    payments: &[Payment],
    change_pool: &mut AccountPool,
    signer: &mut S,
) -> Result<SignedSpend, SpendError<S::Error>> {
    if inputs.is_empty() {
        return Err(SpendError::NoInputs);
    }
    if target_height < pq_activation {
        return Err(SpendError::NotActivated {
            target_height,
            activation: pq_activation,
        });
    }
    let scripts = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            if input.public_key.parameters() != input.origin.parameters() {
                return Err(SpendError::KeyMismatch(index));
            }
            Ok(PqDestination::single_signer(&input.public_key))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let input_sizes: Vec<InputCharge> = scripts.iter().map(InputCharge::for_destination).collect();
    let available = sum(inputs.iter().map(|input| input.value))?;
    let change_parameters = change_pool.state().parameters;
    let quote = price(
        params,
        target_height,
        change_parameters,
        &input_sizes,
        available,
        payments,
    )?;
    let mut outputs: Vec<TxOut> = payments
        .iter()
        .map(|payment| TxOut::new(payment.value, payment.recipient.script()))
        .collect();

    let change = match quote.change {
        Some(value) => {
            let issued = issue_change(change_pool, signer)?;
            let script = PqDestination::single_signer(&issued.public_key).script_pubkey();
            outputs.push(TxOut::new(value, script));
            Some(issued)
        }
        None => None,
    };
    let fee = quote.fee;

    let header = Header {
        version: TxVersion::V5,
        branch_id: BranchId::for_height(params, target_height),
        expiry_height: target_height + EXPIRY_DELTA,
    };
    let spent: Vec<TxOut> = scripts
        .iter()
        .zip(inputs)
        .map(|(destination, input)| TxOut::new(input.value, destination.script_pubkey()))
        .collect();
    let unsigned = UnsignedTransaction::new(transaction::assemble(
        header,
        inputs
            .iter()
            .map(|input| (input.outpoint.clone(), Script::default()))
            .collect(),
        outputs,
        spent.clone(),
    ));

    let change_output = change
        .as_ref()
        .map(|issued| (unsigned.outputs().len() - 1, issued.origin));
    let request = SigningRequest {
        transaction: &unsigned,
        input_keys: inputs.iter().map(|input| input.origin).collect(),
        change: change_output.into_iter().collect(),
        replenish: [Branch::Receive, Branch::Change]
            .into_iter()
            .filter_map(|branch| change_pool.replenish_request(branch))
            .collect(),
    };
    let response = signer.sign(&request).map_err(SpendError::Signer)?;
    if response.signatures.len() != inputs.len() {
        return Err(SpendError::SignatureCount {
            expected: inputs.len(),
            actual: response.signatures.len(),
        });
    }
    change_pool
        .apply_batch(&response.public_keys)
        .map_err(SpendError::Pool)?;

    let script_sigs = response
        .signatures
        .iter()
        .zip(&scripts)
        .map(|(signature, destination)| transaction::script_sig(signature, destination))
        .collect::<Vec<_>>();
    if script_sigs
        .iter()
        .zip(&input_sizes)
        .any(|(script_sig, &size)| txin_size(script_sig) != size.bytes)
    {
        return Err(SpendError::FeeChanged);
    }
    let signed = transaction::with_script_sigs(unsigned.data, script_sigs);
    transaction::verify_data(params.network_type(), &signed).map_err(SpendError::Verification)?;
    let transaction = transaction::freeze(signed).map_err(SpendError::Encoding)?;
    Ok(SignedSpend {
        transaction,
        fee,
        change,
        spent,
    })
}

/// What a spend will cost, worked out before any key is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    /// The fee the spend pays.
    pub fee: Zatoshis,
    /// The change it returns to a fresh change key, or `None` when the remainder is too
    /// small to be worth an output and goes to the fee instead.
    pub change: Option<Zatoshis>,
}

/// The fee and change of spending outputs worth `inputs`, all controlled by
/// `parameters` keys, to `payments`. [`build_spend`] with the same inputs and payments
/// pays exactly this fee and change, so a wallet can show the fee before it signs.
pub fn quote_spend<P: Parameters>(
    params: &P,
    target_height: BlockHeight,
    parameters: ParameterSet,
    inputs: &[Zatoshis],
    payments: &[Payment],
) -> Result<Quote, SpendError<Infallible>> {
    if inputs.is_empty() {
        return Err(SpendError::NoInputs);
    }
    let size = template_input_charge(parameters);
    let available = sum(inputs.iter().copied())?;
    price(
        params,
        target_height,
        parameters,
        &vec![size; inputs.len()],
        available,
        payments,
    )
}

/// The largest single payment to `recipient` that outputs worth `inputs`, all
/// controlled by `parameters` keys, can make with no change left over.
pub fn max_payment<P: Parameters>(
    params: &P,
    target_height: BlockHeight,
    parameters: ParameterSet,
    inputs: &[Zatoshis],
    recipient: &Recipient,
) -> Result<Zatoshis, SpendError<Infallible>> {
    if inputs.is_empty() {
        return Err(SpendError::NoInputs);
    }
    let available = sum(inputs.iter().copied())?;
    let fee = fee_for(
        params,
        target_height,
        &vec![template_input_charge(parameters); inputs.len()],
        &[TxOut::new(Zatoshis::ZERO, recipient.script())],
    )?;
    (available - fee).ok_or(SpendError::InsufficientFunds {
        available,
        required: fee,
    })
}

/// The fee and change for inputs of the given sizes worth `available` in total.
fn price<P: Parameters, E>(
    params: &P,
    target_height: BlockHeight,
    change_parameters: ParameterSet,
    input_sizes: &[InputCharge],
    available: Zatoshis,
    payments: &[Payment],
) -> Result<Quote, SpendError<E>> {
    let paid = sum(payments.iter().map(|payment| payment.value))?;
    let outputs: Vec<TxOut> = payments
        .iter()
        .map(|payment| TxOut::new(payment.value, payment.recipient.script()))
        .collect();
    let fee_without_change = fee_for(params, target_height, input_sizes, &outputs)?;
    let required = (paid + fee_without_change).ok_or(SpendError::Overflow)?;
    if available < required {
        return Err(SpendError::InsufficientFunds {
            available,
            required,
        });
    }
    // Change goes to a PQ output, whose size is the same for every commitment, so any
    // commitment of the change key's parameter set prices it.
    let change_template = pq_template(change_parameters);
    let mut with_change = outputs;
    with_change.push(TxOut::new(Zatoshis::ZERO, change_template.clone()));
    let fee_with_change = fee_for(params, target_height, input_sizes, &with_change)?;
    // No change when the inputs cannot also pay for its output, or when what remains
    // is dust; the remainder then goes to the fee.
    let change = (paid + fee_with_change)
        .and_then(|spent| available - spent)
        .filter(|value| !is_dust(&change_template, *value));
    let fee = (available - paid)
        .and_then(|left| left - change.unwrap_or(Zatoshis::ZERO))
        .ok_or(SpendError::Overflow)?;
    Ok(Quote { fee, change })
}

/// The byte and verification charges for a canonical single-signature input.
#[derive(Clone, Copy)]
struct InputCharge {
    bytes: usize,
    work: usize,
}

impl InputCharge {
    fn for_destination(destination: &PqDestination) -> Self {
        Self {
            bytes: input_size(destination),
            work: match destination.parameters() {
                ParameterSet::Sha2_128f => 60,
                ParameterSet::Sha2_192s => 30,
            },
        }
    }
}

/// Zakura's transparent fee: 400 zatoshis per action, charging the larger of
/// serialized bytes and potential signature work, with a two-action minimum.
/// The wallet only constructs canonical single-signature inputs; their byte
/// charge exceeds their work charge, but both are accounted for explicitly.
fn fee_for<P: Parameters, E>(
    _params: &P,
    _target_height: BlockHeight,
    input_sizes: &[InputCharge],
    outputs: &[TxOut],
) -> Result<Zatoshis, SpendError<E>> {
    let total = |values: &mut dyn Iterator<Item = usize>| {
        let mut sum = 0usize;
        for value in values {
            sum = sum.checked_add(value).ok_or(SpendError::Overflow)?;
        }
        Ok(sum)
    };
    let input_bytes = total(&mut input_sizes.iter().map(|input| input.bytes))?;
    let work = total(&mut input_sizes.iter().map(|input| input.work))?;
    let output_bytes = total(&mut outputs.iter().map(output_size))?;
    let actions = 2usize
        .max(input_bytes.div_ceil(150))
        .max(output_bytes.div_ceil(34))
        .max(work);
    let fee = u64::try_from(actions)
        .ok()
        .and_then(|actions| actions.checked_mul(400))
        .ok_or(SpendError::Overflow)?;
    Zatoshis::from_u64(fee).map_err(|_| SpendError::Overflow)
}

/// Every canonical input has one signature and a size fixed by its parameter set.
fn template_input_charge(parameters: ParameterSet) -> InputCharge {
    let key = PublicKey::from_bytes(parameters, &vec![0; parameters.public_key_bytes()])
        .expect("a buffer of the parameter set's key length");
    InputCharge::for_destination(&PqDestination::single_signer(&key))
}

/// The next unused change key, deriving the missing ones first if none is left.
fn issue_change<S: PqSigner>(
    pool: &mut AccountPool,
    signer: &mut S,
) -> Result<Issued, SpendError<S::Error>> {
    let change = &pool.state().change;
    let derived_left = change.issued_end < change.public_keys.len() as u64;
    if !derived_left && let Some(range) = pool.replenish_request(Branch::Change) {
        let keys = signer.public_keys(&[range]).map_err(SpendError::Signer)?;
        pool.apply_batch(&keys).map_err(SpendError::Pool)?;
    }
    let issued = pool.issue(Branch::Change).map_err(SpendError::Pool)?;
    if !issued.fresh {
        return Err(SpendError::ChangeKeyNotDerived);
    }
    Ok(issued)
}

/// The serialized size of an input spending `destination`, with its final scriptSig.
fn input_size(destination: &PqDestination) -> usize {
    let placeholder = vec![0; destination.parameters().signature_bytes()];
    txin_size(&transaction::script_sig(&placeholder, destination))
}

/// Outpoint (32 + 4 bytes), the length-prefixed scriptSig, and the sequence.
fn txin_size(script_sig: &Script) -> usize {
    36 + script_sig.serialized_size() + 4
}

/// Value (8 bytes) and the length-prefixed output script.
fn output_size(output: &TxOut) -> usize {
    8 + output.script_pubkey().serialized_size()
}

/// A PQ output script of the right shape and size for pricing, paying nothing.
fn pq_template(parameters: ParameterSet) -> Script {
    output::output_script(parameters, &[0; 32])
}

/// The node's relay dust rule, which has no PQ exception: an output is dust below three
/// times the cost of spending it at 100 zatoshis per 1000 bytes, counting a 148-byte
/// spend. That counts the output's own serialized size, so a PQ output's threshold is 57
/// zatoshis rather than a P2SH output's 54, and the node charges the same 148 bytes for a
/// spend that really takes some sixteen kilobytes.
fn is_dust(template: &Script, value: Zatoshis) -> bool {
    let size = (8 + template.serialized_size()) as u64;
    u64::from(value) < 3 * (100 * (size + 148) / 1000)
}

fn sum<E>(mut values: impl Iterator<Item = Zatoshis>) -> Result<Zatoshis, SpendError<E>> {
    values
        .try_fold(Zatoshis::ZERO, |total, value| total + value)
        .ok_or(SpendError::Overflow)
}
