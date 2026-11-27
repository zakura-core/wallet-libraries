use core::fmt;

use transparent::address::Script;
use transparent::bundle::{self as tbundle, Bundle, OutPoint, TxIn, TxOut};
use transparent::pq::output::{self as pq_output, PqOutput};
use transparent::sighash::{self as tsighash, SighashType, TransparentAuthorizingContext};
use zcash_primitives::transaction::sighash::{SignableInput, signature_hash};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Authorized, Transaction, TransactionData};
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::value::Zatoshis;
use zcash_script::interpreter::CallbackTransactionSignatureChecker;
use zcash_script::script::Code;
use zcash_script::signature::HashType;

use crate::PqDestination;

/// The value and output script of every spent output, which the signature hash
/// commits to.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Prevouts {
    amounts: Vec<Zatoshis>,
    script_pubkeys: Vec<Script>,
}

impl tbundle::Authorization for Prevouts {
    type ScriptSig = Script;
}

impl TransparentAuthorizingContext for Prevouts {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.amounts.clone()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.script_pubkeys.clone()
    }
}

/// A transparent-only transaction together with the outputs it spends.
pub(crate) struct WithPrevouts;

impl Authorization for WithPrevouts {
    type TransparentAuth = Prevouts;
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type OrchardAuth = <Authorized as Authorization>::OrchardAuth;
}

/// A transaction whose inputs are not signed yet, with the outputs they spend.
///
/// A signer computes each input's signature hash from this itself rather than
/// accepting digests from the wallet.
pub struct UnsignedTransaction {
    pub(crate) data: TransactionData<WithPrevouts>,
}

impl UnsignedTransaction {
    pub(crate) fn new(data: TransactionData<WithPrevouts>) -> Self {
        Self { data }
    }

    fn bundle(&self) -> &Bundle<Prevouts> {
        self.data
            .transparent_bundle()
            .expect("PQ spends always have a transparent bundle")
    }

    /// The number of inputs.
    pub fn input_count(&self) -> usize {
        self.bundle().vin.len()
    }

    /// The output an input spends.
    pub fn input_outpoint(&self, index: usize) -> &OutPoint {
        self.bundle().vin[index].prevout()
    }

    /// The value of the output an input spends.
    pub fn input_value(&self, index: usize) -> Zatoshis {
        self.bundle().authorization.amounts[index]
    }

    /// The output script an input spends.
    pub fn input_script_pubkey(&self, index: usize) -> &Script {
        &self.bundle().authorization.script_pubkeys[index]
    }

    /// The transaction's outputs.
    pub fn outputs(&self) -> &[TxOut] {
        &self.bundle().vout
    }

    /// The `SIGHASH_ALL` signature hash for an input spending `destination`.
    ///
    /// The script code is the body, which is the whole of what a PQ spend executes. The
    /// digest also commits to the output being spent, so it binds the format, the scheme
    /// and the commitment, and through the commitment the body again.
    pub fn sighash(&self, index: usize, destination: &PqDestination) -> [u8; 32] {
        let script_code = Script(destination.body_code().clone());
        sighash(&self.data, index, &script_code, SighashType::ALL)
    }
}

fn sighash(
    data: &TransactionData<WithPrevouts>,
    index: usize,
    script_code: &Script,
    hash_type: SighashType,
) -> [u8; 32] {
    let bundle = data
        .transparent_bundle()
        .expect("PQ spends always have a transparent bundle");
    let input = tsighash::SignableInput::from_parts(
        bundle,
        hash_type,
        index,
        script_code,
        &bundle.authorization.script_pubkeys[index],
        bundle.authorization.amounts[index],
    )
    .expect("index is one of the bundle's inputs");
    *signature_hash(
        data,
        &SignableInput::Transparent(input),
        &data.digest(TxIdDigester),
    )
    .as_ref()
}

/// The scriptSig spending `destination` with `signature`: the signature with its
/// `SIGHASH_ALL` byte, then the body the output commits to.
///
/// A PQ spend pushes its arguments and then the committed script, and every push must be
/// the shortest encoding for its length: the evaluator rejects a non-minimal push before
/// it executes anything. So a signature of some sixteen kilobytes takes `PUSHDATA2` while
/// a thirty-four or fifty byte body takes a direct push.
pub(crate) fn script_sig(signature: &[u8], destination: &PqDestination) -> Script {
    let mut argument = signature.to_vec();
    argument.push(SighashType::ALL.encode());
    let mut bytes = minimal_push(&argument);
    bytes.extend_from_slice(&minimal_push(destination.body()));
    Script(Code(bytes))
}

/// The shortest push of `value`, which is the only encoding a PQ spend may use.
fn minimal_push(value: &[u8]) -> Vec<u8> {
    const MAX_DIRECT_PUSH: usize = 0x4b;
    let mut pushed = Vec::with_capacity(5 + value.len());
    match value.len() {
        length if length <= MAX_DIRECT_PUSH => {
            pushed.push(length as u8);
        }
        length if length <= usize::from(u8::MAX) => {
            pushed.push(0x4c);
            pushed.push(length as u8);
        }
        length if length <= usize::from(u16::MAX) => {
            pushed.push(0x4d);
            pushed.extend_from_slice(&(length as u16).to_le_bytes());
        }
        length => {
            pushed.push(0x4e);
            let length = u32::try_from(length).expect("a PQ push is below 4 GiB");
            pushed.extend_from_slice(&length.to_le_bytes());
        }
    }
    pushed.extend_from_slice(value);
    pushed
}

/// Builds the transaction data from inputs, outputs, and the outputs they spend.
pub(crate) fn assemble(
    header: Header,
    inputs: Vec<(OutPoint, Script)>,
    outputs: Vec<TxOut>,
    spent: Vec<TxOut>,
) -> TransactionData<WithPrevouts> {
    let (amounts, script_pubkeys) = spent
        .into_iter()
        .map(|output| (output.value(), output.script_pubkey().clone()))
        .unzip();
    TransactionData::from_parts(
        header.version,
        header.branch_id,
        0,
        header.expiry_height,
        Some(Bundle {
            vin: inputs
                .into_iter()
                .map(|(outpoint, script_sig)| TxIn::from_parts(outpoint, script_sig, u32::MAX))
                .collect(),
            vout: outputs,
            authorization: Prevouts {
                amounts,
                script_pubkeys,
            },
        }),
        None,
        None,
        None,
    )
}

/// Fields shared by every transaction this crate builds.
pub(crate) struct Header {
    pub(crate) version: zcash_primitives::transaction::TxVersion,
    pub(crate) branch_id: zcash_protocol::consensus::BranchId,
    pub(crate) expiry_height: zcash_protocol::consensus::BlockHeight,
}

/// Replaces every input's scriptSig.
pub(crate) fn with_script_sigs(
    data: TransactionData<WithPrevouts>,
    script_sigs: Vec<Script>,
) -> TransactionData<WithPrevouts> {
    data.map_bundles(
        |bundle| {
            bundle.map(|bundle| Bundle {
                vin: bundle
                    .vin
                    .into_iter()
                    .zip(script_sigs)
                    .map(|(input, script_sig)| {
                        TxIn::from_parts(input.prevout().clone(), script_sig, input.sequence())
                    })
                    .collect(),
                vout: bundle.vout,
                authorization: bundle.authorization,
            })
        },
        |sapling| sapling,
        |orchard| orchard,
    )
}

/// Drops the spent-output data, leaving a transaction ready to serialize.
pub(crate) fn freeze(data: TransactionData<WithPrevouts>) -> std::io::Result<Transaction> {
    data.map_bundles::<Authorized>(
        |bundle| {
            bundle.map(|bundle| Bundle {
                vin: bundle
                    .vin
                    .into_iter()
                    .map(|input| {
                        TxIn::from_parts(
                            input.prevout().clone(),
                            input.script_sig().clone(),
                            input.sequence(),
                        )
                    })
                    .collect(),
                vout: bundle.vout,
                authorization: tbundle::Authorized,
            })
        },
        |sapling| sapling,
        |orchard| orchard,
    )
    .freeze()
}

/// Why a transaction's PQ inputs did not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The number of spent outputs differs from the number of inputs.
    SpentOutputCount {
        /// Inputs in the transaction.
        inputs: usize,
        /// Spent outputs supplied.
        spent: usize,
    },
    /// The transaction has no transparent inputs.
    NoTransparentInputs,
    /// The output the input spends is not a PQ output of a defined format and scheme.
    NotPq(usize),
    /// The input's PQ authorization is malformed or its signature does not verify.
    Invalid(usize),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpentOutputCount { inputs, spent } => {
                write!(f, "{spent} spent outputs supplied for {inputs} inputs")
            }
            Self::NoTransparentInputs => f.write_str("transaction has no transparent inputs"),
            Self::NotPq(index) => write!(f, "input {index} does not spend a PQ output"),
            Self::Invalid(index) => write!(f, "input {index} failed PQ verification"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Checks every input of `transaction` as a PQ spend of the matching output in `spent`,
/// with Common's verifier.
///
/// The network is needed because it is part of the signing context, so a signature made
/// for one network does not verify on another.
pub fn verify_inputs(
    network: NetworkType,
    transaction: &Transaction,
    spent: &[TxOut],
) -> Result<(), VerifyError> {
    let mut bytes = Vec::new();
    transaction
        .write(&mut bytes)
        .expect("writing to a Vec cannot fail");
    let data = Transaction::read(&bytes[..], transaction.consensus_branch_id())
        .expect("a transaction reads back what it wrote")
        .into_data();
    let inputs = data
        .transparent_bundle()
        .map_or(0, |bundle| bundle.vin.len());
    if inputs == 0 {
        return Err(VerifyError::NoTransparentInputs);
    }
    if inputs != spent.len() {
        return Err(VerifyError::SpentOutputCount {
            inputs,
            spent: spent.len(),
        });
    }
    let amounts = spent.iter().map(TxOut::value).collect();
    let script_pubkeys = spent
        .iter()
        .map(|output| output.script_pubkey().clone())
        .collect();
    let data = data.map_bundles::<WithPrevouts>(
        |bundle| {
            bundle.map(|bundle| Bundle {
                vin: bundle
                    .vin
                    .into_iter()
                    .map(|input| {
                        TxIn::from_parts(
                            input.prevout().clone(),
                            input.script_sig().clone(),
                            input.sequence(),
                        )
                    })
                    .collect(),
                vout: bundle.vout,
                authorization: Prevouts {
                    amounts,
                    script_pubkeys,
                },
            })
        },
        |sapling| sapling,
        |orchard| orchard,
    );
    verify_data(network, &data)
}

/// Verifies every input of transaction data that carries its spent outputs.
pub(crate) fn verify_data(
    network: NetworkType,
    data: &TransactionData<WithPrevouts>,
) -> Result<(), VerifyError> {
    let bundle = data
        .transparent_bundle()
        .ok_or(VerifyError::NoTransparentInputs)?;
    for (index, input) in bundle.vin.iter().enumerate() {
        let script_sig = &input.script_sig().0.0;
        let script_pubkey = &bundle.authorization.script_pubkeys[index].0;
        // Anything outside the PQ namespace keeps the legacy rules, and anything inside it
        // that no format defines is restricted; neither is a spend this crate may make.
        let Ok(Some(output)) = pq_output::parse_output(script_pubkey) else {
            return Err(VerifyError::NotPq(index));
        };
        let sighash = |script_code: &Code, hash_type: &HashType| {
            let hash_type = SighashType::parse(u8::try_from(hash_type.raw_bits()).ok()?)?;
            Some(sighash(
                data,
                index,
                &Script(script_code.clone()),
                hash_type,
            ))
        };
        let checker = CallbackTransactionSignatureChecker {
            sighash: &sighash,
            lock_time: i64::from(data.lock_time()),
            is_final: input.sequence() == u32::MAX,
        };
        // PQ execution has fixed rules, so the verifier takes no legacy interpreter flags.
        match PqOutput::verify_spend(&output, network, script_sig, &checker) {
            Ok(true) => {}
            _ => return Err(VerifyError::Invalid(index)),
        }
    }
    Ok(())
}
