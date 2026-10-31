use core::fmt;

use transparent::address::Script;
use transparent::bundle::{self as tbundle, Bundle, OutPoint, TxIn, TxOut};
use transparent::pq::p2sh::{self, SpendMode};
use transparent::sighash::{self as tsighash, SighashType, TransparentAuthorizingContext};
use zcash_primitives::transaction::sighash::{SignableInput, signature_hash};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Authorized, Transaction, TransactionData};
use zcash_protocol::value::Zatoshis;
use zcash_script::interpreter::{CallbackTransactionSignatureChecker, Flags};
use zcash_script::script::{self, Code};
use zcash_script::signature::HashType;

use crate::PqScript;

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

    /// The `SIGHASH_ALL` signature hash for an input spent through `script`.
    pub fn sighash(&self, index: usize, script: &PqScript) -> [u8; 32] {
        let script_code = Script(script.redeem_code().clone());
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

/// The scriptSig spending `script` with `signature`: the signature with its
/// `SIGHASH_ALL` byte, then the redeem script, each pushed with PUSHDATA2.
pub(crate) fn script_sig(signature: &[u8], script: &PqScript) -> Script {
    let mut argument = signature.to_vec();
    argument.push(SighashType::ALL.encode());
    let mut bytes = pushdata2(&argument);
    bytes.extend_from_slice(&pushdata2(script.redeem_script()));
    Script(Code(bytes))
}

fn pushdata2(value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("PQ pushes are below 64 KiB");
    let mut pushed = Vec::with_capacity(3 + value.len());
    pushed.push(0x4d);
    pushed.extend_from_slice(&length.to_le_bytes());
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
    /// The input does not spend a PQ P2SH output with a matching redeem script.
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
            Self::NotPq(index) => write!(f, "input {index} is not a PQ P2SH spend"),
            Self::Invalid(index) => write!(f, "input {index} failed PQ verification"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Checks every input of `transaction` as a PQ P2SH spend of the matching output in
/// `spent`, with Common's verifier.
pub fn verify_inputs(transaction: &Transaction, spent: &[TxOut]) -> Result<(), VerifyError> {
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
    verify_data(&data)
}

/// Verifies every input of transaction data that carries its spent outputs.
pub(crate) fn verify_data(data: &TransactionData<WithPrevouts>) -> Result<(), VerifyError> {
    let bundle = data
        .transparent_bundle()
        .ok_or(VerifyError::NoTransparentInputs)?;
    for (index, input) in bundle.vin.iter().enumerate() {
        let script_sig = &input.script_sig().0.0;
        let script_pubkey = &bundle.authorization.script_pubkeys[index].0;
        // Common's verifier falls back to legacy rules for other scripts; insist on PQ.
        match p2sh::classify_spend(script_sig, script_pubkey) {
            Ok(SpendMode::Pq(_)) => {}
            _ => return Err(VerifyError::NotPq(index)),
        }
        let sighash = |script_code: &Code, hash_type: &HashType| {
            let hash_type = SighashType::parse(u8::try_from(hash_type.raw_bits()).ok()?)?;
            Some(sighash(
                data,
                index,
                &Script(script_code.clone()),
                hash_type,
            ))
        };
        let spend = script::Raw::from_raw_parts(script_sig.clone(), script_pubkey.0.clone());
        let checker = CallbackTransactionSignatureChecker {
            sighash: &sighash,
            lock_time: i64::from(data.lock_time()),
            is_final: input.sequence() == u32::MAX,
        };
        match p2sh::verify_spend(&spend, Flags::P2SH | Flags::CHECKLOCKTIMEVERIFY, &checker) {
            Ok(true) => {}
            _ => return Err(VerifyError::Invalid(index)),
        }
    }
    Ok(())
}
