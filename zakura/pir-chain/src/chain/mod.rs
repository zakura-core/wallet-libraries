//! Minimal decoded chain data for RPC ingestion. Transaction decoding and IDs use
//! Common's wallet primitives; consensus and proof verification remain the node's
//! responsibility. The optional RocksDB adapter converts through canonical bytes.
mod transaction;
pub(crate) use transaction::{Action, Transaction};

use sha2::{Digest, Sha256};
use std::{
    fmt,
    io::{self, Read},
    sync::Arc,
};
use zcash_primitives::block::BlockHeader;
use zcash_protocol::{encoding::CompactSize, value::Zatoshis};
use zcash_script::script::Evaluable;

pub(crate) type Amount = Zatoshis;
pub(crate) const MAX_BLOCK_BYTES: u64 = 2_000_000;
pub(crate) const MIN_TRANSPARENT_TX_SIZE: u64 = 54;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Hash(pub [u8; 32]);
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::hash::display(&self.0))
    }
}
impl std::str::FromStr for Hash {
    type Err = crate::NodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::hash::parse_display(s).map(Self)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Height(pub u32);
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Script(Vec<u8>);
impl Script {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    pub(crate) fn as_raw_bytes(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OutPoint {
    pub hash: Hash,
    pub index: u32,
}
#[derive(Clone, Debug)]
pub(crate) enum Input {
    Coinbase { height: Option<Height> },
    PrevOut { outpoint: OutPoint },
}
impl Input {
    pub(crate) fn outpoint(&self) -> Option<OutPoint> {
        match self {
            Self::PrevOut { outpoint } => Some(*outpoint),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Output {
    pub value: Amount,
    pub lock_script: Script,
}
impl Output {
    pub(crate) fn zcash_deserialize(mut raw: impl Read) -> io::Result<Self> {
        let output = transparent::bundle::TxOut::read(&mut raw)?;
        Ok(Self {
            value: output.value(),
            lock_script: Script::new(&output.script_pubkey().0.to_bytes()),
        })
    }
    pub(crate) fn zcash_serialize_to_vec(&self) -> io::Result<Vec<u8>> {
        let mut bytes = self.value.to_u64_le_bytes().to_vec();
        CompactSize::write(&mut bytes, self.lock_script.0.len())?;
        bytes.extend_from_slice(&self.lock_script.0);
        Ok(bytes)
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Utxo {
    pub output: Output,
}

#[derive(Debug)]
pub(crate) struct Header {
    pub previous_block_hash: Hash,
    pub merkle_root: [u8; 32],
    pub time: i64,
}
#[derive(Debug)]
pub(crate) struct Block {
    pub header: Header,
    pub transactions: Vec<Arc<Transaction>>,
    hash: Hash,
}
impl Block {
    pub(crate) fn zcash_deserialize(reader: impl Read) -> io::Result<Self> {
        let mut reader = reader.take(MAX_BLOCK_BYTES);
        let header = BlockHeader::read(&mut reader)?;
        if (header.version as u32) < 4 || header.version < 0 {
            return Err(io::Error::other("invalid block version"));
        }
        if !matches!(header.solution.len(), 36 | 1344) {
            return Err(io::Error::other("invalid Equihash solution length"));
        }
        let count = CompactSize::read(&mut reader)?;
        if count == 0 || count > MAX_BLOCK_BYTES / MIN_TRANSPARENT_TX_SIZE {
            return Err(io::Error::other("invalid block transaction count"));
        }
        let mut transactions = Vec::new();
        for _ in 0..count {
            transactions.push(Arc::new(Transaction::zcash_deserialize(&mut reader)?));
        }
        Ok(Self {
            hash: Hash(header.hash().0),
            header: Header {
                previous_block_hash: Hash(header.prev_block.0),
                merkle_root: header.merkle_root,
                time: header.time.into(),
            },
            transactions,
        })
    }
    pub(crate) fn hash(&self) -> Hash {
        self.hash
    }
    pub(crate) fn coinbase_height(&self) -> Option<Height> {
        match self.transactions.first()?.inputs().first()? {
            Input::Coinbase { height } => *height,
            _ => None,
        }
    }
    pub(crate) fn merkle_root(&self) -> [u8; 32] {
        let mut hashes: Vec<_> = self.transactions.iter().map(|tx| tx.hash().0).collect();
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(*hashes.last().expect("nonempty level"));
            }
            hashes = hashes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let mut sha = Sha256::new();
                    sha.update(pair[0]);
                    sha.update(pair[1]);
                    Sha256::digest(sha.finalize()).into()
                })
                .collect();
        }
        hashes.first().copied().unwrap_or([0; 32])
    }
}

#[cfg(test)]
mod tests;
