//! Which PQ transparent keys a wallet may hand out, and how it finds them again.
//!
//! SLH-DSA has no extended public key, so a wallet keeps a batch of signer-generated
//! public keys and hands out addresses from it. One window bounds both how far that
//! batch reaches past the last used key and how far restore searches, so every
//! handed-out key is found again from the seed. The crate holds public material only,
//! builds no scripts or addresses, and persists nothing; the README specifies the
//! rules and what the caller must save.
//!
//! ```
//! use core::num::NonZeroU32;
//! use transparent_pq_keys::{Branch, Network, ParameterSet, WalletSeed};
//! use transparent_pq_pool::AccountPool;
//!
//! // Public example material. A real seed must come from a secure entropy source.
//! let mut seed = WalletSeed::from_bytes(&[0x42; 32])?;
//! let window = NonZeroU32::new(2).unwrap();
//! let mut pool = AccountPool::new(ParameterSet::Sha2_128f, Network::Testnet, 0, window);
//! pool.replenish(Branch::Receive, &mut seed)?;
//! let first = pool.issue(Branch::Receive)?;
//! assert!(first.fresh);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod error;
mod pool;
mod range;
mod source;

pub use error::{Error, SourceError};
pub use pool::{AccountPool, BranchState, Issued, PoolState, SIGNATURE_WARNING_THRESHOLD};
pub use range::KeyRange;
pub use source::PublicKeySource;
