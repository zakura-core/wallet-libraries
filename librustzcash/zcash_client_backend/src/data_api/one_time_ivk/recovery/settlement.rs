//! Durable completion of receiver history under the exact compatible PIR session used.
use super::{History, OneTimeRecoveryWrite};
use crate::data_api::{
    WalletRead,
    one_time_ivk::restore::{DirectoryPayment, LookupWork, PublicationEnd},
    transparent_ledger::ChainPoint,
};
use zakura_one_time_ivk::KeyId;

#[cfg(feature = "test-dependencies")]
use ambassador::delegatable_trait;

/// Session identity obtained from the connected PIR client after archive and chain validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PirSnapshot {
    pub history: History,
    pub session: [u8; 32],
    pub publication: PublicationEnd,
}

/// Permission captured for one receiver's historical work. New receivers do not change this scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirScope<A> {
    pub account: A,
    pub key: KeyId,
    pub work: u64,
    pub snapshot: PirSnapshot,
    pub through: ChainPoint,
}

/// A resumable receiver walk or completed enumeration awaiting candidate admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirWork<A> {
    pub scope: PirScope<A>,
    pub lookup: LookupWork,
    pub enumerated: bool,
}

/// An exact authenticated candidate awaiting a canonical inclusion path and spend checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirWitness<A> {
    pub scope: PirScope<A>,
    pub payment: DirectoryPayment,
}

/// Receiver-history transitions. Implementations keep matches pending until complete enumeration
/// and admission, and never credit stale work after settings, history or chain changes.
#[cfg_attr(feature = "test-dependencies", delegatable_trait)]
pub trait OneTimePirRecovery: OneTimeRecoveryWrite {
    /// Coalesces positive matches for a receiver under an independently validated actual session.
    /// Returns no work when disabled, no match is covered, or a durable retry is not due.
    fn begin_one_time_pir(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        key: KeyId,
        snapshot: PirSnapshot,
        now: i64,
    ) -> Result<Option<PirWork<<Self as WalletRead>::AccountId>>, <Self as WalletRead>::Error>;

    /// Atomically authenticates a bounded consecutive page and saves its cursor. Completion
    /// cannot erase matches while any returned candidate still needs inclusion or spend checks.
    fn record_one_time_pir_page(
        &mut self,
        work: &PirWork<<Self as WalletRead>::AccountId>,
        start: u32,
        records: &[DirectoryPayment],
        complete: bool,
    ) -> Result<bool, <Self as WalletRead>::Error>;

    /// Returns bounded witness work while enabled, including after process restart.
    fn one_time_pir_witnesses(
        &self,
        account: <Self as WalletRead>::AccountId,
        limit: u32,
    ) -> Result<Vec<PirWitness<<Self as WalletRead>::AccountId>>, <Self as WalletRead>::Error>;

    /// Applies a witness only to the same captured candidate and still-current scope.
    fn record_one_time_pir_witness(
        &mut self,
        work: &PirWitness<<Self as WalletRead>::AccountId>,
        anchor: ChainPoint,
        siblings: [[u8; 32]; 32],
    ) -> Result<bool, <Self as WalletRead>::Error>;

    /// Reconsiders bounded pending candidates after local chain progress without a network request.
    fn admit_one_time_pir(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        limit: u32,
    ) -> Result<(), <Self as WalletRead>::Error>;

    /// Persists bounded retry backoff only if this request still owns the receiver's lookup scope.
    fn defer_one_time_pir(
        &mut self,
        scope: &PirScope<<Self as WalletRead>::AccountId>,
        now: i64,
    ) -> Result<(), <Self as WalletRead>::Error>;
}
