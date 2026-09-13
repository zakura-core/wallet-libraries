//! Stopping a run between requests.
//!
//! A run is blocking and CPU-bound, and the library it drives has no
//! cancellation of its own; what it does have is a transport it calls before
//! every request. A stop is therefore a transport that refuses the next
//! request. Everything committed before that stays committed — the store
//! commits each shard as it is retrieved — and the refusal ends the run with
//! a transport error, which the source records as `stopped` rather than as a
//! reason the sync fell short.
//!
//! The latency of a stop is bounded by one request: a private query in
//! flight completes, and the one after it does not begin.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use transparent_wallet::{
    client::Table,
    transport::{BoxError, FilterSource, ShardTransport},
};

/// What a stopped run's transport error says, so the source can tell a stop
/// from a failure.
pub(crate) const STOPPED: &str = "stopped by the wallet";

/// A request to stop the run that holds it.
///
/// Cloned into the run and kept by whoever may want to stop it. Setting it is
/// permanent for that run; a new run takes a new signal.
#[derive(Debug, Clone, Default)]
pub struct StopSignal(Arc<AtomicBool>);

impl StopSignal {
    /// A signal nobody has raised.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the run to stop before its next request.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether a stop has been asked for.
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), BoxError> {
        if self.is_stopped() {
            Err(STOPPED.into())
        } else {
            Ok(())
        }
    }
}

/// A transport that refuses every request once its signal is raised.
///
/// Borrows the transport it guards rather than owning it, so the caller keeps
/// whatever the transport counted or cached once the run is over.
pub struct Stoppable<'a, T: ?Sized> {
    inner: &'a mut T,
    signal: StopSignal,
}

impl<'a, T: ?Sized> Stoppable<'a, T> {
    /// Wraps `inner` so that `signal` can end its run.
    pub fn new(inner: &'a mut T, signal: StopSignal) -> Self {
        Self { inner, signal }
    }
}

impl<T: FilterSource + ?Sized> FilterSource for Stoppable<'_, T> {
    fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.signal.check()?;
        self.inner.shard_map()
    }

    fn filter(&mut self, shard_id: u64) -> Result<(Vec<u8>, u64), BoxError> {
        self.signal.check()?;
        self.inner.filter(shard_id)
    }
}

impl<T: ShardTransport + ?Sized> ShardTransport for Stoppable<'_, T> {
    fn init(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
        self.signal.check()?;
        self.inner.init()
    }

    fn manifest(&mut self, shard_id: u64, revision: &str) -> Result<(Vec<u8>, u64), BoxError> {
        self.signal.check()?;
        self.inner.manifest(shard_id, revision)
    }

    fn setup(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        segment: u32,
    ) -> Result<(Vec<u8>, u64), BoxError> {
        self.signal.check()?;
        self.inner.setup(shard_id, revision, table, segment)
    }

    fn query(
        &mut self,
        shard_id: u64,
        revision: &str,
        table: Table,
        body: &[u8],
    ) -> Result<Vec<u8>, BoxError> {
        self.signal.check()?;
        self.inner.query(shard_id, revision, table, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Never;
    impl FilterSource for Never {
        fn shard_map(&mut self) -> Result<(Vec<u8>, u64), BoxError> {
            Ok((b"{}".to_vec(), 2))
        }
        fn filter(&mut self, _: u64) -> Result<(Vec<u8>, u64), BoxError> {
            Ok((Vec::new(), 0))
        }
    }

    #[test]
    fn a_raised_signal_refuses_the_next_request_and_nothing_before_it() {
        let signal = StopSignal::new();
        let mut never = Never;
        let mut filters = Stoppable::new(&mut never, signal.clone());
        assert!(filters.shard_map().is_ok());
        signal.stop();
        let error = filters.filter(0).unwrap_err().to_string();
        assert_eq!(error, STOPPED);
        assert!(signal.is_stopped());
    }
}
