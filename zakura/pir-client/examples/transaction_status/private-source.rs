//! A caller-supplied private source, without the bundled lightwalletd adapter.
use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use zakura_pir_client::status::policy::{
    DisabledSource, StatusError, StatusMode, StatusObservation, StatusReader, StatusRequest,
    StatusSession, StatusSource,
};

struct PrivateSource;
struct PrivateSession;

impl StatusSource for PrivateSource {
    type Session = PrivateSession;
    async fn open(self) -> Result<Self::Session, StatusError> {
        Ok(PrivateSession)
    }
}

impl StatusSession for PrivateSession {
    async fn observe(&mut self, _: StatusRequest) -> Result<StatusObservation, StatusError> {
        Ok(StatusObservation::Mempool)
    }
}

fn main() {
    let mut reader = StatusReader::new(StatusMode::PrivatePir, DisabledSource, PrivateSource);
    let request = StatusRequest {
        txid: zcash_protocol::TxId::NULL,
        coverage: Default::default(),
    };
    // This fake source completes immediately, so it needs no async runtime.
    let mut observation = pin!(reader.observe(request));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        observation.as_mut().poll(&mut context),
        Poll::Ready(Ok(StatusObservation::Mempool))
    );
}
