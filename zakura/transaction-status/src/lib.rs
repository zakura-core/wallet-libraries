//! Policy-bound status observations, independent of transaction enhancement.
//!
//! A reader selects exactly one source. The other source is never opened, even
//! when the selected source fails. Applications supply their own private PIR
//! source, including its independently verified chain anchor and transport.

pub mod lightwalletd;

use std::fmt;
use zakura_pir_status::LocalCoverageContext;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusMode {
    PublicLightwalletd,
    PrivatePir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusRequest {
    pub txid: TxId,
    pub coverage: LocalCoverageContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusObservation {
    NotFound,
    Mempool,
    Mined(BlockHeight),
    Forked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusError {
    Unsupported,
    Unavailable,
    CoverageIncomplete,
    Stale,
    Timeout,
    Malformed,
    Cancelled,
    Transport { code: i32 },
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transaction status lookup: {self:?}")
    }
}
impl std::error::Error for StatusError {}

impl From<zakura_pir_status::Error> for StatusError {
    fn from(error: zakura_pir_status::Error) -> Self {
        use zakura_pir_status::Error;
        match error {
            Error::Unsupported => Self::Unsupported,
            Error::CoverageIncomplete => Self::CoverageIncomplete,
            Error::Stale => Self::Stale,
            Error::Timeout => Self::Timeout,
            Error::Cancelled => Self::Cancelled,
            Error::Malformed => Self::Malformed,
            Error::Capacity | Error::Unavailable | Error::Pir => Self::Unavailable,
        }
    }
}

impl From<tonic::Status> for StatusError {
    fn from(status: tonic::Status) -> Self {
        use tonic::Code;
        match status.code() {
            Code::Unimplemented => Self::Unsupported,
            Code::Unavailable => Self::Unavailable,
            Code::DeadlineExceeded => Self::Timeout,
            Code::Cancelled => Self::Cancelled,
            code => Self::Transport { code: code as i32 },
        }
    }
}

/// A source is consumed only when its policy is selected. Opening a source may
/// establish a network connection or initialize a private PIR generation.
#[allow(async_fn_in_trait)]
pub trait StatusSource {
    type Session: StatusSession;
    async fn open(self) -> Result<Self::Session, StatusError>;
}

#[allow(async_fn_in_trait)]
pub trait StatusSession {
    async fn observe(&mut self, request: StatusRequest) -> Result<StatusObservation, StatusError>;
}

/// Placeholder for a capability the application does not configure. The
/// reader never opens it when the other mode is selected.
pub struct DisabledSource;
pub struct DisabledSession;

impl StatusSource for DisabledSource {
    type Session = DisabledSession;
    async fn open(self) -> Result<Self::Session, StatusError> {
        Err(StatusError::Unsupported)
    }
}

impl StatusSession for DisabledSession {
    async fn observe(&mut self, _: StatusRequest) -> Result<StatusObservation, StatusError> {
        Err(StatusError::Unsupported)
    }
}

enum State<P: StatusSource, R: StatusSource> {
    Public(P),
    Private(R),
    PublicSession(P::Session),
    PrivateSession(R::Session),
    /// Terminal. Also set while a source is opening, so a dropped `observe`
    /// future leaves the reader failed with `Cancelled` rather than unusable.
    Failed(StatusError),
}

/// Lazily opens and reuses one authorized source for a batch of observations.
/// The unselected source is dropped unopened. An opening failure or a cancelled
/// opening is terminal for this reader; a caller's next retry makes a new
/// reader. An observation failure does not change the selected source.
pub struct StatusReader<P: StatusSource, R: StatusSource> {
    state: State<P, R>,
}

impl<P: StatusSource, R: StatusSource> StatusReader<P, R> {
    pub fn new(mode: StatusMode, public: P, private: R) -> Self {
        let state = match mode {
            StatusMode::PublicLightwalletd => State::Public(public),
            StatusMode::PrivatePir => State::Private(private),
        };
        Self { state }
    }

    pub async fn observe(
        &mut self,
        request: StatusRequest,
    ) -> Result<StatusObservation, StatusError> {
        match std::mem::replace(&mut self.state, State::Failed(StatusError::Cancelled)) {
            State::Public(source) => {
                self.state = source
                    .open()
                    .await
                    .map_or_else(State::Failed, State::PublicSession)
            }
            State::Private(source) => {
                self.state = source
                    .open()
                    .await
                    .map_or_else(State::Failed, State::PrivateSession)
            }
            state => self.state = state,
        }
        match &mut self.state {
            State::PublicSession(session) => session.observe(request).await,
            State::PrivateSession(session) => session.observe(request).await,
            State::Failed(error) => Err(*error),
            State::Public(_) | State::Private(_) => unreachable!("source opened above"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Source {
        opens: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
        open_error: Option<StatusError>,
        open_hangs: bool,
        observation: Result<StatusObservation, StatusError>,
    }

    struct Session {
        calls: Arc<AtomicUsize>,
        observation: Result<StatusObservation, StatusError>,
    }

    impl StatusSource for Source {
        type Session = Session;
        async fn open(self) -> Result<Session, StatusError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if self.open_hangs {
                std::future::pending::<()>().await;
            }
            if let Some(error) = self.open_error {
                return Err(error);
            }
            Ok(Session {
                calls: self.calls,
                observation: self.observation,
            })
        }
    }
    impl StatusSession for Session {
        async fn observe(&mut self, _: StatusRequest) -> Result<StatusObservation, StatusError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observation
        }
    }

    fn source(
        observation: Result<StatusObservation, StatusError>,
    ) -> (Source, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Source {
                opens: opens.clone(),
                calls: calls.clone(),
                open_error: None,
                open_hangs: false,
                observation,
            },
            opens,
            calls,
        )
    }
    fn request() -> StatusRequest {
        StatusRequest {
            txid: TxId::from_bytes([1; 32]),
            coverage: LocalCoverageContext::default(),
        }
    }

    #[tokio::test]
    async fn private_selection_never_opens_public_and_reuses_session() {
        let (public, public_opens, _) = source(Ok(StatusObservation::NotFound));
        let (private, private_opens, private_calls) = source(Ok(StatusObservation::Mempool));
        let mut reader = StatusReader::new(StatusMode::PrivatePir, public, private);
        assert_eq!(
            reader.observe(request()).await,
            Ok(StatusObservation::Mempool)
        );
        assert_eq!(
            reader.observe(request()).await,
            Ok(StatusObservation::Mempool)
        );
        assert_eq!(public_opens.load(Ordering::SeqCst), 0);
        assert_eq!(private_opens.load(Ordering::SeqCst), 1);
        assert_eq!(private_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn private_open_and_observation_fail_closed() {
        let (public, public_opens, _) = source(Ok(StatusObservation::NotFound));
        let (mut private, private_opens, _) = source(Ok(StatusObservation::NotFound));
        private.open_error = Some(StatusError::CoverageIncomplete);
        let mut reader = StatusReader::new(StatusMode::PrivatePir, public, private);
        for _ in 0..2 {
            assert_eq!(
                reader.observe(request()).await,
                Err(StatusError::CoverageIncomplete)
            );
        }
        assert_eq!(private_opens.load(Ordering::SeqCst), 1);
        assert_eq!(public_opens.load(Ordering::SeqCst), 0);

        let (public, public_opens, _) = source(Ok(StatusObservation::NotFound));
        let (private, _, _) = source(Err(StatusError::Stale));
        let mut reader = StatusReader::new(StatusMode::PrivatePir, public, private);
        assert_eq!(reader.observe(request()).await, Err(StatusError::Stale));
        assert_eq!(public_opens.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn public_selection_never_opens_private() {
        let (public, public_opens, _) = source(Ok(StatusObservation::Forked));
        let (private, private_opens, _) = source(Ok(StatusObservation::NotFound));
        let mut reader = StatusReader::new(StatusMode::PublicLightwalletd, public, private);
        assert_eq!(
            reader.observe(request()).await,
            Ok(StatusObservation::Forked)
        );
        assert_eq!(public_opens.load(Ordering::SeqCst), 1);
        assert_eq!(private_opens.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dropped_opening_leaves_reader_cancelled() {
        let (public, public_opens, _) = source(Ok(StatusObservation::NotFound));
        let (mut private, private_opens, _) = source(Ok(StatusObservation::Mempool));
        private.open_hangs = true;
        let mut reader = StatusReader::new(StatusMode::PrivatePir, public, private);
        let dropped = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            reader.observe(request()),
        )
        .await;
        assert!(dropped.is_err());
        assert_eq!(reader.observe(request()).await, Err(StatusError::Cancelled));
        assert_eq!(private_opens.load(Ordering::SeqCst), 1);
        assert_eq!(public_opens.load(Ordering::SeqCst), 0);
    }
}
