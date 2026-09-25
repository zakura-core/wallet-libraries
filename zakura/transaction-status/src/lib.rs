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

enum SelectedSession<P, R> {
    Public(P),
    Private(R),
}

/// Lazily opens and reuses one authorized source for a batch of observations.
/// An opening failure is terminal for this reader; a caller's next retry makes
/// a new reader. An observation failure does not change the selected source.
pub struct StatusReader<P: StatusSource, R: StatusSource> {
    mode: StatusMode,
    public: Option<P>,
    private: Option<R>,
    session: Option<SelectedSession<P::Session, R::Session>>,
    open_error: Option<StatusError>,
}

impl<P: StatusSource, R: StatusSource> StatusReader<P, R> {
    pub fn new(mode: StatusMode, public: P, private: R) -> Self {
        Self {
            mode,
            public: Some(public),
            private: Some(private),
            session: None,
            open_error: None,
        }
    }

    pub async fn observe(
        &mut self,
        request: StatusRequest,
    ) -> Result<StatusObservation, StatusError> {
        if let Some(error) = self.open_error {
            return Err(error);
        }
        if self.session.is_none() {
            let result = match self.mode {
                StatusMode::PublicLightwalletd => self
                    .public
                    .take()
                    .expect("unopened public status source")
                    .open()
                    .await
                    .map(SelectedSession::Public),
                StatusMode::PrivatePir => self
                    .private
                    .take()
                    .expect("unopened private status source")
                    .open()
                    .await
                    .map(SelectedSession::Private),
            };
            self.session = Some(match result {
                Ok(session) => session,
                Err(error) => {
                    self.open_error = Some(error);
                    return Err(error);
                }
            });
        }
        match self.session.as_mut().expect("selected status session") {
            SelectedSession::Public(session) => session.observe(request).await,
            SelectedSession::Private(session) => session.observe(request).await,
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
}
