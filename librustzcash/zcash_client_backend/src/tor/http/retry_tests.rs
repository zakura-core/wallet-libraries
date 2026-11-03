//! Offline tests of the existing SDK retry loop and actual HTTP dispatch.
//!
//! The script selects an IO sentinel with an explicit test filter; it does not
//! fabricate an Arti DNS error or exercise real Tor/TLS opening. Arti's stable
//! API cannot construct that positive error without additional test features.

use std::{
    convert::Infallible,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use arti_client::{BootstrapBehavior, TorClient, config::TorClientConfigBuilder};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response, StatusCode,
    body::{Body, Bytes, Frame, SizeHint},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};
use tor_rtcompat::PreferredRuntime;

use super::{ATTEMPT_SCRIPT, AttemptScript, HttpError, Retry, ScriptedAttempt, TimeoutPhase};
use crate::tor::{Client, Error, Timeouts};

const QUERY: &[u8] = b"one private PIR query";

#[derive(Clone)]
struct TrackedBody {
    inner: Full<Bytes>,
    data_frames: Arc<AtomicUsize>,
}

impl Body for TrackedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let frame = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(&frame, Poll::Ready(Some(Ok(frame))) if frame.is_data()) {
            self.data_frames.fetch_add(1, Ordering::SeqCst);
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn client() -> (tempfile::TempDir, Client) {
    let directory = tempfile::tempdir().unwrap();
    let config = TorClientConfigBuilder::from_directories(
        directory.path().join("state"),
        directory.path().join("cache"),
    )
    .build()
    .unwrap();
    let inner = TorClient::with_runtime(PreferredRuntime::current().unwrap())
        .config(config)
        .bootstrap_behavior(BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .unwrap();
    (
        directory,
        Client {
            inner,
            timeouts: Timeouts::default(),
        },
    )
}

fn selected_failure(message: &'static str) -> ScriptedAttempt {
    ScriptedAttempt::Error(Error::Io(io::Error::new(io::ErrorKind::NotFound, message)))
}

fn unexpected_attempt() -> ScriptedAttempt {
    ScriptedAttempt::Error(Error::Io(io::Error::other("unexpected extra attempt")))
}

fn script(attempts: impl IntoIterator<Item = ScriptedAttempt>) -> Arc<Mutex<AttemptScript>> {
    Arc::new(Mutex::new(AttemptScript {
        attempts: attempts.into_iter().collect(),
        clients: Vec::new(),
        data_frames: Arc::new(AtomicUsize::new(0)),
        frames_before_open: Vec::new(),
    }))
}

fn selected_open_failure(result: Result<StatusCode, &Error>) -> Option<Retry> {
    matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
        .then_some(Retry::Isolated)
}

async fn post(
    client: &Client,
    script: Arc<Mutex<AttemptScript>>,
) -> Result<Response<Vec<u8>>, Error> {
    let data_frames = Arc::clone(&script.lock().unwrap().data_frames);
    ATTEMPT_SCRIPT
        .scope(
            script,
            client.http_post(
                "https://service.invalid/query".parse().unwrap(),
                |builder| builder,
                TrackedBody {
                    inner: Full::new(Bytes::from_static(QUERY)),
                    data_frames,
                },
                |body| async {
                    Ok(body
                        .collect()
                        .await
                        .map_err(HttpError::from)?
                        .to_bytes()
                        .to_vec())
                },
                1,
                selected_open_failure,
            ),
        )
        .await
}

enum Reply {
    Success,
    Unavailable,
    NoHeaders,
    TruncatedBody,
}

/// The peer receives real Hyper request bytes. It uses no socket or DNS.
fn peer(reply: Reply) -> (ScriptedAttempt, JoinHandle<Vec<u8>>) {
    let (stream, mut peer) = tokio::io::duplex(4096);
    let received = tokio::spawn(async move {
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = peer.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "request ended before its body");
            request.extend_from_slice(&buffer[..read]);
            if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).unwrap();
                let length: usize = headers
                    .lines()
                    .skip(1)
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .expect("Hyper emits an exact content length for Full");
                if request.len() >= end + 4 + length {
                    assert_eq!(&request[end + 4..], QUERY);
                    assert!(request.starts_with(b"POST "));
                    break;
                }
            }
        }
        let response: &[u8] = match reply {
            Reply::Success => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            Reply::Unavailable => b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            Reply::NoHeaders => b"",
            Reply::TruncatedBody => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
        };
        peer.write_all(response).await.unwrap();
        request
    });
    (ScriptedAttempt::Http(stream), received)
}

#[tokio::test]
async fn selected_open_failure_recovers_before_exactly_one_post() {
    let (_directory, client) = client();
    let (success, received) = peer(Reply::Success);
    let script = script([selected_failure("first open"), success]);
    let response = post(&client, Arc::clone(&script)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"ok");
    assert!(received.await.unwrap().ends_with(QUERY));
    let script = script.lock().unwrap();
    assert_eq!(script.clients.len(), 2);
    assert_ne!(
        script.clients[0], script.clients[1],
        "retry gets a new client isolation context"
    );
    assert_eq!(script.frames_before_open, [0, 0]);
    assert_eq!(script.data_frames.load(Ordering::SeqCst), 1);
    assert!(script.attempts.is_empty());
}

#[tokio::test]
async fn selected_open_failures_exhaust_without_sending_a_post() {
    let (_directory, client) = client();
    let script = script([
        selected_failure("first open"),
        selected_failure("second open"),
        unexpected_attempt(),
    ]);
    let error = post(&client, Arc::clone(&script)).await.unwrap_err();
    assert!(matches!(&error, Error::Io(error) if error.kind() == io::ErrorKind::NotFound));
    assert_eq!(error.to_string(), "IO error: second open");
    let script = script.lock().unwrap();
    assert_eq!(script.clients.len(), 2);
    assert_ne!(script.clients[0], script.clients[1]);
    assert_eq!(script.data_frames.load(Ordering::SeqCst), 0);
    assert_eq!(script.attempts.len(), 1);
}

#[tokio::test]
async fn losing_headers_after_a_post_does_not_replay_it() {
    let (_directory, client) = client();
    let (closed, received) = peer(Reply::NoHeaders);
    let script = script([closed, unexpected_attempt()]);
    assert!(matches!(
        post(&client, Arc::clone(&script)).await,
        Err(Error::Http(HttpError::Hyper(_)))
    ));
    assert!(received.await.unwrap().ends_with(QUERY));
    let script = script.lock().unwrap();
    assert_eq!(script.clients.len(), 1);
    assert_eq!(script.data_frames.load(Ordering::SeqCst), 1);
    assert_eq!(script.attempts.len(), 1);
}

#[tokio::test]
async fn status_and_body_failures_do_not_replay_a_post() {
    for reply in [Reply::Unavailable, Reply::TruncatedBody] {
        let (_directory, client) = client();
        let unavailable = matches!(reply, Reply::Unavailable);
        let (attempt, received) = peer(reply);
        let script = script([attempt, unexpected_attempt()]);
        let response = post(&client, Arc::clone(&script)).await;
        if unavailable {
            assert_eq!(response.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
        } else {
            assert!(matches!(response, Err(Error::Http(HttpError::Hyper(_)))));
        }
        assert!(received.await.unwrap().ends_with(QUERY));
        let script = script.lock().unwrap();
        assert_eq!(script.clients.len(), 1);
        assert_eq!(script.data_frames.load(Ordering::SeqCst), 1);
        assert_eq!(script.attempts.len(), 1);
    }
}

#[tokio::test]
async fn even_a_selected_parser_error_cannot_replay_a_post() {
    let (_directory, client) = client();
    let (attempt, received) = peer(Reply::Success);
    let script = script([attempt, unexpected_attempt()]);
    let data_frames = Arc::clone(&script.lock().unwrap().data_frames);
    let result = ATTEMPT_SCRIPT
        .scope(
            Arc::clone(&script),
            client.http_post(
                "https://service.invalid/query".parse().unwrap(),
                |builder| builder,
                TrackedBody {
                    inner: Full::new(Bytes::from_static(QUERY)),
                    data_frames,
                },
                |body| async {
                    body.collect().await.map_err(HttpError::from)?;
                    Err::<(), Error>(Error::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        "selected parser failure",
                    )))
                },
                1,
                selected_open_failure,
            ),
        )
        .await;
    assert!(matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound));
    assert!(received.await.unwrap().ends_with(QUERY));
    let script = script.lock().unwrap();
    assert_eq!(script.clients.len(), 1);
    assert_eq!(script.data_frames.load(Ordering::SeqCst), 1);
    assert_eq!(script.attempts.len(), 1);
}

#[tokio::test]
async fn http_failures_do_not_start_another_attempt() {
    let failures = [
        HttpError::Tls(io::Error::new(io::ErrorKind::ConnectionReset, "TLS reset")),
        HttpError::Timeout(TimeoutPhase::Connect),
        HttpError::Timeout(TimeoutPhase::Request),
        HttpError::Timeout(TimeoutPhase::ResponseBody),
    ];
    for failure in failures {
        let (_directory, client) = client();
        let script = script([
            ScriptedAttempt::Error(Error::Http(failure)),
            unexpected_attempt(),
        ]);
        assert!(matches!(
            post(&client, Arc::clone(&script)).await,
            Err(Error::Http(_))
        ));
        let script = script.lock().unwrap();
        assert_eq!(script.clients.len(), 1);
        assert_eq!(script.data_frames.load(Ordering::SeqCst), 0);
        assert_eq!(script.attempts.len(), 1);
    }
}

#[tokio::test]
async fn cancellation_drops_the_pending_recovery_without_a_post() {
    let (_directory, client) = client();
    let dropped = Arc::new(AtomicBool::new(false));
    let script = script([
        selected_failure("first open"),
        ScriptedAttempt::Pending(Arc::clone(&dropped)),
        unexpected_attempt(),
    ]);
    let mut request = Box::pin(post(&client, Arc::clone(&script)));
    poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(script.lock().unwrap().clients.len(), 2);
    assert!(!dropped.load(Ordering::SeqCst));
    drop(request);
    assert!(dropped.load(Ordering::SeqCst));
    let script = script.lock().unwrap();
    assert_eq!(script.clients.len(), 2);
    assert_eq!(script.attempts.len(), 1);
    assert_eq!(script.data_frames.load(Ordering::SeqCst), 0);
}

#[test]
fn name_resolution_classifier_rejects_non_dns_tor_and_http_errors() {
    for address in [
        arti_client::TorAddrError::InvalidHostname,
        arti_client::TorAddrError::NoPort,
        arti_client::TorAddrError::BadPort,
    ] {
        assert!(!Error::Tor(address.into()).is_tor_name_resolution_failure());
    }
    for phase in [
        TimeoutPhase::Connect,
        TimeoutPhase::Request,
        TimeoutPhase::ResponseBody,
    ] {
        assert!(!Error::Http(HttpError::Timeout(phase)).is_tor_name_resolution_failure());
    }
    assert!(
        !Error::Http(HttpError::Tls(io::Error::new(
            io::ErrorKind::NotFound,
            "TLS error"
        )))
        .is_tor_name_resolution_failure()
    );
    assert!(
        !Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "IO sentinel is not DNS classification"
        ))
        .is_tor_name_resolution_failure()
    );
    assert!(!Error::MissingTorDirectory.is_tor_name_resolution_failure());
}
