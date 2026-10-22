//! HTTP transport and the service's JSON metadata shapes.
//!
//! The request carries chain identity, profile and a height range, and nothing
//! else. There is no field in which a script, address, outpoint or match could
//! travel, by construction rather than by convention.

use std::io::Read;
use std::time::Duration;

use crate::transparent::filter::envelope::{FilterBatch, MAX_BATCH_BYTES};
use crate::transparent::filter::error::FilterError;
use crate::transparent::filter::transport::{ByteCharges, FilterTransport, RangeRequest};
use crate::transparent::filter::wire::{ChainEntry, FilterServiceHealth, FilterServiceInfo};
use crate::transparent::routes;
use zakura_pir_protocol::endpoint::Endpoint;

// Metadata has a fixed shape; range and chain responses use the batch byte limit.
const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_ERROR_BYTES: u64 = 800;

/// Fetches ranges over HTTP, from Transparent routes below one server base.
pub struct HttpTransport {
    base_url: String,
    /// `base_url`, parsed; every request addresses a Transparent route below it.
    endpoint: Endpoint,
    client: reqwest::blocking::Client,
    timeout: Duration,
}

impl HttpTransport {
    /// The filter service below the server base `base_url`, whose path prefix
    /// every request keeps. Refuses a base [`Endpoint::parse`] refuses.
    pub fn new(base_url: impl Into<String>) -> Result<Self, FilterError> {
        let base_url = base_url.into();
        let endpoint = Endpoint::parse(&base_url)
            .map_err(|error| FilterError::Response(format!("{base_url}: {error}")))?;
        let timeout = Duration::from_secs(120);
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| FilterError::Response(error.to_string()))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            endpoint,
            client,
            timeout,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The URL of a Transparent `operation`, with an optional `query` string.
    fn url(&self, operation: &str, query: Option<String>) -> Result<String, FilterError> {
        let url = routes::url(&self.endpoint, operation)
            .map_err(|error| FilterError::Response(format!("{operation}: {error}")))?;
        Ok(match query {
            Some(query) => format!("{url}?{query}"),
            None => url,
        })
    }

    fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, FilterError> {
        let response = self
            .client
            .get(url)
            // The request timeout reaches the asynchronous body reader as an
            // absolute deadline. The blocking client's default alone is reset
            // on each Read call and would allow a peer to drip bytes forever.
            .timeout(self.timeout)
            .send()
            .map_err(|error| FilterError::Response(format!("{url}: {error}")))?;
        let status = response.status();
        if !status.is_success() {
            // Only the diagnostic prefix is useful. Do not consume an arbitrary
            // error body or wait for its end before returning the HTTP error.
            let mut prefix = Vec::new();
            response
                .take(MAX_ERROR_BYTES)
                .read_to_end(&mut prefix)
                .map_err(|error| FilterError::Response(format!("{url}: {error}")))?;
            return Err(FilterError::Response(format!(
                "{url}: HTTP {status}: {}",
                String::from_utf8_lossy(&prefix)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )));
        }
        let limit_error =
            || FilterError::LimitExceeded(format!("{url}: response exceeds {max_bytes} bytes"));
        let max_bytes_u64 = u64::try_from(max_bytes).map_err(|_| limit_error())?;
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes_u64)
        {
            return Err(limit_error());
        }
        // Content-Length may be absent or dishonest. The extra byte detects
        // an oversized streamed body without buffering the rest of it.
        let read_limit = max_bytes_u64.checked_add(1).ok_or_else(limit_error)?;
        let mut bytes = Vec::new();
        response
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|error| FilterError::Response(format!("{url}: {error}")))?;
        if bytes.len() > max_bytes {
            return Err(limit_error());
        }
        Ok(bytes)
    }

    pub fn info(&self) -> Result<FilterServiceInfo, FilterError> {
        let bytes = self.get(&self.url("/filters/info", None)?, MAX_METADATA_BYTES)?;
        serde_json::from_slice(&bytes)
            .map_err(|error| FilterError::Response(format!("info: {error}")))
    }

    pub fn health(&self) -> Result<FilterServiceHealth, FilterError> {
        let bytes = self.get(&self.url("/health", None)?, MAX_METADATA_BYTES)?;
        serde_json::from_slice(&bytes)
            .map_err(|error| FilterError::Response(format!("health: {error}")))
    }

    /// Height-to-hash for a range.
    ///
    /// A real wallet has its own accepted chain and must not take this from the
    /// same service that supplies the filters. It exists so the reference
    /// client can be exercised end to end against a live service.
    pub fn chain(&self, start_height: u64, count: u64) -> Result<Vec<ChainEntry>, FilterError> {
        let url = self.url(
            "/filters/chain",
            Some(format!("start_height={start_height}&count={count}")),
        )?;
        let bytes = self.get(&url, MAX_BATCH_BYTES)?;
        serde_json::from_slice(&bytes)
            .map_err(|error| FilterError::Response(format!("chain: {error}")))
    }
}

impl FilterTransport for HttpTransport {
    fn fetch_range(
        &mut self,
        request: &RangeRequest,
    ) -> Result<(FilterBatch, ByteCharges), FilterError> {
        let url = self.url(
            "/filters/range",
            Some(format!(
                "start_height={}&stop_block_hash={}",
                request.start_height,
                request.stop_block_hash.to_display_hex()
            )),
        )?;
        let bytes = self.get(&url, MAX_BATCH_BYTES)?;
        let charges = ByteCharges {
            received: bytes.len() as u64,
            sent: url.len() as u64,
            requests: 1,
        };
        let batch = FilterBatch::decode(&bytes)?;
        Ok((batch, charges))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};

    fn serve(handler: impl FnOnce(TcpStream) + Send + 'static) -> (HttpTransport, JoinHandle<()>) {
        serve_with_timeout(Duration::from_secs(3), handler)
    }

    fn serve_with_timeout(
        timeout: Duration,
        handler: impl FnOnce(TcpStream) + Send + 'static,
    ) -> (HttpTransport, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            handler(stream);
        });
        let base_url = format!("http://{address}");
        let transport = HttpTransport {
            endpoint: Endpoint::parse(&base_url).unwrap(),
            base_url,
            client: reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(timeout)
                .build()
                .unwrap(),
            timeout,
        };
        (transport, worker)
    }

    #[test]
    fn ordinary_metadata_still_decodes_over_http() {
        let body = br#"{"phase":"serving","detail":null,"covered_through":7,"tip_height":7,"filters_stored":2}"#;
        let (transport, worker) = serve(move |mut stream| {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let health = transport.health().unwrap();
        assert_eq!(health.phase, "serving");
        assert_eq!(health.filters_stored, 2);
        worker.join().unwrap();
    }

    #[test]
    fn oversized_content_length_is_refused_before_reading_the_body() {
        let (transport, worker) = serve(|mut stream| {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_METADATA_BYTES + 1
            )
            .unwrap();
        });
        assert!(matches!(
            transport.health(),
            Err(FilterError::LimitExceeded(_))
        ));
        worker.join().unwrap();
    }

    #[test]
    fn chunked_responses_are_bounded_without_content_length() {
        let (transport, worker) = serve(|mut stream| {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let body = vec![b' '; MAX_METADATA_BYTES + 1];
            write!(stream, "{:x}\r\n", body.len()).unwrap();
            // The receiver may close as soon as it has observed the extra byte.
            if stream.write_all(&body).is_ok() {
                let _ = stream.write_all(b"\r\n0\r\n\r\n");
            }
        });
        assert!(matches!(
            transport.health(),
            Err(FilterError::LimitExceeded(_))
        ));
        worker.join().unwrap();
    }

    #[test]
    fn a_slow_stream_cannot_extend_the_whole_request_deadline() {
        let (transport, worker) = serve_with_timeout(Duration::from_millis(300), |mut stream| {
            stream.set_nodelay(true).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            // Each chunk arrives within the blocking Read timeout, but the
            // complete valid response takes longer than the request deadline.
            for _ in 0..12 {
                if stream.write_all(b"1\r\n \r\n").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            let body = br#"{"phase":"serving","detail":null,"covered_through":7,"tip_height":7,"filters_stored":2}"#;
            if write!(stream, "{:x}\r\n", body.len()).is_ok() && stream.write_all(body).is_ok() {
                let _ = stream.write_all(b"\r\n0\r\n\r\n");
            }
        });
        let result = transport.health();
        worker.join().unwrap();
        assert!(
            matches!(result, Err(FilterError::Response(_))),
            "a slow but otherwise valid response must exceed the whole request deadline"
        );
    }

    #[test]
    fn http_errors_return_a_prefix_without_waiting_for_the_body_end() {
        let (done, wait) = mpsc::channel();
        let (transport, worker) = serve(move |mut stream| {
            write!(stream, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", MAX_BATCH_BYTES).unwrap();
            stream.write_all(&[b'x'; MAX_ERROR_BYTES as usize]).unwrap();
            // Deliberately leave the response incomplete until the client has
            // returned. A transport that buffers the body times out instead.
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        let error = transport.health().unwrap_err().to_string();
        done.send(()).unwrap();
        worker.join().unwrap();
        assert!(error.contains("HTTP 500"), "unexpected error: {error}");
        assert!(error.ends_with(&"x".repeat(200)));
    }

    #[test]
    fn requests_keep_the_base_path_below_the_transparent_namespace() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut lines = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                lines.push(
                    String::from_utf8_lossy(&request)
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
            }
            lines
        });
        let transport = HttpTransport::new(format!("http://{address}/edge/")).unwrap();
        assert!(transport.health().is_err());
        assert!(transport.chain(5, 2).is_err());
        assert_eq!(
            worker.join().unwrap(),
            [
                "GET /edge/transparent/v1/health HTTP/1.1",
                "GET /edge/transparent/v1/filters/chain?start_height=5&count=2 HTTP/1.1",
            ],
            "a refused request is not retried on a legacy route"
        );
        assert!(HttpTransport::new("https://pir.example/edge?legacy=1").is_err());
    }
}
