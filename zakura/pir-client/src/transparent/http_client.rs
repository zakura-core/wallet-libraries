//! Buffered requests over the reference blocking HTTP agent.

use std::{sync::Arc, time::Duration};

use ureq::{Agent, config::AutoHeaderValue, http};

#[derive(Clone)]
pub(super) struct Client {
    agent: Agent,
    timeout: Duration,
}

impl Client {
    pub(super) fn new(timeout: Duration, user_agent: Option<&str>) -> Result<Self, ureq::Error> {
        if let Some(value) = user_agent {
            http::HeaderValue::from_str(value).map_err(|error| ureq::Error::Http(error.into()))?;
        }
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .user_agent(user_agent.map_or(AutoHeaderValue::None, AutoHeaderValue::from))
            .build();
        Ok(Self {
            agent: Agent::new_with_config(config),
            timeout,
        })
    }

    pub(super) fn get(&self, url: impl Into<String>) -> Request {
        self.request(http::Method::GET, url.into())
    }

    pub(super) fn post(&self, url: impl Into<String>) -> Request {
        self.request(http::Method::POST, url.into())
    }

    fn request(&self, method: http::Method, url: String) -> Request {
        Request {
            client: self.clone(),
            method,
            url,
            headers: vec![],
            body: Arc::new(vec![]),
            timeout: self.timeout,
        }
    }

    #[cfg(test)]
    pub(super) fn without_proxy(mut self) -> Self {
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(self.timeout))
            .user_agent(self.agent.config().user_agent().clone())
            .proxy(None)
            .build();
        self.agent = Agent::new_with_config(config);
        self
    }
}

// The body is shared between attempts, without copying private query bytes.
#[derive(Clone)]
pub(super) struct Request {
    client: Client,
    method: http::Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Arc<Vec<u8>>,
    timeout: Duration,
}

impl Request {
    pub(super) fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Arc::new(body.into());
        self
    }

    pub(super) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub(super) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn build(&self) -> Result<http::Request<&[u8]>, ureq::Error> {
        let mut request = http::Request::builder()
            .method(self.method.clone())
            .uri(&self.url);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        request
            .body(self.body.as_slice())
            .map_err(ureq::Error::Http)
    }

    pub(super) fn send(self) -> Result<http::Response<ureq::Body>, ureq::Error> {
        let request = self
            .client
            .agent
            .configure_request(self.build()?)
            .timeout_global(Some(self.timeout))
            .build();
        self.client.agent.run(request)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::*;

    const CA: &[u8] = include_bytes!("../../testdata/http-tls/ca.der");
    const CERTIFICATE: &[u8] = include_bytes!("../../testdata/http-tls/server.der");
    const KEY: &[u8] = include_bytes!("../../testdata/http-tls/server-key.der");

    #[test]
    fn private_query_redirects_do_not_replay_the_body() {
        for status in [307, 308] {
            let target = TcpListener::bind("127.0.0.1:0").unwrap();
            target.set_nonblocking(true).unwrap();
            let destination = target.local_addr().unwrap();
            let origin = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = origin.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut socket, _) = origin.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 4096);
                }
                let mut query = [0; 7];
                socket.read_exact(&mut query).unwrap();
                assert_eq!(&query, b"private");
                write!(socket, "HTTP/1.1 {status} Redirect\r\nLocation: http://{destination}/query\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            });
            let result = Client::new(Duration::from_secs(5), None)
                .unwrap()
                .without_proxy()
                .post(format!("http://{address}/query"))
                .body("private")
                .send();
            server.join().unwrap();
            assert!(matches!(result, Err(ureq::Error::RedirectFailed)));
            assert_eq!(
                target.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn https_checks_certificate_trust_and_hostname_before_sending_queries() {
        for (trust_ca, valid_hostname) in [(false, true), (true, false), (true, true)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![rustls::pki_types::CertificateDer::from(CERTIFICATE)],
                        rustls::pki_types::PrivatePkcs8KeyDer::from(KEY).into(),
                    )
                    .unwrap();
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, socket);
                let mut headers = Vec::new();
                let accepted = loop {
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Ok(1) => headers.push(byte[0]),
                        _ => break false,
                    }
                    assert!(headers.len() < 4096);
                    if headers.ends_with(b"\r\n\r\n") {
                        break true;
                    }
                };
                if accepted {
                    let mut query = [0; 7];
                    stream.read_exact(&mut query).unwrap();
                    assert_eq!(&query, b"private");
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }
                accepted
            });
            let mut client = Client::new(Duration::from_secs(5), None)
                .unwrap()
                .without_proxy();
            if trust_ca {
                let tls = ureq::tls::TlsConfig::builder()
                    .root_certs(vec![ureq::tls::Certificate::from_der(CA)].into())
                    .build();
                client.agent = Agent::new_with_config(
                    Agent::config_builder()
                        .http_status_as_error(false)
                        .proxy(None)
                        .tls_config(tls)
                        .build(),
                );
            }
            let hostname = if valid_hostname {
                "localhost"
            } else {
                "127.0.0.1"
            };
            let response = client
                .post(format!("https://{hostname}:{port}/query"))
                .body("private")
                .send();
            if trust_ca && valid_hostname {
                let mut bytes = Vec::new();
                response
                    .unwrap()
                    .into_body()
                    .into_reader()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes, b"ok");
            } else {
                assert!(response.is_err());
            }
            assert_eq!(server.join().unwrap(), trust_ca && valid_hostname);
        }
    }
}
