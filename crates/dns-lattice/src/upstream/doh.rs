//! DNS-over-HTTPS upstream backend (RFC 8484), behind the `doh` Cargo
//! feature. Per ADR-0012 (`DL-A-13`): HTTP transport via `hyper`/
//! `hyper-rustls` (coupled to the same `rustls` TLS stack the `dot`
//! feature uses), supporting the GET wire format (RFC 8484 §4.1's
//! base64url `dns` query parameter) and the POST wire format
//! (`application/dns-message` body).

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::Message;
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use tokio::time::timeout;

use super::UpstreamBackend;

/// The DoH request's HTTP method (RFC 8484 §4.1). Both wire formats carry
/// the DNS query in `application/dns-message` wire format; they differ
/// only in how the request body is transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    /// GET with the base64url-encoded query in the `dns` URI query
    /// parameter (RFC 8484 §4.1, second bullet).
    Get,
    /// POST with the raw wire-format query as the request body and
    /// `content-type: application/dns-message` (RFC 8484 §4.1, first
    /// bullet).
    Post,
}

/// Configuration for [`DohBackend`].
#[derive(Clone)]
pub struct DohBackendConfig {
    /// The DoH endpoint URI, e.g. `https://dns.example/dns-query`.
    pub uri: Uri,
    /// Which RFC 8484 wire format to use for each request.
    pub method: DohMethod,
    /// The `rustls` client configuration used to establish the
    /// HTTPS connection's TLS session.
    pub tls_config: Arc<ClientConfig>,
    /// Bounds the whole request (connect, TLS handshake, send, and
    /// receive the response).
    pub timeout: Duration,
}

/// DNS-over-HTTPS upstream backend (RFC 8484), gated behind the `doh`
/// Cargo feature. Follows the same `Config` + `Backend` +
/// `#[async_trait] impl UpstreamBackend` pattern as [`super::UdpBackend`]/
/// [`super::TcpBackend`]/`DotBackend` (ADR-0011/ADR-0012); adds no fields
/// or methods to the [`UpstreamBackend`] trait itself.
///
/// TLS-layer failures during the underlying HTTPS connection map to
/// [`Error::Tls`]; HTTP-level failures (non-2xx status, malformed
/// `application/dns-message` body, or a connection-level failure below
/// TLS as surfaced by `hyper`) map to [`Error::Transport`] (ADR-0012).
pub struct DohBackend {
    config: DohBackendConfig,
}

impl DohBackend {
    /// Builds a DoH backend from `config`.
    pub fn new(config: DohBackendConfig) -> Self {
        Self { config }
    }

    fn build_request(&self, query: &Message) -> Result<Request<Full<Bytes>>> {
        let payload = query.encode()?;

        match self.config.method {
            DohMethod::Post => Request::builder()
                .method("POST")
                .uri(self.config.uri.clone())
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(Full::new(Bytes::from(payload)))
                .map_err(|err| Error::Transport(err.to_string())),
            DohMethod::Get => {
                let encoded = URL_SAFE_NO_PAD.encode(&payload);
                let mut parts = self.config.uri.clone().into_parts();
                let path = parts
                    .path_and_query
                    .as_ref()
                    .map(|pq| pq.path())
                    .unwrap_or("/");
                let separator = if path.contains('?') { '&' } else { '?' };
                let path_and_query = format!("{path}{separator}dns={encoded}");
                parts.path_and_query = Some(
                    http::uri::PathAndQuery::from_str(&path_and_query)
                        .map_err(|err| Error::Transport(err.to_string()))?,
                );
                let uri =
                    Uri::from_parts(parts).map_err(|err| Error::Transport(err.to_string()))?;

                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("accept", "application/dns-message")
                    .body(Full::new(Bytes::new()))
                    .map_err(|err| Error::Transport(err.to_string()))
            }
        }
    }
}

#[async_trait]
impl UpstreamBackend for DohBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let https = HttpsConnectorBuilder::new()
            .with_tls_config((*self.config.tls_config).clone())
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        let request = self.build_request(query)?;

        let response = timeout(self.config.timeout, client.request(request))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(map_hyper_error)?;

        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "doh server returned http status {}",
                response.status()
            )));
        }

        let body = timeout(self.config.timeout, response.into_body().collect())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?
            .to_bytes();

        Message::decode(&body)
    }
}

/// Maps a `hyper_util` client error to [`Error::Tls`] if it stemmed from
/// the TLS layer, or [`Error::Transport`] otherwise (ADR-0012's DoH
/// mapping: "the HTTP client crate's own error taxonomy determines exactly
/// which category a given failure falls into").
fn map_hyper_error<E: std::error::Error + 'static>(err: E) -> Error {
    if error_chain_is_tls(&err) {
        Error::Tls(err.to_string())
    } else {
        Error::Transport(err.to_string())
    }
}

/// Walks `err`'s `source()` chain, additionally descending into any
/// `std::io::Error` node's own inner boxed error (which `io::Error` does
/// not expose via `Error::source()`), looking for a `rustls::Error`
/// (`hyper-rustls` reports TLS handshake/certificate failures as an
/// `io::Error` wrapping a `rustls::Error`, not as a `rustls::Error`
/// directly reachable via `source()`).
fn error_chain_is_tls(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(node) = current {
        if node.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        if let Some(io_err) = node.downcast_ref::<std::io::Error>()
            && let Some(inner) = io_err.get_ref()
            && error_chain_is_tls(inner)
        {
            return true;
        }
        current = node.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_lattice_model::{Class, Header, Name, Opcode, Question, Rcode, RecordType};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};

    fn query_for(name: &str) -> Message {
        Message {
            header: Header {
                id: 11,
                qr: false,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: Name::from_ascii(name).unwrap(),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn answer_for(name: &str, id: u16) -> Message {
        let mut msg = query_for(name);
        msg.header.id = id;
        msg.header.qr = true;
        msg
    }

    fn self_signed_fixture() -> (ServerConfig, ClientConfig) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        (server_config, client_config)
    }

    /// Minimal, single-request, loopback-only HTTP/1.1-over-TLS responder:
    /// reads one HTTP request off the TLS stream (headers-only, i.e. GET,
    /// or with a `content-length` body for POST) and writes back a fixed
    /// `application/dns-message` 200 response carrying `response`. Fully
    /// offline/deterministic per `@.claude/rules/ci.md` — no real network
    /// I/O, no external HTTP crate on the server side.
    async fn serve_one_doh_response(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        response: Message,
    ) {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let n = tls_stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before headers were complete");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
        };

        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_length: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim().eq_ignore_ascii_case("content-length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        while buf.len() < header_end + content_length {
            let n = tls_stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before body was complete");
            buf.extend_from_slice(&chunk[..n]);
        }

        let bytes = response.encode().unwrap();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            bytes.len()
        );
        tls_stream
            .write_all(http_response.as_bytes())
            .await
            .unwrap();
        tls_stream.write_all(&bytes).await.unwrap();
        tls_stream.shutdown().await.unwrap();
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[tokio::test]
    async fn doh_backend_resolves_with_get_against_a_loopback_https_server() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_answer = answer_for("example.com", 0);
        let responder = tokio::spawn(serve_one_doh_response(listener, acceptor, expected_answer));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("doh backend resolves over get");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_resolves_with_post_against_a_loopback_https_server() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_answer = answer_for("example.com", 0);
        let responder = tokio::spawn(serve_one_doh_response(listener, acceptor, expected_answer));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Post,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("doh backend resolves over post");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_returns_tls_error_on_untrusted_certificate() {
        let (server_config, _matching_client_config) = self_signed_fixture();
        let (_other_server_config, untrusting_client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp_stream).await;
        });

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(untrusting_client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("untrusted certificate fails the tls handshake");
        assert!(
            matches!(err, Error::Tls(_)),
            "expected Tls error, got {err:?}"
        );
        let _ = responder.await;
    }

    #[tokio::test]
    async fn doh_backend_transport_error_on_non_success_status() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = tls_stream.read(&mut buf).await.unwrap();
            let response = b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            tls_stream.write_all(response).await.unwrap();
            tls_stream.shutdown().await.unwrap();
        });

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a non-2xx status is a transport-level failure");
        assert!(matches!(err, Error::Transport(_)));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_transport_error_on_connect_failure() {
        let (_server_config, client_config) = self_signed_fixture();

        let placeholder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = placeholder.local_addr().unwrap();
        drop(placeholder);

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("connecting to a closed port fails");
        assert!(matches!(err, Error::Transport(_)));
    }
}
