//! DNS-over-HTTPS upstream backend (RFC 8484), behind the `doh` Cargo
//! feature. HTTP transport via `hyper`/`hyper-rustls` (coupled to the same
//! `rustls` TLS stack the `dot` feature uses) negotiates HTTP/1.1 or HTTP/2
//! through TLS ALPN, and supports the GET wire format (RFC 8484 §4.1's
//! base64url `dns` query parameter) and the POST wire format
//! (`application/dns-message` body) on either HTTP version.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Buf;
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

#[cfg(feature = "doh")]
use quinn::crypto::rustls::QuicClientConfig;
#[cfg(feature = "doh")]
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};

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
/// [`super::TcpBackend`]/`DotBackend`; adds no fields
/// or methods to the [`UpstreamBackend`] trait itself.
///
/// TLS-layer failures during the underlying HTTPS connection map to
/// [`Error::Tls`]; HTTP-level failures (non-2xx status, malformed
/// `application/dns-message` body, or a connection-level failure below
/// TLS as surfaced by `hyper`) map to [`Error::Transport`].
pub struct DohBackend {
    config: DohBackendConfig,
}

/// Configuration for [`Doh3Backend`], the HTTP/3-over-QUIC DoH transport.
///
/// HTTP/3 uses UDP/QUIC and TLS 1.3; use [`DohBackendConfig`] for legacy
/// TCP HTTPS clients requiring HTTP/1.1 or HTTP/2 with TLS 1.2 support.
#[derive(Clone)]
pub struct Doh3BackendConfig {
    /// The HTTPS DoH endpoint URI. Its host is used for SNI and its path is
    /// used for the RFC 8484 request target.
    pub uri: Uri,
    /// The resolved UDP socket address of the HTTP/3 endpoint.
    pub server: std::net::SocketAddr,
    /// Which RFC 8484 wire format to use.
    pub method: DohMethod,
    /// TLS trust and client-auth configuration. HTTP/3 fixes ALPN to `h3`.
    pub tls_config: Arc<ClientConfig>,
    /// Bounds QUIC connection setup and the complete HTTP/3 request.
    pub timeout: Duration,
}

/// DNS-over-HTTPS over HTTP/3 (RFC 9114) and QUIC, gated by `doh`.
///
/// This is deliberately separate from [`DohBackend`]: HTTP/3 is UDP/QUIC
/// with TLS 1.3, while [`DohBackend`] preserves TCP HTTP/1.1/HTTP/2 support
/// for legacy clients and TLS 1.2 deployments.
///
/// A QUIC TLS alert is reported as [`Error::Tls`]. A non-success HTTP
/// status, a peer closing the negotiated connection, and other non-TLS QUIC
/// or HTTP/3 failures are [`Error::Transport`]; expiry of `timeout` is
/// [`Error::Timeout`].
pub struct Doh3Backend {
    config: Doh3BackendConfig,
}

impl Doh3Backend {
    /// Builds an HTTP/3 DoH backend from `config`.
    pub fn new(config: Doh3BackendConfig) -> Self {
        Self { config }
    }
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
            .enable_http2()
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

#[async_trait]
impl UpstreamBackend for Doh3Backend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let host = self
            .config
            .uri
            .host()
            .ok_or_else(|| Error::Transport("DoH HTTP/3 URI has no host".to_string()))?;
        let mut tls_config = (*self.config.tls_config).clone();
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        let client_config = QuicClientConfig::try_from(Arc::new(tls_config))
            .map_err(|err| Error::Tls(err.to_string()))?;
        let mut quinn_config = QuinnClientConfig::new(Arc::new(client_config));
        quinn_config.transport_config(Arc::new(quinn::TransportConfig::default()));
        let endpoint = Endpoint::client(match self.config.server {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        })
        .map_err(|err| Error::Transport(err.to_string()))?;
        let connecting = endpoint
            .connect_with(quinn_config, self.config.server, host)
            .map_err(|err| Error::Transport(err.to_string()))?;
        let connection = timeout(self.config.timeout, connecting)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(map_quinn_connection_error)?;
        if connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol)
            .as_deref()
            != Some(b"h3")
        {
            return Err(Error::Tls(
                "HTTP/3 peer did not negotiate ALPN h3".to_string(),
            ));
        }

        let (mut driver, mut sender) = timeout(
            self.config.timeout,
            h3::client::new(h3_quinn::Connection::new(connection)),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
        let driver_task = tokio::spawn(async move { driver.wait_idle().await });
        let request = DohBackend {
            config: DohBackendConfig {
                uri: self.config.uri.clone(),
                method: self.config.method,
                tls_config: self.config.tls_config.clone(),
                timeout: self.config.timeout,
            },
        }
        .build_request(query)?;
        let (parts, body) = request.into_parts();
        let mut stream = timeout(
            self.config.timeout,
            sender.send_request(http::Request::from_parts(parts, ())),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
        let bytes = body.into_inner().unwrap_or_default();
        if !bytes.is_empty() {
            timeout(self.config.timeout, stream.send_data(bytes))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|err| Error::Transport(err.to_string()))?;
        }
        timeout(self.config.timeout, stream.finish())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?;
        let response = timeout(self.config.timeout, stream.recv_response())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "doh HTTP/3 server returned http status {}",
                response.status()
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = timeout(self.config.timeout, stream.recv_data())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?
        {
            body.extend_from_slice(chunk.chunk());
        }
        endpoint.close(0u32.into(), b"request complete");
        driver_task.abort();
        Message::decode(&body)
    }
}

/// Maps QUIC handshake failures onto the crate's stable error boundary.
/// QUIC represents TLS alerts as transport errors in the `0x100..0x200`
/// range (RFC 9000 §20.1), so they remain TLS failures to callers rather
/// than being flattened into generic transport errors.
fn map_quinn_connection_error(err: quinn::ConnectionError) -> Error {
    if let quinn::ConnectionError::TransportError(transport) = &err
        && (0x100..0x200).contains(&u64::from(transport.code))
    {
        return Error::Tls(err.to_string());
    }
    Error::Transport(err.to_string())
}

/// Maps a `hyper_util` client error to [`Error::Tls`] if it stemmed from
/// the TLS layer, or [`Error::Transport`] otherwise. The HTTP client
/// crate's error taxonomy determines which category a given failure falls
/// into.
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
    use hyper::body::Incoming;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use quinn::ServerConfig as QuinnServerConfig;
    use quinn::crypto::rustls::QuicServerConfig;
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

    fn http3_fixture() -> (QuinnServerConfig, ClientConfig) {
        let (mut server_config, client_config) = self_signed_fixture();
        server_config.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicServerConfig::try_from(Arc::new(server_config)).unwrap();
        (
            QuinnServerConfig::with_crypto(Arc::new(crypto)),
            client_config,
        )
    }

    async fn serve_one_doh3_response(
        endpoint: quinn::Endpoint,
        response: Message,
        expected_method: hyper::Method,
    ) {
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let data = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .unwrap();
        assert_eq!(data.protocol.as_deref(), Some(b"h3".as_slice()));
        let mut h3_connection =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (request, mut stream) = resolver.resolve_request().await.unwrap();
        assert_eq!(request.method(), expected_method);
        assert_eq!(request.uri().path(), "/dns-query");
        while stream.recv_data().await.unwrap().is_some() {}
        stream
            .send_response(
                http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("content-type", "application/dns-message")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(Bytes::from(response.encode().unwrap()))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        // Keep the H3 connection alive until the client finishes reading;
        // dropping it immediately sends H3_NO_ERROR before the response can
        // deterministically reach the loopback client.
        let _ = h3_connection.accept().await;
    }

    async fn serve_one_doh3_status(endpoint: quinn::Endpoint, status: http::StatusCode) {
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (_request, mut stream) = resolver.resolve_request().await.unwrap();
        while stream.recv_data().await.unwrap().is_some() {}
        stream
            .send_response(http::Response::builder().status(status).body(()).unwrap())
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let _ = h3_connection.accept().await;
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

    /// Serves one TLS-ALPN-negotiated HTTP/2 DoH request. The assertion on
    /// the selected ALPN protocol makes this an end-to-end HTTP/2 test, not
    /// merely a server-side HTTP/2 parser test.
    async fn serve_one_doh_h2_response(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        response: Message,
        expected_method: hyper::Method,
    ) {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice())
        );

        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let response = response.clone();
            let expected_method = expected_method.clone();
            async move {
                assert_eq!(request.version(), hyper::Version::HTTP_2);
                assert_eq!(request.method(), expected_method);
                assert_eq!(request.uri().path(), "/dns-query");
                let _ = request.into_body().collect().await.unwrap();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/dns-message")
                        .body(Full::new(Bytes::from(response.encode().unwrap())))
                        .unwrap(),
                )
            }
        });

        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls_stream), service)
            .await
            .unwrap();
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
    async fn doh_backend_resolves_with_get_over_http2() {
        let (mut server_config, client_config) = self_signed_fixture();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh_h2_response(
            listener,
            acceptor,
            answer_for("example.com", 0),
            hyper::Method::GET,
        ));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_resolves_with_post_over_http2() {
        let (mut server_config, client_config) = self_signed_fixture();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh_h2_response(
            listener,
            acceptor,
            answer_for("example.com", 0),
            hyper::Method::POST,
        ));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Post,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_resolves_with_get_over_http3() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh3_response(
            endpoint,
            answer_for("example.com", 0),
            hyper::Method::GET,
        ));
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });
        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_resolves_with_post_over_http3() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh3_response(
            endpoint,
            answer_for("example.com", 0),
            hyper::Method::POST,
        ));
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Post,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });
        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_returns_transport_error_on_non_success_status() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh3_status(
            endpoint,
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ));
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a non-2xx HTTP/3 status is a transport failure");
        assert!(matches!(err, Error::Transport(_)), "got {err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_returns_tls_error_on_untrusted_certificate() {
        let (server_config, _trusted_client_config) = http3_fixture();
        let (_other_server_config, untrusted_client_config) = self_signed_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let _ = incoming.await;
        });
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(untrusted_client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("an untrusted HTTP/3 certificate fails TLS");
        assert!(matches!(err, Error::Tls(_)), "got {err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_times_out_when_server_never_completes_handshake() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            // Keeping the endpoint alive without polling `accept` prevents a
            // server handshake while retaining a deterministic local UDP peer.
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(endpoint);
        });
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_millis(30),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("an incomplete HTTP/3 handshake must time out");
        assert!(matches!(err, Error::Timeout), "got {err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_returns_transport_when_peer_closes_after_handshake() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            connection.close(0u32.into(), b"test peer closed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a peer closing a negotiated HTTP/3 connection is transport failure");
        assert!(matches!(err, Error::Transport(_)), "got {err:?}");
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
    async fn doh_backend_returns_transport_when_peer_closes_before_tls() {
        let (_server_config, client_config) = self_signed_fixture();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://127.0.0.1:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a peer that closes before TLS is a transport failure");
        assert!(matches!(err, Error::Transport(_)));
        responder.await.unwrap();
    }
}
