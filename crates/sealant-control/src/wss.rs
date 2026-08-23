//! Secure WebSocket control frontend (ADR-0013).
//!
//! Third frontend beside the Unix socket and stdio, for deployments where the controller and the
//! workspace are on different hosts (Kubernetes). It is **off unless configured** and never
//! replaces the Unix socket: the socket stays the in-workspace path and the readiness signal.
//!
//! Security boundary, in order of enforcement:
//!
//!   1. TLS with mutual authentication. The verifier is `WebPkiClientVerifier` built from the
//!      configured client CA with **no** anonymous fallback: a peer that presents no certificate,
//!      a certificate from another CA, or a certificate without the `clientAuth` extended key
//!      usage is rejected during the handshake — before a single HTTP byte is read. A workspace
//!      that can read its own `serverAuth`-only certificate therefore cannot authenticate as the
//!      control plane.
//!   2. The HTTP upgrade must target exactly [`CONTROL_PATH`]; anything else is answered with a
//!      plain `404` and closed.
//!   3. Bounded resources: a connection semaphore, a handshake deadline, and a WebSocket message
//!      size cap derived from the service's `max_frame_bytes`.
//!
//! Wire: binary messages carry the **exact** length-prefixed Protobuf byte stream the other
//! frontends carry. The WebSocket is adapted into `AsyncRead` + `AsyncWrite` and handed to the
//! unchanged [`handle_connection`], so framing, dispatch, backpressure and connection-scoped
//! channel teardown are the same code on every transport. Nothing in this module logs peer
//! certificates, handshake material or payload bytes.

use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::BufWriter;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_util::io::{CopyToBytes, SinkWriter, StreamReader};

use crate::server::handle_connection;
use crate::service::ControlService;

/// The only path the frontend accepts an upgrade on.
pub const CONTROL_PATH: &str = "/control";

/// Default cap on concurrently open (or handshaking) connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// Default TLS + WebSocket handshake deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Framing prefix plus body; a WebSocket message never needs to be larger than one frame.
const LENGTH_PREFIX_BYTES: usize = 4;

/// Outbound coalescing buffer: `write_frame` writes prefix, body, flush — the buffer turns that
/// into one message per frame for bodies that fit, and a handful for larger ones.
const WRITE_BUFFER_BYTES: usize = 64 * 1024;

/// What the daemon needs to open the frontend. Paths are read once at bind time.
#[derive(Debug, Clone)]
pub struct WssConfig {
    /// Address to bind, e.g. `0.0.0.0:7443`.
    pub listen: SocketAddr,
    /// PEM server certificate chain (leaf first).
    pub cert_path: PathBuf,
    /// PEM private key for the leaf certificate (PKCS#8, PKCS#1 or SEC1).
    pub key_path: PathBuf,
    /// PEM bundle of CA certificates trusted to sign control-plane client certificates.
    pub client_ca_path: PathBuf,
    pub max_connections: usize,
    pub handshake_timeout: Duration,
}

impl WssConfig {
    /// Config with default limits.
    pub fn new(
        listen: SocketAddr,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
        client_ca_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            listen,
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            client_ca_path: client_ca_path.into(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

impl WssConfig {
    /// Parse the operator-facing string form shared by the CLI flags and the `SEALANT_CONTROL_WSS_*`
    /// boot variables. `None` when `listen` is absent (the frontend stays off); an error when it is
    /// present but incomplete or malformed. Messages name keys, never values beyond the listen addr.
    ///
    /// # Errors
    /// Returns a readable message for a bad address, a missing path, or a bad connection limit.
    pub fn from_parts(
        listen: Option<&str>,
        cert_path: Option<&str>,
        key_path: Option<&str>,
        client_ca_path: Option<&str>,
        max_connections: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let Some(listen) = listen.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let listen: SocketAddr = listen
            .parse()
            .map_err(|e| format!("wss listen address '{listen}' is invalid: {e}"))?;
        let require = |value: Option<&str>, what: &str| -> Result<PathBuf, String> {
            value
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| format!("wss is enabled but {what} is not set"))
        };
        let mut config = Self::new(
            listen,
            require(cert_path, "the server certificate path")?,
            require(key_path, "the server key path")?,
            require(client_ca_path, "the client CA path")?,
        );
        if let Some(raw) = max_connections.map(str::trim).filter(|s| !s.is_empty()) {
            config.max_connections = raw
                .parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("wss max connections '{raw}' must be a positive integer"))?;
        }
        Ok(Some(config))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn read_pem_certs(path: &Path, what: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{what} {}: {e}", path.display())))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<_, _>>()
        .map_err(|e| invalid(format!("{what} {}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(invalid(format!(
            "{what} {} contains no certificates",
            path.display()
        )));
    }
    Ok(certs)
}

fn read_pem_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("wss key {}: {e}", path.display())))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|e| invalid(format!("wss key {}: {e}", path.display())))?
        .ok_or_else(|| {
            invalid(format!(
                "wss key {} contains no private key",
                path.display()
            ))
        })
}

/// Build the rustls server configuration: mutual TLS, client certificates required.
fn build_tls_config(config: &WssConfig) -> io::Result<Arc<rustls::ServerConfig>> {
    let certs = read_pem_certs(&config.cert_path, "wss certificate")?;
    let key = read_pem_key(&config.key_path)?;
    let client_roots = {
        let mut roots = rustls::RootCertStore::empty();
        for cert in read_pem_certs(&config.client_ca_path, "wss client CA")? {
            roots
                .add(cert)
                .map_err(|e| invalid(format!("wss client CA: {e}")))?;
        }
        Arc::new(roots)
    };
    // No `allow_unauthenticated()`: anonymous peers fail the handshake.
    let verifier = rustls::server::WebPkiClientVerifier::builder(client_roots)
        .build()
        .map_err(|e| invalid(format!("wss client verifier: {e}")))?;
    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| invalid(format!("wss server certificate: {e}")))?;
    Ok(Arc::new(tls))
}

/// A bound frontend. Binding (and loading TLS material) happens eagerly so misconfiguration is a
/// synchronous, readable error at startup rather than a silently absent listener.
pub struct WssListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    max_connections: usize,
    handshake_timeout: Duration,
}

impl std::fmt::Debug for WssListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WssListener")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("max_connections", &self.max_connections)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl WssListener {
    /// Load TLS material and bind the TCP listener.
    ///
    /// # Errors
    /// Any unreadable/invalid PEM, a CA bundle without certificates, or a bind failure.
    pub async fn bind(config: &WssConfig) -> io::Result<Self> {
        if config.max_connections == 0 {
            return Err(invalid("wss max_connections must be at least 1"));
        }
        let tls = build_tls_config(config)?;
        let listener = TcpListener::bind(config.listen).await?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(tls),
            max_connections: config.max_connections,
            handshake_timeout: config.handshake_timeout,
        })
    }

    /// The bound address (useful when the configured port was 0).
    ///
    /// # Errors
    /// Propagates the socket's `local_addr` failure.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept and serve connections until shutdown is signalled. On shutdown the listener stops
    /// accepting, every live connection observes the same signal through `handle_connection`, and
    /// the remaining tasks are joined (aborted after a short grace).
    pub async fn serve<S: ControlService>(
        self,
        service: Arc<S>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let max_frame_bytes = service.max_frame_bytes();
        let permits = Arc::new(Semaphore::new(self.max_connections));
        let mut connections = JoinSet::new();
        tracing::info!(addr = ?self.listener.local_addr().ok(), "control wss listening");

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                // Reap finished connection tasks so the set does not grow without bound.
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                accepted = self.listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::warn!(error = %e, "wss accept failed");
                            continue;
                        }
                    };
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        tracing::warn!(%peer, "wss connection limit reached; refusing");
                        drop(stream);
                        continue;
                    };
                    let acceptor = self.acceptor.clone();
                    let service = service.clone();
                    let shutdown = shutdown.clone();
                    let handshake_timeout = self.handshake_timeout;
                    connections.spawn(async move {
                        let _permit = permit;
                        let handshake = tokio::time::timeout(
                            handshake_timeout,
                            accept_control_socket(acceptor, stream, max_frame_bytes),
                        );
                        let websocket = match handshake.await {
                            Ok(Ok(ws)) => ws,
                            Ok(Err(error)) => {
                                // Error *kinds* only; rustls errors never include peer material.
                                tracing::warn!(%peer, %error, "wss handshake rejected");
                                return;
                            }
                            Err(_) => {
                                tracing::warn!(%peer, "wss handshake timed out");
                                return;
                            }
                        };
                        tracing::debug!(%peer, "wss control connection established");
                        let (sink, stream) = websocket.split();
                        let reader = StreamReader::new(
                            stream.filter_map(|message| futures::future::ready(message_to_bytes(message))),
                        );
                        let writer = BufWriter::with_capacity(
                            WRITE_BUFFER_BYTES,
                            SinkWriter::new(CopyToBytes::new(
                                sink.sink_map_err(|e: tokio_tungstenite::tungstenite::Error| {
                                    io::Error::new(io::ErrorKind::BrokenPipe, e)
                                })
                                .with(|bytes: bytes_shim::Bytes| {
                                    futures::future::ready(Ok::<_, io::Error>(Message::Binary(bytes)))
                                }),
                            )),
                        );
                        handle_connection(service, reader, writer, shutdown).await;
                        tracing::debug!(%peer, "wss control connection closed");
                    });
                }
            }
        }

        // Drain: connections see the same shutdown receiver and unwind on their own; give them a
        // moment, then abort whatever is still handshaking or blocked.
        let grace = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(grace);
        loop {
            tokio::select! {
                _ = &mut grace => break,
                next = connections.join_next() => {
                    if next.is_none() {
                        break;
                    }
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        tracing::info!("control wss closed");
    }
}

/// `bytes` is re-exported by tungstenite; alias it so the workspace does not grow a direct dep.
mod bytes_shim {
    pub(super) use tokio_tungstenite::tungstenite::Bytes;
}

type ControlSocket =
    tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>;

/// TLS handshake (mutual auth enforced by the verifier) then the WebSocket upgrade on [`CONTROL_PATH`].
// The callback's error type is fixed by tungstenite's `Callback` trait.
#[allow(clippy::result_large_err)]
async fn accept_control_socket(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    max_frame_bytes: u32,
) -> Result<ControlSocket, tokio_tungstenite::tungstenite::Error> {
    let tls = acceptor.accept(stream).await?;
    let max_message = max_frame_bytes as usize + LENGTH_PREFIX_BYTES;
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message))
        .accept_unmasked_frames(false);
    let callback = |request: &Request, response: Response| {
        if request.uri().path() == CONTROL_PATH {
            Ok(response)
        } else {
            let mut refusal = tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(
                Some("not found".to_owned()),
            );
            *refusal.status_mut() = StatusCode::NOT_FOUND;
            Err(refusal)
        }
    };
    tokio_tungstenite::accept_hdr_async_with_config(tls, callback, Some(ws_config)).await
}

/// Inbound message → bytes for the frame reader. Binary carries protocol bytes; a Close (or a
/// transport error) ends the stream as EOF/error; text and control frames are ignored (pings are
/// answered by tungstenite when the stream is polled).
fn message_to_bytes(
    message: Result<Message, tokio_tungstenite::tungstenite::Error>,
) -> Option<io::Result<bytes_shim::Bytes>> {
    match message {
        Ok(Message::Binary(bytes)) => Some(Ok(bytes)),
        Ok(Message::Close(_)) => None,
        Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => None,
        Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
        | Err(tokio_tungstenite::tungstenite::Error::AlreadyClosed) => None,
        Err(e) => Some(Err(io::Error::new(io::ErrorKind::ConnectionAborted, e))),
    }
}

/// Convenience: bind then serve. Prefer [`WssListener::bind`] + [`WssListener::serve`] when the
/// caller wants bind failures surfaced before the rest of startup proceeds.
///
/// # Errors
/// See [`WssListener::bind`].
pub async fn serve_wss<S: ControlService>(
    service: Arc<S>,
    config: &WssConfig,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = WssListener::bind(config).await?;
    listener.serve(service, shutdown).await;
    Ok(())
}
