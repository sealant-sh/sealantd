//! Transport policy for the two outbound HTTP paths of a capture session: the session channel
//! ([`crate::registrar::HttpRegistrar`]) and presigned object URLs ([`crate::sink::PresignedHttp`]).
//!
//! The channel carries the session token and answers with the URLs every capture is shipped to,
//! so whoever can read or answer it holds the session. The policy therefore fails closed: a URL is
//! dialled only over HTTPS with a verified certificate, unless it names this machine's loopback or
//! the launcher said in so many words that the network between the executor and the channel is
//! private ([`ChannelTransport::allow_plaintext`]). Nothing here can turn certificate verification
//! off, and no redirect is followed: a channel or a presigned URL that answers 3xx is refused like
//! any other unexpected status, so an answer can never move a request to a host or scheme this
//! policy did not check.
//!
//! Where the executor reaches the platform through a local socket instead of the network
//! ([`Dial`]: a Unix socket on the `docker` runtime, `AF_VSOCK` to the host on `host-vm`), every
//! request is written to that socket unchanged: the same request line, and the `Host` header the
//! URL names (`Host: garage:3900`, `Host: mend:3106`), because a presigned URL's signature covers
//! the host it was signed for and the relay behind the socket forwards it as it is. Plain HTTP is
//! then dialled to any host: the bytes go no further than this machine's socket, to a relay the
//! platform runs.
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ureq::http::Uri;
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig, parse_pem};

/// Why a URL is not dialled, or why the policy could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransportError {
    /// Not a URL with a host.
    #[error("{what} is not an http(s) URL with a host")]
    Malformed {
        /// What the URL was for (never the URL: a presigned URL is a credential).
        what: &'static str,
    },
    /// A scheme other than `https` (or an allowed `http`).
    #[error("{what} uses the {scheme} scheme; only https is dialled")]
    Scheme {
        /// What the URL was for.
        what: &'static str,
        /// The scheme it named.
        scheme: String,
    },
    /// Plain HTTP to something other than loopback, without the explicit exception.
    #[error(
        "{what} is plain http to {host}: refused. Serve it over https (SEALANT_CAPTURE_CA_FILE or \
         SEALANT_CAPTURE_CA_PEM names a private CA), or set SEALANT_CAPTURE_ALLOW_PLAINTEXT=true \
         when the network between this executor and {host} is private"
    )]
    Plaintext {
        /// What the URL was for.
        what: &'static str,
        /// The host it named (a host is not a credential; the path and query may be).
        host: String,
    },
    /// The CA bundle held no certificate, or could not be read.
    #[error("channel CA bundle: {0}")]
    CaBundle(String),
    /// A [`Dial`] spelling that is not `tcp`, `unix:<path>` or `vsock:<cid>:<port>`.
    #[error("capture dial {0:?} is not tcp, unix:<absolute path> or vsock:<cid>:<port>")]
    Dial(String),
}

/// How a request reaches the host its URL names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Dial {
    /// A TCP connection to the URL's host and port, resolved by DNS. The default.
    #[default]
    Tcp,
    /// A Unix socket (`/run/sealant/capture.sock` on the `docker` runtime) whose relay forwards
    /// each request, unchanged, to the host its `Host` header names.
    Unix(PathBuf),
    /// `AF_VSOCK` to `cid:port` (`2:1025`, the host's capture relay, on `host-vm`), likewise.
    Vsock {
        /// The peer's context id.
        cid: u32,
        /// The peer's port.
        port: u32,
    },
}

impl Dial {
    /// Parse `tcp`, `unix:<absolute path>` or `vsock:<cid>:<port>` (`SEALANT_CAPTURE_DIAL`).
    /// Empty is [`Dial::Tcp`].
    ///
    /// # Errors
    /// [`TransportError::Dial`] for anything else.
    pub fn parse(spec: &str) -> Result<Self, TransportError> {
        let spec = spec.trim();
        let refuse = || TransportError::Dial(spec.to_owned());
        if spec.is_empty() || spec == "tcp" {
            return Ok(Self::Tcp);
        }
        if let Some(path) = spec.strip_prefix("unix:") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(refuse());
            }
            return Ok(Self::Unix(path));
        }
        if let Some(rest) = spec.strip_prefix("vsock:") {
            let (cid, port) = rest.split_once(':').ok_or_else(refuse)?;
            let cid = cid.parse().map_err(|_| refuse())?;
            let port = port.parse().map_err(|_| refuse())?;
            return Ok(Self::Vsock { cid, port });
        }
        Err(refuse())
    }

    /// Whether requests go to a local socket rather than over the network.
    #[must_use]
    pub fn is_local(&self) -> bool {
        !matches!(self, Self::Tcp)
    }
}

/// How this session's outbound HTTP is dialled. Built once at boot from the environment.
#[derive(Clone, Default)]
pub struct ChannelTransport {
    allow_plaintext: bool,
    dial: Dial,
    channel_roots: Option<Arc<Vec<Certificate<'static>>>>,
    object_roots: Option<Arc<Vec<Certificate<'static>>>>,
}

impl std::fmt::Debug for ChannelTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelTransport")
            .field("allow_plaintext", &self.allow_plaintext)
            .field("dial", &self.dial)
            .field(
                "channel_roots",
                &self.channel_roots.as_ref().map(|roots| roots.len()),
            )
            .field(
                "object_roots",
                &self.object_roots.as_ref().map(|roots| roots.len()),
            )
            .finish()
    }
}

impl ChannelTransport {
    /// HTTPS with the bundled public roots; plain HTTP to loopback only.
    #[must_use]
    pub fn verified() -> Self {
        Self::default()
    }

    /// The explicit exception (`SEALANT_CAPTURE_ALLOW_PLAINTEXT`): plain HTTP is dialled to any
    /// host. For a private network between the executor and the channel, and for development.
    #[must_use]
    pub fn allow_plaintext(mut self, allow: bool) -> Self {
        self.allow_plaintext = allow;
        self
    }

    /// Trust exactly the certificates in this PEM bundle for the session channel
    /// (`SEALANT_CAPTURE_CA_FILE`, `SEALANT_CAPTURE_CA_PEM`), in place of the public roots: a
    /// channel behind a private CA, and nothing a public CA signs can stand in for it. Presigned
    /// object URLs keep their own roots ([`ChannelTransport::with_object_ca_pem`]).
    ///
    /// # Errors
    /// [`TransportError::CaBundle`] when the bundle holds no certificate.
    pub fn with_channel_ca_pem(mut self, pem: &str) -> Result<Self, TransportError> {
        let roots = certificates_in(pem)?;
        self.channel_roots = Some(Arc::new(roots));
        Ok(self)
    }

    /// Trust exactly the certificates in this PEM bundle for presigned object URLs
    /// (`SEALANT_CAPTURE_OBJECT_CA_FILE`, `SEALANT_CAPTURE_OBJECT_CA_PEM`), in place of the public
    /// roots: an object store behind a private CA, so a private install is not pushed onto the
    /// plaintext exception.
    ///
    /// # Errors
    /// [`TransportError::CaBundle`] when the bundle holds no certificate.
    pub fn with_object_ca_pem(mut self, pem: &str) -> Result<Self, TransportError> {
        let roots = certificates_in(pem)?;
        self.object_roots = Some(Arc::new(roots));
        Ok(self)
    }

    /// Send every request through `dial` instead of TCP: the request, its `Host` header and,
    /// for HTTPS, its TLS server name stay those of the URL.
    #[must_use]
    pub fn dial_via(mut self, dial: Dial) -> Self {
        self.dial = dial;
        self
    }

    /// How requests are dialled.
    #[must_use]
    pub fn dial(&self) -> &Dial {
        &self.dial
    }

    /// Whether plain HTTP beyond loopback is dialled: the explicit exception, or a local socket
    /// ([`Dial::is_local`]).
    #[must_use]
    pub fn plaintext_allowed(&self) -> bool {
        self.allow_plaintext || self.dial.is_local()
    }

    /// Refuse a URL this policy does not dial. `what` names its purpose for the error.
    ///
    /// # Errors
    /// The matching [`TransportError`].
    pub fn check(&self, what: &'static str, url: &str) -> Result<(), TransportError> {
        let uri: Uri = url
            .parse()
            .map_err(|_| TransportError::Malformed { what })?;
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or(TransportError::Malformed { what })?;
        match uri.scheme_str() {
            Some("https") => Ok(()),
            Some("http") if self.plaintext_allowed() || is_loopback(host) => Ok(()),
            Some("http") => Err(TransportError::Plaintext {
                what,
                host: host.to_owned(),
            }),
            Some(other) => Err(TransportError::Scheme {
                what,
                scheme: other.to_owned(),
            }),
            None => Err(TransportError::Malformed { what }),
        }
    }

    /// The agent for the session channel: no redirects, the channel's roots.
    pub(crate) fn channel_agent(&self, timeout: Duration) -> ureq::Agent {
        self.agent(timeout, self.channel_roots.clone())
    }

    /// The agent for presigned object URLs: no redirects, the object roots.
    pub(crate) fn object_agent(&self, timeout: Duration) -> ureq::Agent {
        self.agent(timeout, self.object_roots.clone())
    }

    fn agent(
        &self,
        timeout: Duration,
        roots: Option<Arc<Vec<Certificate<'static>>>>,
    ) -> ureq::Agent {
        let tls = TlsConfig::builder()
            .root_certs(roots.map_or(RootCerts::WebPki, RootCerts::Specific))
            .disable_verification(false)
            .build();
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            // A 3xx is returned as the answer, and every caller refuses it: a redirect would
            // otherwise reach a host or scheme `check` never saw.
            .max_redirects(0)
            // Proxy variables in the daemon's environment are not honoured: a plain-HTTP request
            // this policy allowed because it names loopback would otherwise be handed, token and
            // all, to whatever HTTP_PROXY names.
            .proxy(None)
            .tls_config(tls)
            .build();
        match &self.dial {
            Dial::Tcp => ureq::Agent::new_with_config(config),
            local => {
                use ureq::unversioned::transport::{Connector, RustlsConnector};
                let connector =
                    local::LocalConnector::new(local.clone()).chain(RustlsConnector::default());
                ureq::Agent::with_parts(config, connector, local::NoResolve)
            }
        }
    }
}

/// The ureq connector and resolver for a [`Dial`] that is not TCP.
mod local {
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::os::unix::net::UnixStream;
    use std::time::Duration as StdDuration;

    use ureq::Error;
    use ureq::config::Config;
    use ureq::http::Uri;
    use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
    use ureq::unversioned::transport::{
        Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
    };

    use super::Dial;

    /// Never resolves the URL's host: the socket is fixed, and the host only travels in the
    /// request's `Host` header (and TLS server name). Answers one placeholder address because
    /// ureq requires one.
    #[derive(Debug)]
    pub(super) struct NoResolve;

    impl Resolver for NoResolve {
        fn resolve(
            &self,
            _uri: &Uri,
            _config: &Config,
            _timeout: NextTimeout,
        ) -> Result<ResolvedSocketAddrs, Error> {
            let mut addrs = self.empty();
            addrs.push(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
            Ok(addrs)
        }
    }

    /// Opens the [`Dial`]'s socket for every connection, whatever the URL names.
    #[derive(Debug)]
    pub(super) struct LocalConnector {
        dial: Dial,
    }

    impl LocalConnector {
        pub(super) fn new(dial: Dial) -> Self {
            Self { dial }
        }
    }

    impl<In: Transport> Connector<In> for LocalConnector {
        type Out = LocalTransport;

        fn connect(
            &self,
            details: &ConnectionDetails,
            _chained: Option<In>,
        ) -> Result<Option<Self::Out>, Error> {
            let stream = match &self.dial {
                Dial::Unix(path) => Stream::Unix(UnixStream::connect(path)?),
                Dial::Vsock { cid, port } => Stream::Vsock(connect_vsock(*cid, *port)?),
                Dial::Tcp => return Ok(None),
            };
            let buffers = LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            );
            Ok(Some(LocalTransport {
                stream,
                buffers,
                read_timeout: None,
                write_timeout: None,
            }))
        }
    }

    #[cfg(target_os = "linux")]
    fn connect_vsock(cid: u32, port: u32) -> io::Result<socket2::Socket> {
        let socket = socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)?;
        socket.connect(&socket2::SockAddr::vsock(cid, port))?;
        Ok(socket)
    }

    #[cfg(not(target_os = "linux"))]
    fn connect_vsock(_cid: u32, _port: u32) -> io::Result<UnixStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "AF_VSOCK is Linux only",
        ))
    }

    #[derive(Debug)]
    enum Stream {
        Unix(UnixStream),
        #[cfg(target_os = "linux")]
        Vsock(socket2::Socket),
        #[cfg(not(target_os = "linux"))]
        Vsock(UnixStream),
    }

    impl Stream {
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                Self::Unix(stream) => (&*stream).read(buf),
                Self::Vsock(socket) => (&*socket).read(buf),
            }
        }
        fn write_all(&self, buf: &[u8]) -> io::Result<()> {
            match self {
                Self::Unix(stream) => (&*stream).write_all(buf),
                Self::Vsock(socket) => (&*socket).write_all(buf),
            }
        }
        fn set_read_timeout(&self, timeout: Option<StdDuration>) -> io::Result<()> {
            match self {
                Self::Unix(stream) => stream.set_read_timeout(timeout),
                Self::Vsock(socket) => socket.set_read_timeout(timeout),
            }
        }
        fn set_write_timeout(&self, timeout: Option<StdDuration>) -> io::Result<()> {
            match self {
                Self::Unix(stream) => stream.set_write_timeout(timeout),
                Self::Vsock(socket) => socket.set_write_timeout(timeout),
            }
        }
        fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            match self {
                Self::Unix(stream) => stream.set_nonblocking(nonblocking),
                Self::Vsock(socket) => socket.set_nonblocking(nonblocking),
            }
        }
    }

    /// One connection over the local socket.
    #[derive(Debug)]
    pub(super) struct LocalTransport {
        stream: Stream,
        buffers: LazyBuffers,
        read_timeout: Option<StdDuration>,
        write_timeout: Option<StdDuration>,
    }

    /// Map an I/O error, a timed-out read or write becoming ureq's timeout for `timeout`.
    fn io_error(error: io::Error, timeout: NextTimeout) -> Error {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Error::Timeout(timeout.reason),
            _ => Error::Io(error),
        }
    }

    impl Transport for LocalTransport {
        fn buffers(&mut self) -> &mut dyn Buffers {
            &mut self.buffers
        }

        fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), Error> {
            let wanted = timeout.not_zero().map(|t| *t);
            if wanted != self.write_timeout {
                self.stream.set_write_timeout(wanted)?;
                self.write_timeout = wanted;
            }
            let output = &self.buffers.output()[..amount];
            self.stream
                .write_all(output)
                .map_err(|error| io_error(error, timeout))
        }

        fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, Error> {
            let wanted = timeout.not_zero().map(|t| *t);
            if wanted != self.read_timeout {
                self.stream.set_read_timeout(wanted)?;
                self.read_timeout = wanted;
            }
            let input = self.buffers.input_append_buf();
            let read = self
                .stream
                .read(input)
                .map_err(|error| io_error(error, timeout))?;
            self.buffers.input_appended(read);
            Ok(read > 0)
        }

        fn is_open(&mut self) -> bool {
            // Pooled connections are reused only while nothing unasked-for is waiting and the
            // peer has not closed: a read that would block.
            if self.stream.set_nonblocking(true).is_err() {
                return false;
            }
            let mut probe = [0u8; 1];
            let open = matches!(
                self.stream.read(&mut probe),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
            );
            open && self.stream.set_nonblocking(false).is_ok()
        }
    }
}

fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Every certificate of a PEM bundle, as owned DER. Other items (keys) are ignored.
fn certificates_in(pem: &str) -> Result<Vec<Certificate<'static>>, TransportError> {
    let mut found = Vec::new();
    for item in parse_pem(pem.as_bytes()) {
        let item = item.map_err(|error| TransportError::CaBundle(error.to_string()))?;
        if let PemItem::Certificate(certificate) = item {
            found.push(certificate);
        }
    }
    if found.is_empty() {
        return Err(TransportError::CaBundle("no certificate found".to_owned()));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_dialled_anywhere() {
        let transport = ChannelTransport::verified();
        assert_eq!(
            transport.check("the channel", "https://mend.example/api/channel"),
            Ok(())
        );
    }

    #[test]
    fn plain_http_is_dialled_to_loopback_only() {
        let transport = ChannelTransport::verified();
        for url in [
            "http://127.0.0.1:3106/channel",
            "http://127.8.9.1/channel",
            "http://[::1]:3106/channel",
            "http://localhost:3106/channel",
        ] {
            assert_eq!(transport.check("the channel", url), Ok(()), "{url}");
        }
        for (url, host) in [
            ("http://mend-api:3106/channel", "mend-api"),
            ("http://10.0.0.6:3106/channel", "10.0.0.6"),
            (
                "http://127.0.0.1.example.com/channel",
                "127.0.0.1.example.com",
            ),
            (
                "http://localhost.example.com/channel",
                "localhost.example.com",
            ),
        ] {
            assert_eq!(
                transport.check("the channel", url),
                Err(TransportError::Plaintext {
                    what: "the channel",
                    host: host.to_owned()
                }),
                "{url}"
            );
        }
    }

    #[test]
    fn the_explicit_exception_dials_plain_http() {
        let transport = ChannelTransport::verified().allow_plaintext(true);
        assert_eq!(
            transport.check("the channel", "http://mend-api:3106/channel"),
            Ok(())
        );
    }

    #[test]
    fn other_schemes_and_shapes_are_refused_even_with_the_exception() {
        let transport = ChannelTransport::verified().allow_plaintext(true);
        assert_eq!(
            transport.check("the channel", "ftp://mend.example/channel"),
            Err(TransportError::Scheme {
                what: "the channel",
                scheme: "ftp".to_owned()
            })
        );
        for url in ["", "mend.example/channel", "/channel", "https://"] {
            assert_eq!(
                transport.check("the channel", url),
                Err(TransportError::Malformed {
                    what: "the channel"
                }),
                "{url:?}"
            );
        }
    }

    #[test]
    fn spellings_that_only_look_like_loopback_are_refused() {
        let transport = ChannelTransport::verified();
        for url in [
            "http://127.0.0.1@evil.example/channel",
            "http://localhost@evil.example/channel",
            "http://0.0.0.0:3106/channel",
            "http://2130706433/channel",
            "http://localhost./channel",
            "http://[::ffff:127.0.0.1]/channel",
        ] {
            assert!(
                matches!(
                    transport.check("the channel", url),
                    Err(TransportError::Plaintext { .. } | TransportError::Malformed { .. })
                ),
                "{url}"
            );
        }
        // A scheme is case-insensitive: an uppercase one earns no exemption.
        assert!(matches!(
            transport.check("the channel", "HTTP://mend-api:3106/channel"),
            Err(TransportError::Plaintext { .. })
        ));
    }

    #[test]
    fn a_refusal_never_repeats_the_path_or_query() {
        let refusal = ChannelTransport::verified()
            .check(
                "an object URL",
                "http://bucket.internal/captures/w/pack?X-Amz-Signature=secret",
            )
            .expect_err("refused");
        let text = refusal.to_string();
        assert!(text.contains("bucket.internal"), "{text}");
        assert!(
            !text.contains("secret") && !text.contains("captures/w"),
            "{text}"
        );
    }

    #[test]
    fn a_dial_is_tcp_a_unix_path_or_a_vsock_address() {
        assert_eq!(Dial::parse(""), Ok(Dial::Tcp));
        assert_eq!(Dial::parse("tcp"), Ok(Dial::Tcp));
        assert_eq!(
            Dial::parse("unix:/run/sealant/capture.sock"),
            Ok(Dial::Unix("/run/sealant/capture.sock".into()))
        );
        assert_eq!(
            Dial::parse("vsock:2:1025"),
            Ok(Dial::Vsock { cid: 2, port: 1025 })
        );
        for spec in [
            "unix:relative.sock",
            "unix:",
            "vsock:2",
            "vsock:host:1025",
            "vsock:2:port",
            "http://garage:3900",
        ] {
            assert!(
                matches!(Dial::parse(spec), Err(TransportError::Dial(_))),
                "{spec}"
            );
        }
    }

    #[test]
    fn a_local_dial_dials_plain_http_without_the_exception_but_no_other_scheme() {
        let transport = ChannelTransport::verified().dial_via(Dial::Vsock { cid: 2, port: 1025 });
        assert_eq!(
            transport.check("an object URL", "http://garage:3900/captures/w/pack"),
            Ok(())
        );
        assert!(matches!(
            transport.check("an object URL", "ftp://garage:3900/pack"),
            Err(TransportError::Scheme { .. })
        ));
    }

    #[test]
    fn a_ca_bundle_without_a_certificate_is_refused() {
        assert!(matches!(
            ChannelTransport::verified().with_channel_ca_pem("not pem"),
            Err(TransportError::CaBundle(_))
        ));
    }
}
