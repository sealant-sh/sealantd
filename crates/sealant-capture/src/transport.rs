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
use std::net::IpAddr;
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
}

/// How this session's outbound HTTP is dialled. Built once at boot from the environment.
#[derive(Clone, Default)]
pub struct ChannelTransport {
    allow_plaintext: bool,
    channel_roots: Option<Arc<Vec<Certificate<'static>>>>,
    object_roots: Option<Arc<Vec<Certificate<'static>>>>,
}

impl std::fmt::Debug for ChannelTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelTransport")
            .field("allow_plaintext", &self.allow_plaintext)
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

    /// Whether plain HTTP beyond loopback is dialled.
    #[must_use]
    pub fn plaintext_allowed(&self) -> bool {
        self.allow_plaintext
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
            Some("http") if self.allow_plaintext || is_loopback(host) => Ok(()),
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
        ureq::Agent::new_with_config(config)
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
    fn a_ca_bundle_without_a_certificate_is_refused() {
        assert!(matches!(
            ChannelTransport::verified().with_channel_ca_pem("not pem"),
            Err(TransportError::CaBundle(_))
        ));
    }
}
