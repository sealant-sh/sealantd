//! TLS: the per-executor CA that signs inspected hosts' leaves, the upstream client that trusts
//! only public roots, and the `ClientHello` peek that reads SNI before anything is decided.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, PublicKeyData,
    SerialNumber,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::der;
use crate::policy::normalize_host;

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("certificate PEM: {0}")]
    CertPem(String),
    #[error("private key PEM: {0}")]
    KeyPem(String),
    #[error("{0}")]
    Der(String),
    #[error("subject: {0}")]
    Subject(String),
    #[error("the private key does not match the certificate")]
    KeyMismatch,
    #[error("signing: {0}")]
    Sign(#[from] rcgen::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("a minted leaf does not verify against the CA: {0}")]
    SelfCheck(String),
}

impl From<der::DerError> for CaError {
    fn from(e: der::DerError) -> Self {
        Self::Der(e.to_string())
    }
}

const LEAF_LIFETIME_DAYS: i64 = 7;
const LEAF_RENEW_BEFORE_DAYS: i64 = 1;

struct CachedLeaf {
    config: Arc<ServerConfig>,
    not_after: OffsetDateTime,
}

/// The per-executor CA, loaded from Sealant, and the leaves it has minted.
pub struct MitmAuthority {
    issuer: rcgen::Certificate,
    issuer_key: KeyPair,
    ca_der: CertificateDer<'static>,
    has_key_id: bool,
    leaf_key: KeyPair,
    leaves: Mutex<HashMap<String, CachedLeaf>>,
}

impl fmt::Debug for MitmAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmAuthority").finish_non_exhaustive()
    }
}

impl MitmAuthority {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, CaError> {
        let ca_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| CaError::CertPem(e.to_string()))?;
        let issuer_key = KeyPair::from_pem(key_pem).map_err(|e| CaError::KeyPem(e.to_string()))?;
        let info = der::parse_certificate(&ca_der)?;

        // The key must be the certificate's: compare the subjectPublicKey bits.
        let (spki, _) = der::read_tlv(&info.spki)?;
        let (_alg, after) = der::read_tlv(spki.value)?;
        let (bits, _) = der::read_tlv(after)?;
        if bits.value.split_first().map(|(_, key)| key) != Some(issuer_key.der_bytes()) {
            return Err(CaError::KeyMismatch);
        }

        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name(&info.subject)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_identifier_method = match &info.subject_key_id {
            Some(id) => KeyIdMethod::PreSpecified(id.clone()),
            None => KeyIdMethod::Sha256,
        };
        let issuer = params.self_signed(&issuer_key)?;

        let authority = Self {
            issuer,
            issuer_key,
            ca_der: ca_der.into_owned(),
            has_key_id: info.subject_key_id.is_some(),
            leaf_key: KeyPair::generate()?,
            leaves: Mutex::new(HashMap::new()),
        };
        authority.self_check()?;
        Ok(authority)
    }

    /// Mint a leaf and verify it against the CA as a client would, so a CA whose subject this
    /// module cannot reproduce fails when the policy loads, not on a workspace's first request.
    fn self_check(&self) -> Result<(), CaError> {
        let host = "sealant-selftest.invalid";
        let (leaf, _) = self.mint(host)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(self.ca_der.clone())
            .map_err(|e| CaError::SelfCheck(e.to_string()))?;
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .map_err(|e| CaError::SelfCheck(e.to_string()))?;
        let name = ServerName::try_from(host).map_err(|e| CaError::SelfCheck(e.to_string()))?;
        verifier
            .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
            .map_err(|e| CaError::SelfCheck(e.to_string()))?;
        Ok(())
    }

    fn mint(&self, host: &str) -> Result<(CertificateDer<'static>, OffsetDateTime), CaError> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = self.has_key_id;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        let not_after = now + Duration::days(LEAF_LIFETIME_DAYS);
        params.not_after = not_after;
        let mut serial = [0u8; 16];
        getrandom::getrandom(&mut serial).map_err(|e| CaError::SelfCheck(e.to_string()))?;
        serial[0] &= 0x7f;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let cert = params.signed_by(&self.leaf_key, &self.issuer, &self.issuer_key)?;
        Ok((cert.der().clone(), not_after))
    }

    /// The server config that presents a leaf for exactly `host`, minted on first use and cached.
    pub(crate) fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let now = OffsetDateTime::now_utc();
        if let Ok(leaves) = self.leaves.lock()
            && let Some(cached) = leaves.get(host)
            && cached.not_after - now > Duration::days(LEAF_RENEW_BEFORE_DAYS)
        {
            return Ok(cached.config.clone());
        }
        let (leaf, not_after) = self.mint(host)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf, self.ca_der.clone()], key)?;
        // HTTP/1.1 only: the proxy parses every request, and WebSocket upgrades ride on it.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if let Ok(mut leaves) = self.leaves.lock() {
            leaves.insert(
                host.to_string(),
                CachedLeaf {
                    config: config.clone(),
                    not_after,
                },
            );
        }
        Ok(config)
    }

    /// Whether `roots` would trust this CA. The proxy must never trust it upstream.
    pub(crate) fn trusted_by(&self, roots: &RootCertStore) -> bool {
        let Ok(info) = der::parse_certificate(&self.ca_der) else {
            return false;
        };
        let Ok((spki, _)) = der::read_tlv(&info.spki) else {
            return false;
        };
        roots
            .roots
            .iter()
            .any(|anchor| anchor.subject_public_key_info.as_ref() == spki.value)
    }
}

fn distinguished_name(attributes: &[der::NameAttribute]) -> Result<DistinguishedName, CaError> {
    let mut name = DistinguishedName::new();
    for attr in attributes {
        let kind = match attr.oid.as_slice() {
            [2, 5, 4, 3] => DnType::CommonName,
            [2, 5, 4, 6] => DnType::CountryName,
            [2, 5, 4, 7] => DnType::LocalityName,
            [2, 5, 4, 8] => DnType::StateOrProvinceName,
            [2, 5, 4, 10] => DnType::OrganizationName,
            [2, 5, 4, 11] => DnType::OrganizationalUnitName,
            other => DnType::CustomDnType(other.to_vec()),
        };
        let subject = |e: rcgen::Error| CaError::Subject(e.to_string());
        let utf8 =
            || String::from_utf8(attr.value.clone()).map_err(|e| CaError::Subject(e.to_string()));
        let value = match attr.tag {
            0x0c => DnValue::Utf8String(utf8()?),
            0x13 => DnValue::PrintableString(utf8()?.try_into().map_err(subject)?),
            0x16 => DnValue::Ia5String(utf8()?.try_into().map_err(subject)?),
            0x14 => {
                let text: String = attr.value.iter().map(|b| char::from(*b)).collect();
                DnValue::TeletexString(text.try_into().map_err(subject)?)
            }
            0x1e => {
                let units: Vec<u16> = attr
                    .value
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes(*c))
                    .collect();
                let text =
                    String::from_utf16(&units).map_err(|e| CaError::Subject(e.to_string()))?;
                DnValue::BmpString(text.try_into().map_err(subject)?)
            }
            0x1c => {
                let text: Option<String> = attr
                    .value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| char::from_u32(u32::from_be_bytes(*c)))
                    .collect();
                let text = text.ok_or_else(|| CaError::Subject("bad UniversalString".into()))?;
                DnValue::UniversalString(text.try_into().map_err(subject)?)
            }
            tag => return Err(CaError::Subject(format!("unsupported string tag {tag:#x}"))),
        };
        name.push(kind, value);
    }
    Ok(name)
}

/// The client config for brokered and inspected upstreams: public roots only, HTTP/1.1.
pub(crate) fn upstream_client_config(
    roots: Arc<RootCertStore>,
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The public roots the binary verifies upstreams against.
pub fn public_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// What the first bytes of a client stream turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hello {
    Tls { sni: Option<String> },
    NotTls,
}

const MAX_HELLO_BYTES: usize = 64 * 1024;
pub(crate) const HELLO_TIMEOUT: StdDuration = StdDuration::from_secs(10);

/// Read the client's first bytes into `buf` and, when they are a TLS handshake, the SNI of its
/// `ClientHello`. Everything read stays in `buf`, to be replayed upstream or into the TLS acceptor.
pub(crate) async fn peek_client_hello<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> io::Result<Hello> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
    while buf.is_empty() {
        read_more(reader, buf).await?;
    }
    if buf[0] != 0x16 {
        return Ok(Hello::NotTls);
    }
    let mut handshake = Vec::new();
    let mut pos = 0;
    loop {
        while buf.len() < pos + 5 {
            read_more(reader, buf).await?;
        }
        if buf[pos] != 0x16 {
            return Err(bad("ClientHello interrupted by a non-handshake record"));
        }
        let len = usize::from(u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]));
        if len == 0 || len > 16384 + 256 {
            return Err(bad("TLS record length out of range"));
        }
        while buf.len() < pos + 5 + len {
            read_more(reader, buf).await?;
        }
        handshake.extend_from_slice(&buf[pos + 5..pos + 5 + len]);
        pos += 5 + len;
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Err(bad("first handshake message is not a ClientHello"));
            }
            let body_len = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if body_len + 4 > MAX_HELLO_BYTES {
                return Err(bad("ClientHello too large"));
            }
            if handshake.len() >= body_len + 4 {
                let sni = client_hello_sni(&handshake[4..4 + body_len]).map_err(bad)?;
                return Ok(Hello::Tls { sni });
            }
        }
        if buf.len() > MAX_HELLO_BYTES {
            return Err(bad("ClientHello too large"));
        }
    }
}

async fn read_more<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0u8; 4096];
    let n = reader.read(&mut chunk).await?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "client closed before its ClientHello",
        ));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if self.0.len() < n {
            return Err("truncated ClientHello");
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<usize, &'static str> {
        Ok(usize::from(self.take(1)?[0]))
    }
    fn u16(&mut self) -> Result<usize, &'static str> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
}

/// The `server_name` of a ClientHello body (after the 4-byte handshake header).
pub(crate) fn client_hello_sni(body: &[u8]) -> Result<Option<String>, &'static str> {
    let mut c = Cursor(body);
    c.take(2 + 32)?; // legacy_version, random
    let session = c.u8()?;
    c.take(session)?;
    let suites = c.u16()?;
    c.take(suites)?;
    let compression = c.u8()?;
    c.take(compression)?;
    if c.0.is_empty() {
        return Ok(None);
    }
    let ext_len = c.u16()?;
    let mut exts = Cursor(c.take(ext_len)?);
    let mut found = None;
    while !exts.0.is_empty() {
        let kind = exts.u16()?;
        let len = exts.u16()?;
        let data = exts.take(len)?;
        if kind != 0 {
            continue;
        }
        if found.is_some() {
            return Err("duplicate server_name extension");
        }
        let mut list = Cursor(data);
        let list_len = list.u16()?;
        let mut names = Cursor(list.take(list_len)?);
        while !names.0.is_empty() {
            let name_type = names.u8()?;
            let name_len = names.u16()?;
            let name = names.take(name_len)?;
            if name_type == 0 {
                let text = std::str::from_utf8(name).map_err(|_| "server_name is not ASCII")?;
                let host = normalize_host(text).ok_or("server_name is not a hostname")?;
                found = Some(host);
                break;
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello_bytes(host: &str) -> Vec<u8> {
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(host.to_string()).unwrap(),
        )
        .unwrap();
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out).unwrap();
        }
        out
    }

    #[tokio::test]
    async fn reads_sni_from_a_real_client_hello_and_keeps_every_byte() {
        let bytes = client_hello_bytes("API.Example.com");
        let mut reader = &bytes[..];
        let mut buf = Vec::new();
        let hello = peek_client_hello(&mut reader, &mut buf).await.unwrap();
        assert_eq!(
            hello,
            Hello::Tls {
                sni: Some("api.example.com".into())
            }
        );
        assert_eq!(buf, bytes);
    }

    #[tokio::test]
    async fn plaintext_is_not_tls() {
        let mut reader = &b"GET / HTTP/1.1\r\n\r\n"[..];
        let mut buf = Vec::new();
        assert_eq!(
            peek_client_hello(&mut reader, &mut buf).await.unwrap(),
            Hello::NotTls
        );
        assert_eq!(buf[0], b'G');
    }

    #[tokio::test]
    async fn truncated_and_garbage_hellos_error_without_panicking() {
        let bytes = client_hello_bytes("example.com");
        for cut in [3, 9, 40, bytes.len() - 1] {
            let mut reader = &bytes[..cut];
            let mut buf = Vec::new();
            assert!(
                peek_client_hello(&mut reader, &mut buf).await.is_err(),
                "cut {cut}"
            );
        }
        let mut garbage = vec![0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04];
        garbage.extend_from_slice(&[0xff; 4]);
        let mut reader = &garbage[..];
        let mut buf = Vec::new();
        assert!(peek_client_hello(&mut reader, &mut buf).await.is_err());
    }

    fn test_ca(with_key_id: bool) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Sealant executor CA");
        name.push(
            DnType::OrganizationName,
            DnValue::PrintableString("Sealant".try_into().unwrap()),
        );
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        if !with_key_id {
            params.key_identifier_method = KeyIdMethod::PreSpecified(Vec::new());
        }
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn mints_leaves_that_verify_against_the_loaded_ca() {
        for with_key_id in [true, false] {
            let (cert, key) = test_ca(with_key_id);
            let ca = MitmAuthority::from_pem(&cert, &key).unwrap();
            // from_pem already verified one; a cached config is reused.
            let a = ca.server_config("api.example.com").unwrap();
            let b = ca.server_config("api.example.com").unwrap();
            assert!(Arc::ptr_eq(&a, &b));
            assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
        }
    }

    #[test]
    fn refuses_a_key_that_is_not_the_certificates() {
        let (cert, _) = test_ca(true);
        let (_, other_key) = test_ca(true);
        assert!(matches!(
            MitmAuthority::from_pem(&cert, &other_key),
            Err(CaError::KeyMismatch)
        ));
    }

    #[test]
    fn detects_the_ca_among_roots() {
        let (cert, key) = test_ca(true);
        let ca = MitmAuthority::from_pem(&cert, &key).unwrap();
        assert!(!ca.trusted_by(&public_roots()));
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(cert.as_bytes()).unwrap())
            .unwrap();
        assert!(ca.trusted_by(&roots));
    }
}
