//! One client connection's HTTP/1.1 requests, relayed to one upstream.
//!
//! Used two ways:
//! - **Inspected HTTPS** (brokered and `inspectTls` hosts): the client's TLS is terminated with a
//!   leaf for exactly the host, and every request is checked (`SNI == Host == bindHost`, methods,
//!   path prefixes) before the placeholder in the one configured header is swapped for the secret.
//!   The upstream is dialed at a proxy-resolved, validated address and verified against public
//!   roots. WebSocket upgrades turn into a byte splice that stays registered for revocation.
//! - **Plain HTTP**: one request per connection, never any substitution.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::ServerName;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_rustls::TlsConnector;

use crate::events::Event;
use crate::http1::{
    Framing, HttpError, HttpReader, RequestHead, parse_request, parse_response, simple_response,
};
use crate::io::{BoxStream, Stream, connect_any, splice_halves};
use crate::policy::{BrokeredSecret, scope_permits};
use crate::state::{Ingress, Shared};

const FIRST_HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) struct SessionSpec {
    pub(crate) ingress: Ingress,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) addrs: Vec<SocketAddr>,
    /// Inspected HTTPS: check every request, substitute, and use TLS upstream.
    pub(crate) inspect: bool,
    /// The secrets bound to the host when the connection was admitted.
    pub(crate) secret_ids: Vec<String>,
    /// Plain HTTP: relay one request, then close.
    pub(crate) single_request: bool,
}

enum Outcome {
    Done { keep_alive: bool },
    Upgraded,
}

type Upstream = (HttpReader<ReadHalf<BoxStream>>, WriteHalf<BoxStream>);

pub(crate) async fn run<C: Stream + 'static>(
    shared: Arc<Shared>,
    spec: SessionSpec,
    client: C,
    initial: Vec<u8>,
    first: Option<RequestHead>,
) {
    let (cr, mut cw) = tokio::io::split(client);
    let mut creader = HttpReader::new(cr, initial);
    let mut upstream: Option<Upstream> = None;
    let mut first = first;
    let mut served = 0usize;
    loop {
        let mut req = match first.take() {
            Some(req) => req,
            None => {
                let wait = if served == 0 {
                    FIRST_HEAD_TIMEOUT
                } else {
                    IDLE_TIMEOUT
                };
                let head = match next_head(&mut creader, &mut upstream, wait).await {
                    Ok(Ok(Some(head))) => head,
                    Ok(Ok(None)) | Err(_) => break,
                    Ok(Err(e)) => {
                        reject(&mut cw, 400, &e.to_string()).await;
                        break;
                    }
                };
                match parse_request(&head) {
                    Ok(req) => req,
                    Err(e) => {
                        reject(&mut cw, 400, &e.to_string()).await;
                        break;
                    }
                }
            }
        };
        served += 1;
        let path = request_path(&req.target);

        let mut used_secrets = Vec::new();
        if spec.inspect {
            match check_inspected(&shared, &spec, &mut req, &path) {
                Ok(used) => used_secrets = used,
                Err((status, reason)) => {
                    violation(&shared, &spec, &req, &path, &reason);
                    reject(&mut cw, status, &reason).await;
                    break;
                }
            }
        }
        let framing = match req.framing() {
            Ok(framing) => framing,
            Err(e) => {
                reject(&mut cw, 400, &e.to_string()).await;
                break;
            }
        };
        let upgrade = req.wants_upgrade();
        if spec.inspect && upgrade && !req.is_websocket_upgrade() {
            reject(&mut cw, 400, "only WebSocket upgrades are relayed").await;
            break;
        }
        if spec.single_request && !upgrade {
            req.set("Connection", b"close");
        }
        let head = req.encode();

        // A reused upstream can close between our idle check and our write. A request with no
        // body is safe to send again, once, on a fresh connection.
        let mut retried = false;
        let relay = loop {
            let reused = upstream.is_some();
            if upstream.is_none() {
                match dial(&shared, &spec).await {
                    Ok(stream) => {
                        let (ur, uw) = tokio::io::split(stream);
                        upstream = Some((HttpReader::new(ur, Vec::new()), uw));
                    }
                    Err(reason) => {
                        shared.events.emit(Event {
                            ingress: Some(spec.ingress.as_str()),
                            host: Some(spec.host.clone()),
                            port: Some(spec.port),
                            reason: Some(reason.clone()),
                            ..Event::new("upstream_error")
                        });
                        reject(&mut cw, 502, "upstream unavailable").await;
                        break None;
                    }
                }
            }
            let Some((ureader, uw)) = upstream.as_mut() else {
                break None;
            };
            let result = match uw.write_all(&head).await {
                Ok(()) => tokio::try_join!(
                    async {
                        creader.copy_body(framing, uw).await?;
                        uw.flush().await?;
                        Ok::<_, HttpError>(())
                    },
                    relay_response(ureader, &mut cw, &req.method, upgrade, spec.single_request),
                ),
                Err(_) => Err(HttpError::UpstreamClosedEarly),
            };
            match result {
                Err(HttpError::UpstreamClosedEarly)
                    if reused
                        && !retried
                        && matches!(framing, Framing::None | Framing::Length(0)) =>
                {
                    retried = true;
                    upstream = None;
                }
                other => break Some(other),
            }
        };
        let (outcome, status) = match relay {
            Some(Ok(((), result))) => result,
            Some(Err(e)) => {
                tracing::debug!(host = %spec.host, error = %e, "relay ended");
                break;
            }
            None => break,
        };
        shared.events.emit(Event {
            ingress: Some(spec.ingress.as_str()),
            host: Some(spec.host.clone()),
            port: Some(spec.port),
            method: Some(req.method.clone()),
            path: Some(path.clone()),
            status: Some(status),
            secret_ids: used_secrets,
            ..Event::new("request")
        });
        match outcome {
            Outcome::Upgraded => {
                let Some((ureader, uw)) = upstream.take() else {
                    break;
                };
                let (cr, cbuf) = creader.into_parts();
                let (ur, ubuf) = ureader.into_parts();
                let mut uw = uw;
                if (!cbuf.is_empty() && uw.write_all(&cbuf).await.is_err())
                    || (!ubuf.is_empty() && cw.write_all(&ubuf).await.is_err())
                {
                    return;
                }
                let _ = splice_halves(cr, cw, ur, uw).await;
                return;
            }
            Outcome::Done { keep_alive } => {
                // A response delimited by close, or one that says it closes, ends the client
                // connection too: the client was told so and reads it that way.
                if spec.single_request || !keep_alive || !req.keep_alive() {
                    break;
                }
            }
        }
    }
    let _ = cw.shutdown().await;
}

/// Wait for the client's next head. While idle, an upstream that closes, errors or sends bytes
/// nobody asked for is dropped, so the next request dials a fresh connection.
async fn next_head<R: tokio::io::AsyncRead + Unpin>(
    creader: &mut HttpReader<R>,
    upstream: &mut Option<Upstream>,
    wait: Duration,
) -> Result<Result<Option<Vec<u8>>, HttpError>, tokio::time::error::Elapsed> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let Some((ureader, _)) = upstream.as_mut() else {
            return tokio::time::timeout_at(deadline, creader.read_head()).await;
        };
        tokio::select! {
            head = tokio::time::timeout_at(deadline, creader.read_head()) => return head,
            _ = ureader.fill_once() => {}
        }
        *upstream = None;
    }
}

/// The per-request checks on an inspected host. Returns the secret IDs substituted.
fn check_inspected(
    shared: &Shared,
    spec: &SessionSpec,
    req: &mut RequestHead,
    path: &str,
) -> Result<Vec<String>, (u16, String)> {
    if !target_is_acceptable(&req.target, &req.method) {
        return Err((400, "target_not_origin_form".into()));
    }
    let host = match req.single_host() {
        Ok((host, _)) => host,
        Err(_) => return Err((400, "bad_host_header".into())),
    };
    if host != spec.host {
        return Err((403, "sni_host_mismatch".into()));
    }
    let Some(snapshot) = shared.snapshot() else {
        return Err((503, "not_initialized".into()));
    };
    let policy = &snapshot.policy;
    let secrets: Vec<&BrokeredSecret> = policy
        .secrets_for(&spec.host)
        .filter(|s| spec.secret_ids.contains(&s.secret_id))
        .collect();
    if !secrets.is_empty() && !snapshot.lease_ok {
        return Err((503, "lease_expired".into()));
    }
    let rule = policy.inspect_rule(&spec.host, spec.port);
    let wants_paths = rule.is_some_and(|r| r.path_prefixes.is_some())
        || secrets.iter().any(|s| s.path_prefixes.is_some());
    if wants_paths && !path_is_canonical(path) {
        return Err((403, "non_canonical_path".into()));
    }
    if let Some(rule) = rule
        && !scope_permits(
            rule.methods.as_deref(),
            rule.path_prefixes.as_deref(),
            &req.method,
            path,
        )
    {
        return Err((403, "method_or_path_not_allowed".into()));
    }
    substitute(req, &secrets, path).map_err(|id| (403, format!("secret_scope:{id}")))
}

/// Origin form only, and no `#`: a fragment never belongs on the wire, and an origin that
/// reads one oddly could step past a path-prefix check (`/v1/x#/../../admin`).
fn target_is_acceptable(target: &str, method: &str) -> bool {
    (target.starts_with('/') || (target == "*" && method == "OPTIONS")) && !target.contains('#')
}

/// Swap each secret's placeholder for its value, inside that secret's one header only.
/// Returns the IDs used, or the ID of a secret whose method/path scope the request is outside.
pub(crate) fn substitute(
    req: &mut RequestHead,
    secrets: &[&BrokeredSecret],
    path: &str,
) -> Result<Vec<String>, String> {
    let mut used = Vec::new();
    for secret in secrets {
        let placeholder = secret.placeholder.as_bytes();
        let carries = req.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case(&secret.header_name) && contains(&h.value, placeholder)
        });
        if !carries {
            continue;
        }
        if !secret.permits(&req.method, path) {
            return Err(secret.secret_id.clone());
        }
        let value = secret.value.expose().as_bytes();
        for header in req
            .headers
            .iter_mut()
            .filter(|h| h.name.eq_ignore_ascii_case(&secret.header_name))
        {
            header.value = replace(&header.value, placeholder, value);
        }
        used.push(secret.secret_id.clone());
    }
    Ok(used)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn replace(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len() + with.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

fn absolute_authority(target: &str) -> Option<&str> {
    let rest = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))?;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(rest))
}

/// The path of a request target, without query or fragment.
pub(crate) fn request_path(target: &str) -> String {
    let path_and_query = match absolute_authority(target) {
        Some(authority) => {
            let start = target.find(authority).map_or(0, |i| i + authority.len());
            &target[start..]
        }
        None => target,
    };
    let path = path_and_query.split(['?', '#']).next().unwrap_or("");
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

/// No dot segments, empty segments, `;` parameters, backslashes or encoded dots and slashes, so a path prefix
/// check cannot be stepped around.
fn path_is_canonical(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.starts_with('/')
        && !path.contains('\\')
        && !path.contains("//")
        && !path.contains(';')
        && !["%2e", "%2f", "%5c"].iter().any(|e| lower.contains(e))
        && !path.split('/').any(|seg| seg == "." || seg == "..")
}

async fn relay_response<R, W>(
    ureader: &mut HttpReader<R>,
    cw: &mut W,
    method: &str,
    upgrade_requested: bool,
    single_request: bool,
) -> Result<(Outcome, u16), HttpError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(head) = ureader.read_head().await? else {
            return Err(HttpError::UpstreamClosedEarly);
        };
        let resp = parse_response(&head)?;
        if resp.status == 101 {
            if !upgrade_requested {
                return Err(HttpError::Malformed("unsolicited 101"));
            }
            cw.write_all(&resp.raw).await?;
            cw.flush().await?;
            return Ok((Outcome::Upgraded, 101));
        }
        if (100..200).contains(&resp.status) {
            cw.write_all(&resp.raw).await?;
            cw.flush().await?;
            continue;
        }
        let framing = resp.framing(method)?;
        let head = if single_request {
            resp.encode_closing()
        } else {
            resp.raw.clone()
        };
        cw.write_all(&head).await?;
        ureader.copy_body(framing, cw).await?;
        cw.flush().await?;
        let keep_alive = resp.keep_alive() && framing != Framing::UntilClose;
        return Ok((Outcome::Done { keep_alive }, resp.status));
    }
}

async fn dial(shared: &Shared, spec: &SessionSpec) -> Result<BoxStream, String> {
    let tcp = connect_any(&spec.addrs, shared.connect_timeout)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    if !spec.inspect {
        return Ok(Box::new(tcp));
    }
    let name = ServerName::try_from(spec.host.clone()).map_err(|e| format!("server name: {e}"))?;
    let connector = TlsConnector::from(shared.upstream_tls.clone());
    let tls = tokio::time::timeout(shared.connect_timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| "upstream TLS handshake timed out".to_string())?
        .map_err(|e| format!("upstream TLS: {e}"))?;
    Ok(Box::new(tls))
}

fn violation(shared: &Shared, spec: &SessionSpec, req: &RequestHead, path: &str, reason: &str) {
    shared.events.emit(Event {
        ingress: Some(spec.ingress.as_str()),
        host: Some(spec.host.clone()),
        port: Some(spec.port),
        method: Some(req.method.clone()),
        path: Some(path.to_string()),
        reason: Some(reason.to_string()),
        ..Event::new("violation")
    });
}

async fn reject<W: AsyncWrite + Unpin>(cw: &mut W, status: u16, reason: &str) {
    let _ = cw.write_all(&simple_response(status, reason)).await;
    let _ = cw.flush().await;
}

/// The head of a plain HTTP request after its absolute-form target is made origin-form.
pub(crate) fn to_origin_form(req: &mut RequestHead, path_and_query: String) {
    req.target = path_and_query;
    req.remove("proxy-connection");
    req.remove("proxy-authorization");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretValue;

    fn secret(
        header: &str,
        methods: Option<Vec<&str>>,
        prefixes: Option<Vec<&str>>,
    ) -> BrokeredSecret {
        BrokeredSecret {
            secret_id: "s1".into(),
            placeholder: "mend_sec_PLACEHOLDER".into(),
            value: serde_json::from_str::<SecretValue>("\"real-token\"").unwrap(),
            header_name: header.into(),
            bind_hosts: vec!["api.example.com".into()],
            methods: methods.map(|m| m.into_iter().map(String::from).collect()),
            path_prefixes: prefixes.map(|p| p.into_iter().map(String::from).collect()),
        }
    }

    fn request(text: &str) -> RequestHead {
        parse_request(text.as_bytes()).unwrap()
    }

    #[test]
    fn substitutes_only_inside_the_configured_header() {
        let s = secret("authorization", None, None);
        let mut req = request(
            "GET /v1?token=mend_sec_PLACEHOLDER HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer mend_sec_PLACEHOLDER\r\nX-Other: mend_sec_PLACEHOLDER\r\n\r\n",
        );
        let used = substitute(&mut req, &[&s], "/v1").unwrap();
        assert_eq!(used, vec!["s1".to_string()]);
        assert_eq!(req.header("authorization").unwrap(), b"Bearer real-token");
        assert_eq!(req.header("x-other").unwrap(), b"mend_sec_PLACEHOLDER");
        assert_eq!(req.target, "/v1?token=mend_sec_PLACEHOLDER");
    }

    #[test]
    fn leaves_requests_without_the_placeholder_alone() {
        let s = secret("authorization", None, None);
        let mut req = request("GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer mine\r\n\r\n");
        assert!(substitute(&mut req, &[&s], "/").unwrap().is_empty());
        assert_eq!(req.header("authorization").unwrap(), b"Bearer mine");
    }

    #[test]
    fn refuses_placeholders_outside_the_secrets_scope() {
        let s = secret("x-api-key", Some(vec!["GET"]), Some(vec!["/v1/"]));
        let mut req =
            request("POST /v1/x HTTP/1.1\r\nHost: a\r\nX-API-Key: mend_sec_PLACEHOLDER\r\n\r\n");
        assert_eq!(substitute(&mut req, &[&s], "/v1/x"), Err("s1".into()));
        let mut req =
            request("GET /v2/x HTTP/1.1\r\nHost: a\r\nX-API-Key: mend_sec_PLACEHOLDER\r\n\r\n");
        assert_eq!(substitute(&mut req, &[&s], "/v2/x"), Err("s1".into()));
        let mut req =
            request("GET /v1/x HTTP/1.1\r\nHost: a\r\nX-API-Key: mend_sec_PLACEHOLDER\r\n\r\n");
        assert_eq!(
            substitute(&mut req, &[&s], "/v1/x").unwrap(),
            vec!["s1".to_string()]
        );
    }

    #[test]
    fn inspected_targets_are_origin_form_without_fragments() {
        assert!(target_is_acceptable("/v1/x?y=1", "GET"));
        assert!(target_is_acceptable("*", "OPTIONS"));
        assert!(!target_is_acceptable("/v1/x#/../../admin", "GET"));
        assert!(!target_is_acceptable("https://api.test/v1", "GET"));
        assert!(!target_is_acceptable("*", "GET"));
    }

    #[test]
    fn paths_drop_queries_and_dot_segments_are_not_canonical() {
        assert_eq!(request_path("/a/b?x=1"), "/a/b");
        assert_eq!(request_path("https://h.example/a?q"), "/a");
        assert_eq!(request_path("http://h.example"), "/");
        assert!(path_is_canonical("/v1/repos"));
        for bad in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1//x",
            "/v1\\x",
            "/v1/%2F",
            "/v1/..;/admin",
            "/v1;x=1/y",
        ] {
            assert!(!path_is_canonical(bad), "{bad}");
        }
    }
}
