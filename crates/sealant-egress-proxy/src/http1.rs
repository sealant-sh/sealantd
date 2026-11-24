//! HTTP/1.1 heads and message framing, enough to relay requests one at a time.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_LINE: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("malformed HTTP: {0}")]
    Malformed(&'static str),
    #[error("HTTP head larger than {MAX_HEAD} bytes")]
    HeadTooLarge,
    /// A reused upstream closed before sending a byte of the response.
    #[error("upstream closed before responding")]
    UpstreamClosedEarly,
}

/// A reader that keeps what it read past the current message for the next one.
pub(crate) struct HttpReader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> HttpReader<R> {
    pub(crate) fn new(inner: R, initial: Vec<u8>) -> Self {
        Self {
            inner,
            buf: initial,
        }
    }

    /// Read once more into the buffer. Used to notice an idle peer closing or misbehaving.
    pub(crate) async fn fill_once(&mut self) -> io::Result<usize> {
        self.fill().await
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.inner.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// Read one head, through its blank line. `None` when the peer closed before sending a byte.
    pub(crate) async fn read_head(&mut self) -> Result<Option<Vec<u8>>, HttpError> {
        let mut searched = 0;
        loop {
            if let Some(end) = find_head_end(&self.buf, searched) {
                let rest = self.buf.split_off(end);
                let head = std::mem::replace(&mut self.buf, rest);
                return Ok(Some(head));
            }
            searched = self.buf.len().saturating_sub(3);
            if self.buf.len() > MAX_HEAD {
                return Err(HttpError::HeadTooLarge);
            }
            if self.fill().await? == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(HttpError::Malformed("connection closed inside a head"));
            }
        }
    }

    pub(crate) async fn copy_exact<W: AsyncWrite + Unpin>(
        &mut self,
        mut remaining: u64,
        out: &mut W,
    ) -> Result<(), HttpError> {
        while remaining > 0 {
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(HttpError::Malformed("connection closed inside a body"));
            }
            let take = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(self.buf.len());
            out.write_all(&self.buf[..take]).await?;
            self.buf.drain(..take);
            remaining -= take as u64;
        }
        Ok(())
    }

    async fn read_line(&mut self) -> Result<Vec<u8>, HttpError> {
        let mut searched = 0;
        loop {
            if let Some(pos) = self.buf[searched..].windows(2).position(|w| w == b"\r\n") {
                let end = searched + pos + 2;
                let rest = self.buf.split_off(end);
                return Ok(std::mem::replace(&mut self.buf, rest));
            }
            searched = self.buf.len().saturating_sub(1);
            if self.buf.len() > MAX_LINE {
                return Err(HttpError::Malformed("chunk line too long"));
            }
            if self.fill().await? == 0 {
                return Err(HttpError::Malformed(
                    "connection closed inside chunked body",
                ));
            }
        }
    }

    /// Relay a chunked body verbatim, through its trailers.
    pub(crate) async fn copy_chunked<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
    ) -> Result<(), HttpError> {
        loop {
            let line = self.read_line().await?;
            let size = parse_chunk_size(&line)?;
            out.write_all(&line).await?;
            if size == 0 {
                loop {
                    let trailer = self.read_line().await?;
                    out.write_all(&trailer).await?;
                    if trailer == b"\r\n" {
                        return Ok(());
                    }
                }
            }
            self.copy_exact(size, out).await?;
            let crlf = self.read_line().await?;
            if crlf != b"\r\n" {
                return Err(HttpError::Malformed("chunk data not followed by CRLF"));
            }
            out.write_all(&crlf).await?;
        }
    }

    pub(crate) async fn copy_to_eof<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
    ) -> Result<(), HttpError> {
        if !self.buf.is_empty() {
            out.write_all(&self.buf).await?;
            self.buf.clear();
        }
        tokio::io::copy(&mut self.inner, out).await?;
        Ok(())
    }

    pub(crate) async fn copy_body<W: AsyncWrite + Unpin>(
        &mut self,
        framing: Framing,
        out: &mut W,
    ) -> Result<(), HttpError> {
        match framing {
            Framing::None => Ok(()),
            Framing::Length(n) => self.copy_exact(n, out).await,
            Framing::Chunked => self.copy_chunked(out).await,
            Framing::UntilClose => self.copy_to_eof(out).await,
        }
    }

    pub(crate) fn into_parts(self) -> (R, Vec<u8>) {
        (self.inner, self.buf)
    }
}

fn find_head_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| from + pos + 4)
}

fn parse_chunk_size(line: &[u8]) -> Result<u64, HttpError> {
    let text = std::str::from_utf8(line).map_err(|_| HttpError::Malformed("chunk size"))?;
    let digits = text
        .trim_end_matches("\r\n")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if digits.is_empty() || digits.len() > 15 {
        return Err(HttpError::Malformed("chunk size"));
    }
    u64::from_str_radix(digits, 16).map_err(|_| HttpError::Malformed("chunk size"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) name: String,
    pub(crate) value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) minor_version: u8,
    pub(crate) headers: Vec<Header>,
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseHead {
    pub(crate) status: u16,
    pub(crate) minor_version: u8,
    pub(crate) headers: Vec<Header>,
    pub(crate) raw: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

fn collect_headers(parsed: &[httparse::Header<'_>]) -> Result<Vec<Header>, HttpError> {
    parsed
        .iter()
        .map(|h| {
            if h.value
                .iter()
                .any(|b| *b == b'\r' || *b == b'\n' || *b == 0)
            {
                return Err(HttpError::Malformed("control byte in header value"));
            }
            Ok(Header {
                name: h.name.to_string(),
                value: h.value.to_vec(),
            })
        })
        .collect()
}

pub(crate) fn parse_request(head: &[u8]) -> Result<RequestHead, HttpError> {
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut storage);
    match req.parse(head) {
        // A head httparse ends before the blank line `read_head` found (bare LFs) would leave
        // bytes that one side reads as a second message and the other as this one's body.
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Ok(httparse::Status::Complete(_)) => {
            return Err(HttpError::Malformed("head ends before its CRLF blank line"));
        }
        Ok(httparse::Status::Partial) => {
            return Err(HttpError::Malformed("incomplete request head"));
        }
        Err(_) => return Err(HttpError::Malformed("request head")),
    }
    let (Some(method), Some(target), Some(version)) = (req.method, req.path, req.version) else {
        return Err(HttpError::Malformed("request line"));
    };
    Ok(RequestHead {
        method: method.to_string(),
        target: target.to_string(),
        minor_version: version,
        headers: collect_headers(req.headers)?,
    })
}

pub(crate) fn parse_response(head: &[u8]) -> Result<ResponseHead, HttpError> {
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut res = httparse::Response::new(&mut storage);
    match res.parse(head) {
        // A head httparse ends before the blank line `read_head` found (bare LFs) would leave
        // bytes that one side reads as a second message and the other as this one's body.
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Ok(httparse::Status::Complete(_)) => {
            return Err(HttpError::Malformed("head ends before its CRLF blank line"));
        }
        Ok(httparse::Status::Partial) => {
            return Err(HttpError::Malformed("incomplete response head"));
        }
        Err(_) => return Err(HttpError::Malformed("response head")),
    }
    let (Some(status), Some(version)) = (res.code, res.version) else {
        return Err(HttpError::Malformed("status line"));
    };
    Ok(ResponseHead {
        status,
        minor_version: version,
        headers: collect_headers(res.headers)?,
        raw: head.to_vec(),
    })
}

pub(crate) fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_slice())
}

/// Whether a comma-separated header (any occurrence) lists `token`, case-insensitively.
pub(crate) fn has_token(headers: &[Header], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .flat_map(|h| h.value.split(|b| *b == b','))
        .any(|t| t.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
}

fn content_length(headers: &[Header]) -> Result<Option<u64>, HttpError> {
    let mut found: Option<u64> = None;
    for h in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        for part in h.value.split(|b| *b == b',') {
            let text = std::str::from_utf8(part.trim_ascii())
                .map_err(|_| HttpError::Malformed("content-length"))?;
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpError::Malformed("content-length"));
            }
            let n: u64 = text
                .parse()
                .map_err(|_| HttpError::Malformed("content-length"))?;
            if found.is_some_and(|f| f != n) {
                return Err(HttpError::Malformed("conflicting content-length"));
            }
            found = Some(n);
        }
    }
    Ok(found)
}

fn chunked_last(headers: &[Header]) -> Option<bool> {
    let codings: Vec<&[u8]> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|h| h.value.split(|b| *b == b','))
        .map(<[u8]>::trim_ascii)
        .filter(|t| !t.is_empty())
        .collect();
    let last = codings.last()?;
    Some(last.eq_ignore_ascii_case(b"chunked"))
}

impl RequestHead {
    /// The one `Host` header, normalized, with its port. Missing, repeated or malformed is an
    /// error: a second Host is the classic way to make two parsers disagree on the target.
    pub(crate) fn single_host(&self) -> Result<(String, Option<u16>), HttpError> {
        let mut hosts = self
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("host"));
        let (Some(only), None) = (hosts.next(), hosts.next()) else {
            return Err(HttpError::Malformed("exactly one Host header is required"));
        };
        std::str::from_utf8(&only.value)
            .ok()
            .filter(|v| !v.is_empty() && !v.contains(['@', '/', '\\', ' ', ',']))
            .and_then(crate::policy::split_host_port)
            .ok_or(HttpError::Malformed("malformed Host header"))
    }

    /// Whether the target is origin-form (`/path`), or `*` for OPTIONS. Anything else names an
    /// authority of its own that an origin would prefer over Host (RFC 9112 §3.2.2).
    pub(crate) fn is_origin_form(&self) -> bool {
        self.target.starts_with('/') || (self.target == "*" && self.method == "OPTIONS")
    }

    pub(crate) fn header(&self, name: &str) -> Option<&[u8]> {
        header(&self.headers, name)
    }

    /// How the request body is delimited. Refuses the ambiguous forms request smuggling uses.
    pub(crate) fn framing(&self) -> Result<Framing, HttpError> {
        let length = content_length(&self.headers)?;
        match chunked_last(&self.headers) {
            Some(true) if length.is_some() => Err(HttpError::Malformed(
                "both transfer-encoding and content-length",
            )),
            Some(true) => Ok(Framing::Chunked),
            Some(false) => Err(HttpError::Malformed(
                "request transfer-encoding is not chunked",
            )),
            None => Ok(length.map_or(Framing::None, Framing::Length)),
        }
    }

    pub(crate) fn wants_upgrade(&self) -> bool {
        self.header("upgrade").is_some() && has_token(&self.headers, "connection", "upgrade")
    }

    pub(crate) fn is_websocket_upgrade(&self) -> bool {
        self.wants_upgrade() && has_token(&self.headers, "upgrade", "websocket")
    }

    pub(crate) fn keep_alive(&self) -> bool {
        if self.minor_version == 0 {
            has_token(&self.headers, "connection", "keep-alive")
        } else {
            !has_token(&self.headers, "connection", "close")
        }
    }

    pub(crate) fn remove(&mut self, name: &str) {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }

    pub(crate) fn set(&mut self, name: &str, value: &[u8]) {
        self.remove(name);
        self.headers.push(Header {
            name: name.to_string(),
            value: value.to_vec(),
        });
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_bytes());
        out.extend_from_slice(format!(" HTTP/1.{}\r\n", self.minor_version).as_bytes());
        encode_headers(&self.headers, &mut out);
        out
    }
}

impl ResponseHead {
    pub(crate) fn framing(&self, request_method: &str) -> Result<Framing, HttpError> {
        if request_method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&self.status)
            || self.status == 204
            || self.status == 304
        {
            return Ok(Framing::None);
        }
        match chunked_last(&self.headers) {
            Some(true) => Ok(Framing::Chunked),
            Some(false) => Ok(Framing::UntilClose),
            None => Ok(content_length(&self.headers)?.map_or(Framing::UntilClose, Framing::Length)),
        }
    }

    pub(crate) fn keep_alive(&self) -> bool {
        if self.minor_version == 0 {
            has_token(&self.headers, "connection", "keep-alive")
        } else {
            !has_token(&self.headers, "connection", "close")
        }
    }

    /// The head re-encoded with `Connection: close`.
    pub(crate) fn encode_closing(&self) -> Vec<u8> {
        let mut headers: Vec<Header> = self
            .headers
            .iter()
            .filter(|h| {
                !h.name.eq_ignore_ascii_case("connection")
                    && !h.name.eq_ignore_ascii_case("keep-alive")
            })
            .cloned()
            .collect();
        headers.push(Header {
            name: "Connection".into(),
            value: b"close".to_vec(),
        });
        let mut out = Vec::with_capacity(self.raw.len() + 20);
        let reason = status_reason(self.status);
        out.extend_from_slice(
            format!("HTTP/1.{} {} {reason}\r\n", self.minor_version, self.status).as_bytes(),
        );
        encode_headers(&headers, &mut out);
        out
    }
}

fn encode_headers(headers: &[Header], out: &mut Vec<u8>) {
    for h in headers {
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&h.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

fn status_reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// A complete short response the proxy itself sends, always closing the connection.
pub(crate) fn simple_response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        status_reason(status),
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_heads_and_keeps_the_rest() {
        let data = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nBODY".to_vec();
        let mut reader = HttpReader::new(&data[..], Vec::new());
        let head = reader.read_head().await.unwrap().unwrap();
        assert_eq!(head, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let (_, rest) = reader.into_parts();
        assert_eq!(rest, b"BODY");
    }

    #[tokio::test]
    async fn relays_chunked_bodies_verbatim() {
        let body = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: x\r\n\r\nNEXT".to_vec();
        let mut reader = HttpReader::new(&body[..], Vec::new());
        let mut out = Vec::new();
        reader.copy_chunked(&mut out).await.unwrap();
        assert_eq!(out, &body[..body.len() - 4]);
        let (_, rest) = reader.into_parts();
        assert_eq!(rest, b"NEXT");
    }

    #[test]
    fn refuses_smuggling_shapes() {
        let req = |extra: &str| {
            parse_request(format!("POST / HTTP/1.1\r\nHost: a\r\n{extra}\r\n").as_bytes()).unwrap()
        };
        assert!(
            req("Transfer-Encoding: chunked\r\nContent-Length: 4\r\n")
                .framing()
                .is_err()
        );
        assert!(
            req("Content-Length: 4\r\nContent-Length: 5\r\n")
                .framing()
                .is_err()
        );
        assert!(req("Transfer-Encoding: gzip\r\n").framing().is_err());
        assert!(req("Content-Length: +4\r\n").framing().is_err());
        assert_eq!(
            req("Content-Length: 4\r\n").framing().unwrap(),
            Framing::Length(4)
        );
        assert_eq!(
            req("Transfer-Encoding: chunked\r\n").framing().unwrap(),
            Framing::Chunked
        );
        assert_eq!(req("").framing().unwrap(), Framing::None);
    }

    #[test]
    fn a_head_that_ends_before_its_crlf_blank_line_is_refused() {
        let head = b"GET /a HTTP/1.1\nHost: a\n\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n";
        assert!(parse_request(head).is_err());
        assert!(parse_request(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n").is_ok());
    }

    #[test]
    fn exactly_one_well_formed_host_is_required() {
        let host = |extra: &str| {
            parse_request(format!("GET / HTTP/1.1\r\n{extra}\r\n").as_bytes())
                .unwrap()
                .single_host()
        };
        assert_eq!(
            host("Host: API.test:8443\r\n").unwrap(),
            ("api.test".into(), Some(8443))
        );
        assert!(host("").is_err());
        assert!(host("Host: a.test\r\nHost: b.test\r\n").is_err());
        assert!(host("Host: a.test\r\nhost: a.test\r\n").is_err());
        assert!(host("Host: user@a.test\r\n").is_err());
        assert!(host("Host: a.test/x\r\n").is_err());
        assert!(host("Host: a.test, b.test\r\n").is_err());
    }

    #[test]
    fn only_origin_form_targets_are_origin_form() {
        let form = |line: &str| {
            parse_request(format!("{line} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes())
                .unwrap()
                .is_origin_form()
        };
        assert!(form("GET /v1"));
        assert!(form("OPTIONS *"));
        assert!(!form("GET *"));
        assert!(!form("GET HTTPS://evil.test/steal"));
        assert!(!form("GET foo://evil.test/x"));
        assert!(!form("GET evil.test:443"));
    }

    #[test]
    fn detects_websocket_upgrades() {
        let req = parse_request(
            b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
        assert!(req.is_websocket_upgrade());
    }
}
