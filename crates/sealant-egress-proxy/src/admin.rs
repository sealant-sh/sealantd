//! The control-plane API on `/run/sealant/proxy-admin.sock`, reachable only by Sealant (the socket
//! lives on the proxy's own `mend-control` subpath, which the workspace never mounts).
//!
//! | Route                | Effect                                                              |
//! | -------------------- | ------------------------------------------------------------------- |
//! | `PUT /v1/policy`     | Load or replace the policy; closes streams it no longer allows.     |
//! | `POST /v1/revoke`    | Drop secrets/hosts and close matching streams, then answer `200`.   |
//! | `POST /v1/heartbeat` | Renew the disconnected lease; check the revocation watermark.       |
//! | `GET /v1/health`     | Readiness, policy hash, watermark, live connections, lease left.    |
//! | `GET /v1/events`     | NDJSON telemetry: the recent backlog, then live (`?follow=0` stops). |

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast::error::RecvError;
use tracing::Instrument as _;

use crate::http1::{HttpReader, parse_request};
use crate::policy::{Policy, PolicyDocument};
use crate::state::{HeartbeatRequest, RevokeRequest, Shared, StateError};

const MAX_BODY: u64 = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Bind the admin socket, replacing a stale socket file, readable and writable by owner and group.
pub(crate) fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_socket()
    {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

pub(crate) async fn serve(shared: Arc<Shared>, listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            handle(shared, stream).await;
        });
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
}

async fn send_json<W: AsyncWrite + Unpin>(w: &mut W, status: u16, body: &impl Serialize) {
    let body = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = w.write_all(head.as_bytes()).await;
    let _ = w.write_all(&body).await;
    let _ = w.flush().await;
}

async fn send_error<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: u16,
    error: &str,
    message: impl Into<String>,
) {
    send_json(
        w,
        status,
        &ErrorBody {
            error,
            message: message.into(),
        },
    )
    .await;
}

async fn send_state_error<W: AsyncWrite + Unpin>(w: &mut W, e: StateError) {
    let (status, code) = match &e {
        StateError::NotInitialized => (503, "not_initialized"),
        StateError::WatermarkRollback { .. } => (409, "watermark_rollback"),
        StateError::CloseTimeout(_) => (500, "close_unconfirmed"),
    };
    send_error(w, status, code, e.to_string()).await;
}

async fn handle(shared: Arc<Shared>, stream: UnixStream) {
    let mut reader = HttpReader::new(stream, Vec::new());
    let head = match tokio::time::timeout(REQUEST_TIMEOUT, reader.read_head()).await {
        Ok(Ok(Some(head))) => head,
        _ => return,
    };
    let Ok(req) = parse_request(&head) else {
        let (mut stream, _) = reader.into_parts();
        send_error(&mut stream, 400, "bad_request", "malformed request").await;
        return;
    };
    let length = match req.framing() {
        Ok(crate::http1::Framing::None) => 0,
        Ok(crate::http1::Framing::Length(n)) => n,
        _ => {
            let (mut stream, _) = reader.into_parts();
            send_error(
                &mut stream,
                400,
                "bad_request",
                "send a Content-Length body",
            )
            .await;
            return;
        }
    };
    if length > MAX_BODY {
        let (mut stream, _) = reader.into_parts();
        send_error(&mut stream, 413, "too_large", "body too large").await;
        return;
    }
    let mut body = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
    if tokio::time::timeout(REQUEST_TIMEOUT, reader.copy_exact(length, &mut body))
        .await
        .map_or(true, |r| r.is_err())
    {
        return;
    }
    let (mut stream, _) = reader.into_parts();
    let (path, query) = req
        .target
        .split_once('?')
        .unwrap_or((req.target.as_str(), ""));
    // The policy changes are spans, under the controller's `traceparent` when it sends one. The
    // body (brokered secrets among it) is never recorded: only which change it was.
    let change = match (req.method.as_str(), path) {
        ("PUT", "/v1/policy") => Some("sealantd.proxy.admin.policy"),
        ("POST", "/v1/revoke") => Some("sealantd.proxy.admin.revoke"),
        ("POST", "/v1/heartbeat") => Some("sealantd.proxy.admin.heartbeat"),
        _ => None,
    };
    let span = change.map_or_else(tracing::Span::none, |name| {
        let span = tracing::info_span!(
            "sealantd.proxy.admin",
            otel.name = name,
            otel.kind = "server"
        );
        let text = |name: &str| {
            req.header(name)
                .and_then(|value| std::str::from_utf8(value).ok())
                .unwrap_or_default()
        };
        sealant_observability::set_remote_parent(&span, text("traceparent"), text("tracestate"));
        span
    });
    let dispatch = async {
        match (req.method.as_str(), path) {
            ("PUT", "/v1/policy") => put_policy(&shared, &mut stream, &body).await,
            ("POST", "/v1/revoke") => revoke(&shared, &mut stream, &body).await,
            ("POST", "/v1/heartbeat") => heartbeat(&shared, &mut stream, &body).await,
            ("GET", "/v1/health") => send_json(&mut stream, 200, &shared.health()).await,
            ("GET", "/v1/events") => {
                let follow = !query
                    .split('&')
                    .any(|kv| kv == "follow=0" || kv == "follow=false");
                events(&shared, stream, follow).await;
            }
            (_, "/v1/policy" | "/v1/revoke" | "/v1/heartbeat" | "/v1/health" | "/v1/events") => {
                send_error(&mut stream, 405, "method_not_allowed", "wrong method").await;
            }
            _ => send_error(&mut stream, 404, "not_found", "no such route").await,
        }
    };
    dispatch.instrument(span).await;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Applied {
    ok: bool,
    policy_hash: String,
    revocation_watermark: u64,
    closed: usize,
}

async fn put_policy(shared: &Shared, stream: &mut UnixStream, body: &[u8]) {
    let doc: PolicyDocument = match serde_json::from_slice(body) {
        Ok(doc) => doc,
        Err(e) => return send_error(stream, 400, "invalid_policy", e.to_string()).await,
    };
    let previous = shared.current_policy();
    let policy = match Policy::from_document(doc, previous.as_deref()) {
        Ok(policy) => policy,
        Err(e) => return send_error(stream, 400, "invalid_policy", e.to_string()).await,
    };
    if let Some(ca) = &policy.ca
        && ca.trusted_by(&shared.upstream_roots)
    {
        return send_error(
            stream,
            400,
            "invalid_policy",
            "the executor CA is among the upstream roots; it must never be trusted upstream",
        )
        .await;
    }
    let policy_hash = policy.policy_hash.clone();
    let revocation_watermark = policy.revocation_watermark;
    match shared.apply_policy(policy).await {
        Ok(closed) => {
            send_json(
                stream,
                200,
                &Applied {
                    ok: true,
                    policy_hash,
                    revocation_watermark,
                    closed,
                },
            )
            .await;
        }
        Err(e) => send_state_error(stream, e).await,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Revoked {
    ok: bool,
    revocation_watermark: u64,
    closed: usize,
}

async fn revoke(shared: &Shared, stream: &mut UnixStream, body: &[u8]) {
    let request: RevokeRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return send_error(stream, 400, "invalid_revoke", e.to_string()).await,
    };
    let watermark = request.revocation_watermark;
    match shared.revoke(request).await {
        Ok(closed) => {
            send_json(
                stream,
                200,
                &Revoked {
                    ok: true,
                    revocation_watermark: watermark,
                    closed,
                },
            )
            .await;
        }
        Err(e) => send_state_error(stream, e).await,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Renewed {
    ok: bool,
    resync_required: bool,
    lease_remaining_ms: u64,
    revocation_watermark: u64,
}

async fn heartbeat(shared: &Shared, stream: &mut UnixStream, body: &[u8]) {
    let request: HeartbeatRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return send_error(
                stream,
                400,
                "invalid_heartbeat",
                format!("a heartbeat needs revocationWatermark: {e}"),
            )
            .await;
        }
    };
    match shared.heartbeat(request).await {
        Ok(resync_required) => {
            let health = shared.health();
            send_json(
                stream,
                200,
                &Renewed {
                    ok: true,
                    resync_required,
                    lease_remaining_ms: health.lease_remaining_ms,
                    revocation_watermark: health.revocation_watermark,
                },
            )
            .await;
        }
        Err(e) => send_state_error(stream, e).await,
    }
}

async fn events(shared: &Shared, mut stream: UnixStream, follow: bool) {
    let (mut live, backlog) = shared.events.subscribe();
    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    let mut last = 0;
    for line in backlog {
        last = line.seq;
        if write_line(&mut stream, &line.text).await.is_err() {
            return;
        }
    }
    if !follow {
        let _ = stream.shutdown().await;
        return;
    }
    loop {
        match live.recv().await {
            Ok(line) if line.seq <= last => {}
            Ok(line) => {
                last = line.seq;
                if write_line(&mut stream, &line.text).await.is_err() {
                    return;
                }
            }
            Err(RecvError::Lagged(skipped)) => {
                let note = format!("{{\"kind\":\"events_dropped\",\"count\":{skipped}}}");
                if write_line(&mut stream, &note).await.is_err() {
                    return;
                }
            }
            Err(RecvError::Closed) => return,
        }
    }
}

async fn write_line(stream: &mut UnixStream, text: &str) -> std::io::Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await
}
