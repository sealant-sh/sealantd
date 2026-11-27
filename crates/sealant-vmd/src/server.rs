//! Loopback HTTP/1.1 control server + `Upgrade: sealant-vmm-v1` direct TCP FD handoff.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sealant_vmm_proto::{
    HealthResponse, LaunchVmRequest, PROTOCOL_VERSION, UPGRADE_PROTOCOL, WorkerLaunchSpec,
    kernel_cmdline, validate_host_header, validate_mac, verify_bearer_token,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::{disk, selftest, sys};

/// Maximum concurrent unauthenticated connections accepted at once.
const MAX_PRE_AUTH_CONNS: usize = 32;
/// Hard deadline for completing the HTTP head + body before authentication succeeds.
const PRE_AUTH_DEADLINE: Duration = Duration::from_secs(2);
/// Maximum HTTP head + body bytes read on any control request.
const MAX_REQUEST_BYTES: usize = 32 * 1024;
/// Minimum and maximum allowed VM memory (128 MiB ..= 128 GiB).
const MIN_VM_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_VM_MEMORY_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MIN_MTU: u32 = 1500;
const MAX_MTU: u32 = 65_520;

/// Runtime configuration for a `sealant-vmd` instance.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub bearer_token: String,
    pub vm_root: PathBuf,
    pub kernel_path: PathBuf,
    pub worker_path: PathBuf,
}

#[derive(Debug)]
pub struct ServerState {
    config: Config,
    listen_port: u16,
    instance_nonce: String,
    kernel_sha256: String,
    workers_running: AtomicU32,
    pre_auth_permits: Arc<Semaphore>,
}

impl ServerState {
    pub fn new(config: Config, listen_port: u16) -> io::Result<Arc<Self>> {
        let mut nonce_bytes = [0u8; 16];
        getrandom::getrandom(&mut nonce_bytes).map_err(|e| io::Error::other(e.to_string()))?;
        let kernel_sha256 = sha256_file(&config.kernel_path).unwrap_or_default();
        Ok(Arc::new(Self {
            config,
            listen_port,
            instance_nonce: hex::encode(nonce_bytes),
            kernel_sha256,
            workers_running: AtomicU32::new(0),
            pre_auth_permits: Arc::new(Semaphore::new(MAX_PRE_AUTH_CONNS)),
        }))
    }

    pub fn instance_nonce(&self) -> &str {
        &self.instance_nonce
    }

    pub fn workers_running(&self) -> u32 {
        self.workers_running.load(Ordering::Relaxed)
    }
}

/// Binds strictly on loopback (`127.0.0.1` or `::1`) and returns `(TcpListener, Arc<ServerState>)`.
pub async fn bind(config: Config) -> io::Result<(TcpListener, Arc<ServerState>)> {
    if !config.listen_addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "sealant-vmd refuses to bind non-loopback address {}",
                config.listen_addr
            ),
        ));
    }
    let listener = TcpListener::bind(config.listen_addr).await?;
    let bound_port = listener.local_addr()?.port();
    let state = ServerState::new(config, bound_port)?;
    Ok((listener, state))
}

/// Runs the accept loop until the listener fails or `shutdown` triggers.
pub async fn serve(
    listener: TcpListener,
    state: Arc<ServerState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = state.pre_auth_permits.clone().try_acquire_owned() else {
                    tracing::warn!(%peer, "dropping connection: pre-auth concurrency cap reached");
                    drop(stream);
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state, permit).await {
                        tracing::debug!(%peer, "connection ended: {e}");
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

struct ParsedRequest {
    method: String,
    path: String,
    host: Option<String>,
    origin: Option<String>,
    authorization: Option<String>,
    upgrade: Option<String>,
    body: Vec<u8>,
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<ServerState>,
    pre_auth_permit: tokio::sync::OwnedSemaphorePermit,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let parsed = match tokio::time::timeout(PRE_AUTH_DEADLINE, read_http_request(&mut stream)).await
    {
        Ok(Ok(req)) => req,
        Ok(Err(HttpReadError::TooLarge)) => {
            write_json_response(
                &mut stream,
                413,
                "Payload Too Large",
                &serde_json::json!({"error": "request too large"}),
            )
            .await?;
            return Ok(());
        }
        Ok(Err(HttpReadError::Malformed(msg))) => {
            write_json_response(
                &mut stream,
                400,
                "Bad Request",
                &serde_json::json!({"error": msg}),
            )
            .await?;
            return Ok(());
        }
        Ok(Err(HttpReadError::Io(e))) => return Err(e),
        Err(_) => {
            write_json_response(
                &mut stream,
                408,
                "Request Timeout",
                &serde_json::json!({"error": "pre-auth deadline exceeded"}),
            )
            .await?;
            return Ok(());
        }
    };

    // 1. Reject any browser Origin header and any DNS-rebound Host header.
    if parsed.origin.is_some() {
        write_json_response(
            &mut stream,
            403,
            "Forbidden",
            &serde_json::json!({"error": "Origin header is forbidden"}),
        )
        .await?;
        return Ok(());
    }
    let host_ok = parsed
        .host
        .as_deref()
        .is_some_and(|h| validate_host_header(h, state.listen_port));
    if !host_ok {
        write_json_response(
            &mut stream,
            403,
            "Forbidden",
            &serde_json::json!({"error": "invalid Host header"}),
        )
        .await?;
        return Ok(());
    }

    // 2. Constant-time bearer auth.
    let auth_ok = parsed
        .authorization
        .as_deref()
        .is_some_and(|h| verify_bearer_token(h, &state.config.bearer_token));
    if !auth_ok {
        write_json_response(
            &mut stream,
            401,
            "Unauthorized",
            &serde_json::json!({"error": "invalid bearer token"}),
        )
        .await?;
        return Ok(());
    }
    // Authenticated: release the pre-auth permit immediately.
    drop(pre_auth_permit);

    match (parsed.method.as_str(), parsed.path.as_str()) {
        ("GET", "/v1/health") => {
            let (memory_bytes, available_memory_bytes, memory_pressure) = sys::host_memory();
            let resp = HealthResponse {
                protocol_version: PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                instance_nonce: state.instance_nonce.clone(),
                kernel_sha256: state.kernel_sha256.clone(),
                arch: std::env::consts::ARCH.to_owned(),
                macos_version: sys::macos_version_string(),
                host_ips: sys::host_interface_ips(),
                memory_bytes,
                available_memory_bytes,
                memory_pressure,
                disk_available_important_bytes: sys::disk_available_bytes(&state.config.vm_root),
                workers_running: state.workers_running(),
            };
            write_json_response(&mut stream, 200, "OK", &resp).await?;
        }
        ("GET", "/v1/self-test") => {
            let report = selftest::run(
                &state.config.kernel_path,
                &state.config.worker_path,
                &state.config.vm_root,
            );
            write_json_response(&mut stream, 200, "OK", &report).await?;
        }
        ("POST", "/v1/vms") => {
            handle_launch_vm(stream, parsed, state).await?;
        }
        _ => {
            write_json_response(
                &mut stream,
                404,
                "Not Found",
                &serde_json::json!({"error": "not found"}),
            )
            .await?;
        }
    }
    Ok(())
}

async fn handle_launch_vm(
    mut stream: TcpStream,
    parsed: ParsedRequest,
    state: Arc<ServerState>,
) -> io::Result<()> {
    let wants_upgrade = parsed
        .upgrade
        .as_deref()
        .is_some_and(|u| u.eq_ignore_ascii_case(UPGRADE_PROTOCOL));
    if !wants_upgrade {
        write_json_response(
            &mut stream,
            426,
            "Upgrade Required",
            &serde_json::json!({"error": format!("Upgrade: {UPGRADE_PROTOCOL} is required")}),
        )
        .await?;
        return Ok(());
    }

    let req: LaunchVmRequest = match serde_json::from_slice(&parsed.body) {
        Ok(r) => r,
        Err(e) => {
            write_json_response(
                &mut stream,
                400,
                "Bad Request",
                &serde_json::json!({"error": format!("invalid launch JSON: {e}")}),
            )
            .await?;
            return Ok(());
        }
    };

    if req.protocol_version != PROTOCOL_VERSION {
        write_json_response(
            &mut stream,
            426,
            "Upgrade Required",
            &serde_json::json!({
                "error": format!(
                    "unsupported protocolVersion {} (expected {PROTOCOL_VERSION})",
                    req.protocol_version
                )
            }),
        )
        .await?;
        return Ok(());
    }
    if req.vcpus == 0 || req.vcpus > 64 {
        write_json_response(
            &mut stream,
            400,
            "Bad Request",
            &serde_json::json!({"error": "vcpus must be 1..=64"}),
        )
        .await?;
        return Ok(());
    }
    if !(MIN_VM_MEMORY_BYTES..=MAX_VM_MEMORY_BYTES).contains(&req.memory_bytes) {
        write_json_response(
            &mut stream,
            400,
            "Bad Request",
            &serde_json::json!({"error": "memoryBytes out of allowed range"}),
        )
        .await?;
        return Ok(());
    }
    if !(MIN_MTU..=MAX_MTU).contains(&req.mtu) {
        write_json_response(
            &mut stream,
            400,
            "Bad Request",
            &serde_json::json!({"error": "mtu must be 1500..=65520"}),
        )
        .await?;
        return Ok(());
    }
    let normalized_mac = match req.mac.as_deref() {
        Some(mac) => match validate_mac(mac) {
            Ok(m) => Some(m),
            Err(e) => {
                write_json_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    &serde_json::json!({"error": e}),
                )
                .await?;
                return Ok(());
            }
        },
        None => None,
    };

    let disks = match disk::resolve_and_validate(
        &state.config.vm_root,
        &req.base_image_key,
        &req.vm_name,
    ) {
        Ok(d) => d,
        Err(disk::DiskError::AlreadyLocked(msg)) => {
            write_json_response(
                &mut stream,
                409,
                "Conflict",
                &serde_json::json!({"error": format!("data disk already locked: {msg}")}),
            )
            .await?;
            return Ok(());
        }
        Err(disk::DiskError::NotFound(msg)) => {
            write_json_response(
                &mut stream,
                404,
                "Not Found",
                &serde_json::json!({"error": format!("disk not found: {msg}")}),
            )
            .await?;
            return Ok(());
        }
        Err(e) => {
            write_json_response(
                &mut stream,
                400,
                "Bad Request",
                &serde_json::json!({"error": e.to_string()}),
            )
            .await?;
            return Ok(());
        }
    };

    let spec = WorkerLaunchSpec {
        protocol_version: PROTOCOL_VERSION,
        vm_name: req.vm_name.clone(),
        mode: req.mode,
        vm_root: disks.vm_root.display().to_string(),
        kernel_path: state.config.kernel_path.display().to_string(),
        base_image_path: disks.base_image.display().to_string(),
        data_image_path: disks.data_image.display().to_string(),
        cmdline: kernel_cmdline("hvc0", req.mode),
        vcpus: req.vcpus,
        memory_bytes: req.memory_bytes,
        mac: normalized_mac,
        mtu: req.mtu,
        transport_fd: sys::WORKER_TRANSPORT_FD,
    };
    let spec_bytes = serde_json::to_vec(&spec).map_err(io::Error::other)?;

    // Send 101 Switching Protocols BEFORE handing the socket FD to `sealant-vz-worker`.
    let upgrade_reply = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: {UPGRADE_PROTOCOL}\r\nConnection: Upgrade\r\n\r\n"
    );
    stream.write_all(upgrade_reply.as_bytes()).await?;
    stream.flush().await?;

    // Convert Tokio TcpStream -> std TcpStream so it can be inherited cleanly as FD 3.
    let std_stream = stream.into_std()?;
    let tcp_fd = std_stream.as_raw_fd();

    let mut cmd = Command::new(&state.config.worker_path);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    sys::configure_worker_handoff(&mut cmd, tcp_fd);

    #[allow(
        clippy::disallowed_methods,
        reason = "sealant-vmd is a standalone macOS daemon with no orphan reaper and must pass FD 3 via pre_exec"
    )]
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(vm = %req.vm_name, "failed to spawn sealant-vz-worker: {e}");
            return Err(e);
        }
    };

    // Immediately drop our copy of the TCP socket FD so sealant-vmd is 100% out of the data path!
    drop(std_stream);

    // Feed the validated launch spec over stdin and close stdin immediately.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&spec_bytes);
        let _ = stdin.flush();
    }

    let pid = child.id();
    state.workers_running.fetch_add(1, Ordering::Relaxed);
    tracing::info!(vm = %req.vm_name, pid, "handed TCP FD to sealant-vz-worker");

    let state_reap = Arc::clone(&state);
    let vm_name = req.vm_name;
    tokio::task::spawn_blocking(move || {
        let status = child.wait();
        state_reap.workers_running.fetch_sub(1, Ordering::Relaxed);
        tracing::info!(vm = %vm_name, pid, ?status, "sealant-vz-worker exited");
    });

    Ok(())
}

enum HttpReadError {
    TooLarge,
    Malformed(&'static str),
    Io(io::Error),
}

impl From<io::Error> for HttpReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Result<ParsedRequest, HttpReadError> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() >= MAX_REQUEST_BYTES {
            return Err(HttpReadError::TooLarge);
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(HttpReadError::Malformed("unexpected EOF reading headers"));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&buf[..header_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(HttpReadError::Malformed("malformed HTTP request")),
    }
    let method = req
        .method
        .ok_or(HttpReadError::Malformed("missing method"))?
        .to_owned();
    let path = req
        .path
        .ok_or(HttpReadError::Malformed("missing path"))?
        .to_owned();

    let mut host = None;
    let mut origin = None;
    let mut authorization = None;
    let mut upgrade = None;
    let mut content_length: usize = 0;

    for h in req.headers {
        let Ok(val) = std::str::from_utf8(h.value) else {
            return Err(HttpReadError::Malformed("non-UTF8 header value"));
        };
        let val = val.trim();
        if h.name.eq_ignore_ascii_case("host") {
            host = Some(val.to_owned());
        } else if h.name.eq_ignore_ascii_case("origin") {
            origin = Some(val.to_owned());
        } else if h.name.eq_ignore_ascii_case("authorization") {
            authorization = Some(val.to_owned());
        } else if h.name.eq_ignore_ascii_case("upgrade") {
            upgrade = Some(val.to_owned());
        } else if h.name.eq_ignore_ascii_case("content-length") {
            content_length = val
                .parse::<usize>()
                .map_err(|_| HttpReadError::Malformed("invalid Content-Length"))?;
        }
    }

    if header_end.saturating_add(content_length) > MAX_REQUEST_BYTES {
        return Err(HttpReadError::TooLarge);
    }

    let mut body = buf[header_end..].to_vec();
    if body.len() > content_length {
        // Reject pipelined trailing bytes before upgrade so no frames get accidentally consumed.
        body.truncate(content_length);
    }
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let take = remaining.min(tmp.len());
        let n = stream.read(&mut tmp[..take]).await?;
        if n == 0 {
            return Err(HttpReadError::Malformed("unexpected EOF reading body"));
        }
        body.extend_from_slice(&tmp[..n]);
    }

    Ok(ParsedRequest {
        method,
        path,
        host,
        origin,
        authorization,
        upgrade,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

async fn write_json_response<T: serde::Serialize>(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &T,
) -> io::Result<()> {
    let payload = serde_json::to_vec(body).map_err(io::Error::other)?;
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await
}

fn sha256_file(path: &PathBuf) -> io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_vmm_proto::{Frame, RunnerControl, VmMode, WorkerControl, read_frame, write_frame};
    use std::os::unix::fs::PermissionsExt;

    async fn raw_http(addr: SocketAddr, req: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn enforces_auth_host_origin_protocol_and_hands_off_fd3() {
        let tmp = tempfile::tempdir().unwrap();
        let vm_root = tmp.path().join("vm");
        std::fs::create_dir_all(vm_root.join("images")).unwrap();
        std::fs::create_dir_all(vm_root.join("data/ws-1")).unwrap();
        std::fs::write(vm_root.join("images/sha256-abc.img"), b"base").unwrap();
        std::fs::write(vm_root.join("data/ws-1/data.img"), b"data").unwrap();
        let kernel = tmp.path().join("Image");
        std::fs::write(&kernel, b"fake-kernel").unwrap();

        // Fake worker script: reads JSON spec from stdin, then sends a Control frame directly
        // over inherited FD 3 and reads back one RunnerControl frame before exiting!
        let worker = tmp.path().join("fake-worker.py");
        std::fs::write(
            &worker,
            r#"#!/usr/bin/env python3
import json, os, struct, sys

spec = json.loads(sys.stdin.read())
fd = spec["transportFd"]

def send_frame(kind, sid, payload):
    os.write(fd, struct.pack(">BII", kind, sid, len(payload)) + payload)

def read_exact(n):
    out = bytearray()
    while len(out) < n:
        chunk = os.read(fd, n - len(out))
        if not chunk:
            raise EOFError()
        out.extend(chunk)
    return bytes(out)

started = json.dumps({"type": "vmStarted", "bootTimeUtcMs": 12345, "negotiatedMtu": spec["mtu"]}).encode()
send_frame(1, 0, started)
hdr = read_exact(9)
kind, sid, length = struct.unpack(">BII", hdr)
payload = read_exact(length)
assert kind == 1
msg = json.loads(payload.decode())
assert msg["type"] == "requestStop"
exited = json.dumps({"type": "vmExited", "clean": True}).encode()
send_frame(1, 0, exited)
"#,
        )
        .unwrap();
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cfg = Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bearer_token: "super-secret-token".to_owned(),
            vm_root,
            kernel_path: kernel,
            worker_path: worker,
        };
        let (listener, state) = bind(cfg).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let server_task = tokio::spawn(serve(listener, Arc::clone(&state), rx));

        // 1. Missing auth -> 401
        let r = raw_http(
            addr,
            &format!("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 401 "), "{r}");

        // 2. DNS rebinding Host -> 403
        let r = raw_http(
            addr,
            &format!("GET /v1/health HTTP/1.1\r\nHost: evil.example:{port}\r\nAuthorization: Bearer super-secret-token\r\n\r\n"),
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 403 "), "{r}");

        // 3. Browser Origin header -> 403
        let r = raw_http(
            addr,
            &format!("GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://evil.example\r\nAuthorization: Bearer super-secret-token\r\n\r\n"),
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 403 "), "{r}");

        // 4. Valid /v1/health -> 200 with instanceNonce
        let r = raw_http(
            addr,
            &format!("GET /v1/health HTTP/1.1\r\nHost: host.docker.internal:{port}\r\nAuthorization: Bearer super-secret-token\r\n\r\n"),
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 200 "), "{r}");
        assert!(r.contains(state.instance_nonce()), "{r}");

        // 5. POST /v1/vms Upgrade -> 101 + direct FD 3 communication surviving server shutdown!
        let mut s = TcpStream::connect(addr).await.unwrap();
        let launch_body = serde_json::to_string(&LaunchVmRequest {
            protocol_version: 1,
            vm_name: "ws-1".to_owned(),
            mode: VmMode::Normal,
            base_image_key: "sha256-abc".to_owned(),
            vcpus: 2,
            memory_bytes: 512 * 1024 * 1024,
            mac: Some("02:aa:bb:cc:dd:ee".to_owned()),
            mtu: 65_520,
        })
        .unwrap();
        let upgrade_req = format!(
            "POST /v1/vms HTTP/1.1\r\nHost: host.docker.internal:{port}\r\nAuthorization: Bearer super-secret-token\r\nConnection: Upgrade\r\nUpgrade: sealant-vmm-v1\r\nContent-Length: {}\r\n\r\n{}",
            launch_body.len(),
            launch_body
        );
        s.write_all(upgrade_req.as_bytes()).await.unwrap();

        let mut head = Vec::new();
        while find_header_end(&head).is_none() {
            let b = s.read_u8().await.unwrap();
            head.push(b);
        }
        let head_str = String::from_utf8(head).unwrap();
        assert!(head_str.starts_with("HTTP/1.1 101 "), "{head_str}");

        // Read VmStarted directly from the spawned worker on FD 3!
        let f1 = read_frame(&mut s).await.unwrap().unwrap();
        let started: WorkerControl = serde_json::from_slice(&f1.payload).unwrap();
        assert_eq!(
            started,
            WorkerControl::VmStarted {
                boot_time_utc_ms: 12345,
                negotiated_mtu: 65_520,
            }
        );

        // Shut down sealant-vmd's accept loop BEFORE sending RequestStop to prove the live
        // runner <-> worker FD 3 link survives sealant-vmd exiting!
        let _ = tx.send(true);
        server_task.await.unwrap().unwrap();

        write_frame(
            &mut s,
            &Frame::control_json(&RunnerControl::RequestStop).unwrap(),
        )
        .await
        .unwrap();
        let f2 = read_frame(&mut s).await.unwrap().unwrap();
        let exited: WorkerControl = serde_json::from_slice(&f2.payload).unwrap();
        assert_eq!(
            exited,
            WorkerControl::VmExited {
                clean: true,
                error: None,
            }
        );
    }
}
