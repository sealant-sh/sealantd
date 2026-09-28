//! The workspace's own Docker daemon, as the final capture sees it.
//!
//! A workspace can have a Docker daemon of its own: Core's Lambda MicroVM image starts `dockerd`
//! in the VM (`DOCKER_HOST=unix:///run/docker/docker.sock`), its Kubernetes adapter runs a
//! rootless dind sidecar in the Pod (the same socket path), and its Docker adapter attaches a
//! dind sidecar container on a per-workspace network (`DOCKER_HOST=tcp://docker:2375`, TLS off).
//! A container that daemon runs can bind-mount the worktree and write to it, and its processes
//! are neither in sealantd's process groups nor its descendants: the final capture stops every
//! container of that daemon (`POST /containers/{id}/stop?t=<grace>`: `SIGTERM`, then `SIGKILL`)
//! before it snaps, and waits until none is running.
//!
//! Which daemon ([`workspace_endpoint`]): `SEALANT_WORKSPACE_DOCKER_HOST` when the launcher sets
//! it; otherwise `DOCKER_HOST` only when it is one of the endpoints above, which Core reserves
//! for the workspace-scoped daemon (a caller cannot set `DOCKER_HOST`). Any other `DOCKER_HOST` —
//! a devcontainer pointing at its host's daemon, say — is never touched: stopping every
//! container of a host daemon would stop the workspace's own container and other people's.
//!
//! The client is a minimal HTTP/1.1 client of the Engine API over a Unix socket or plain TCP.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The launcher's explicit name for the workspace's own daemon.
pub const WORKSPACE_DOCKER_HOST_ENV: &str = "SEALANT_WORKSPACE_DOCKER_HOST";

/// `DOCKER_HOST` values Core sets for a workspace-scoped daemon: the MicroVM's and the
/// Kubernetes sidecar's socket, and the Docker adapter's dind sidecar.
pub const KNOWN_WORKSPACE_DOCKER_HOSTS: &[&str] =
    &["unix:///run/docker/docker.sock", "tcp://docker:2375"];

/// How long the final capture waits for the daemon to report no running container after the
/// stops returned.
const SETTLE: Duration = Duration::from_secs(5);

/// Beyond the grace, how long one Engine API call may take.
const CALL_SLACK: Duration = Duration::from_secs(30);

/// Where a Docker daemon listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerEndpoint {
    /// A Unix socket.
    Unix(PathBuf),
    /// Plain TCP, `host:port`.
    Tcp(String),
    /// A `DOCKER_HOST` this client cannot speak (`ssh://`, TLS): known to exist, never reached.
    Unsupported(String),
}

impl DockerEndpoint {
    /// Parse a `DOCKER_HOST`-style value.
    #[must_use]
    pub fn parse(host: &str) -> Self {
        let host = host.trim();
        if let Some(path) = host.strip_prefix("unix://") {
            Self::Unix(PathBuf::from(path))
        } else if let Some(addr) = host.strip_prefix("tcp://") {
            Self::Tcp(addr.trim_end_matches('/').to_owned())
        } else {
            Self::Unsupported(host.to_owned())
        }
    }
}

impl std::fmt::Display for DockerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            Self::Unsupported(raw) => f.write_str(raw),
        }
    }
}

/// The workspace's own daemon, from `SEALANT_WORKSPACE_DOCKER_HOST` (`explicit`) or a
/// `DOCKER_HOST` Core reserves for one. `None`: the workspace has none this capture stops.
#[must_use]
pub fn workspace_endpoint(
    explicit: Option<&str>,
    docker_host: Option<&str>,
) -> Option<DockerEndpoint> {
    if let Some(explicit) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(DockerEndpoint::parse(explicit));
    }
    docker_host
        .map(str::trim)
        .filter(|h| KNOWN_WORKSPACE_DOCKER_HOSTS.contains(h))
        .map(DockerEndpoint::parse)
}

/// What stopping the daemon's containers came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stopped {
    /// Containers that were running.
    pub containers: usize,
    /// Containers still running at the end.
    pub running: usize,
}

/// Stop every running container of `endpoint` with `grace` for its processes (`docker stop
/// -t`), concurrently, then wait up to [`SETTLE`] for the daemon to report none running.
///
/// # Errors
/// The daemon could not be reached, or answered something other than a container list or a
/// stop: nobody knows what still runs.
pub async fn stop_all(endpoint: &DockerEndpoint, grace: Duration) -> Result<Stopped, String> {
    let call = grace + CALL_SLACK;
    let running = list_running(endpoint, call).await?;
    let secs = grace.as_secs() + u64::from(grace.subsec_nanos() > 0);
    let mut stops = tokio::task::JoinSet::new();
    for id in &running {
        let endpoint = endpoint.clone();
        let path = format!("/containers/{id}/stop?t={secs}");
        let id = id.clone();
        stops.spawn(async move {
            let answer = request(&endpoint, "POST", &path, call).await;
            (id, answer)
        });
    }
    while let Some(joined) = stops.join_next().await {
        match joined {
            // 204 stopped, 304 already stopped, 404 gone meanwhile.
            Ok((id, Ok((204 | 304 | 404, _)))) => {
                tracing::info!(container = %id, "final capture: container stopped");
            }
            Ok((id, Ok((status, body)))) => tracing::warn!(
                container = %id,
                status,
                body = %String::from_utf8_lossy(&body),
                "final capture: the daemon refused to stop a container"
            ),
            Ok((id, Err(error))) => {
                tracing::warn!(container = %id, %error, "final capture: stopping a container failed");
            }
            Err(error) => tracing::warn!(%error, "final capture: a container stop task failed"),
        }
    }
    let until = Instant::now() + SETTLE;
    loop {
        let left = list_running(endpoint, call).await?;
        if left.is_empty() || Instant::now() >= until {
            return Ok(Stopped {
                containers: running.len(),
                running: left.len(),
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Ids of the running containers.
async fn list_running(endpoint: &DockerEndpoint, within: Duration) -> Result<Vec<String>, String> {
    let (status, body) = request(endpoint, "GET", "/containers/json", within).await?;
    if status != 200 {
        return Err(format!(
            "GET /containers/json: http {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    let list: Vec<serde_json::Value> =
        serde_json::from_slice(&body).map_err(|e| format!("GET /containers/json: {e}"))?;
    list.iter()
        .map(|c| {
            c.get("Id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "GET /containers/json: an entry without an Id".to_owned())
        })
        .collect()
}

/// One Engine API call; the status and the (de-chunked) body.
async fn request(
    endpoint: &DockerEndpoint,
    method: &str,
    path: &str,
    within: Duration,
) -> Result<(u16, Vec<u8>), String> {
    let call = async {
        match endpoint {
            DockerEndpoint::Unix(socket) => {
                let stream = tokio::net::UnixStream::connect(socket)
                    .await
                    .map_err(|e| format!("{endpoint}: {e}"))?;
                exchange(stream, method, path).await
            }
            DockerEndpoint::Tcp(addr) => {
                let stream = tokio::net::TcpStream::connect(addr.as_str())
                    .await
                    .map_err(|e| format!("{endpoint}: {e}"))?;
                exchange(stream, method, path).await
            }
            DockerEndpoint::Unsupported(raw) => Err(format!(
                "{raw}: this daemon's endpoint is not a unix:// or plain tcp:// one"
            )),
        }
    };
    tokio::time::timeout(within, call)
        .await
        .map_err(|_| format!("{method} {path}: no answer within {within:?}"))?
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    method: &str,
    path: &str,
) -> Result<(u16, Vec<u8>), String> {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| format!("{method} {path}: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("{method} {path}: {e}"))?;
    parse_response(&raw).map_err(|e| format!("{method} {path}: {e}"))
}

/// Parse an HTTP/1.1 response read to its end.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no end of headers")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("no status line")?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if !chunked {
        return Ok((status, body.to_vec()));
    }
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("a chunk without a size line")?;
        let size_line = String::from_utf8_lossy(&rest[..end]);
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| format!("a bad chunk size {size_line:?}"))?;
        rest = &rest[end + 2..];
        if size == 0 {
            return Ok((status, out));
        }
        if rest.len() < size {
            return Err("a truncated chunk".to_owned());
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_daemon_core_starts_for_the_workspace_is_stopped() {
        assert_eq!(
            workspace_endpoint(None, Some("unix:///run/docker/docker.sock")),
            Some(DockerEndpoint::Unix("/run/docker/docker.sock".into()))
        );
        assert_eq!(
            workspace_endpoint(None, Some("tcp://docker:2375")),
            Some(DockerEndpoint::Tcp("docker:2375".into()))
        );
        // A devcontainer's host daemon, the host's default socket: never.
        assert_eq!(
            workspace_endpoint(None, Some("unix:///var/run/docker.sock")),
            None
        );
        assert_eq!(workspace_endpoint(None, Some("tcp://10.0.0.1:2376")), None);
        assert_eq!(workspace_endpoint(None, None), None);
        // The launcher names it: taken as it is, whatever it is.
        assert_eq!(
            workspace_endpoint(
                Some("unix:///srv/d.sock"),
                Some("unix:///var/run/docker.sock")
            ),
            Some(DockerEndpoint::Unix("/srv/d.sock".into()))
        );
        assert_eq!(
            workspace_endpoint(Some("ssh://u@h"), None),
            Some(DockerEndpoint::Unsupported("ssh://u@h".into()))
        );
    }

    #[test]
    fn responses_parse_plain_and_chunked() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]";
        assert_eq!(parse_response(plain).unwrap(), (200, b"[]".to_vec()));
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n[{}\r\n1\r\n]\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap(), (200, b"[{}]".to_vec()));
        let stopped = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(parse_response(stopped).unwrap(), (204, Vec::new()));
    }
}
