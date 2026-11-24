//! The session channel inside the guest: a loopback TCP listener (`MEND_SESSION_ENDPOINT`)
//! whose every connection is relayed, byte for byte, to the host's `session.sock` over vsock
//! port 1027. Workspace tools speak plain HTTP to `127.0.0.1:<port>` as they would to the
//! socket on the `docker` runtime; the host side authenticates every request (per-person bearer
//! tokens), so the forwarder adds nothing and reads nothing.

use std::future::Future;
use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

/// Bind the guest's loopback listener on an ephemeral port.
///
/// # Errors
/// The bind failed (no loopback interface).
pub async fn bind() -> io::Result<TcpListener> {
    TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await
}

/// The `MEND_SESSION_ENDPOINT` value for `listener`.
///
/// # Errors
/// The listener's address could not be read.
pub fn endpoint(listener: &TcpListener) -> io::Result<String> {
    Ok(format!("http://{}", listener.local_addr()?))
}

/// Relay every connection `listener` accepts to a stream `dial` opens, until `shutdown`. A
/// connection whose dial fails is closed at once (the host is not serving the channel); the
/// others are unaffected. Returns once the listener stopped and every relay has ended.
pub async fn forward<D, F, S>(listener: TcpListener, dial: D, mut shutdown: watch::Receiver<bool>)
where
    D: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<S>> + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let dial = std::sync::Arc::new(dial);
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            Some(_) = relays.join_next(), if !relays.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((mut client, _)) => {
                    let dial = dial.clone();
                    relays.spawn(async move {
                        match dial().await {
                            Ok(mut upstream) => {
                                if let Err(error) =
                                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                                {
                                    tracing::debug!(%error, "session relay ended");
                                }
                            }
                            Err(error) => tracing::warn!(
                                %error,
                                "the host's session channel (vsock 1027) refused a connection"
                            ),
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "session listener accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
    drop(listener);
    relays.abort_all();
    while relays.join_next().await.is_some() {}
}

/// [`forward`] to the host's `session.sock` (CID 2, port 1027).
#[cfg(target_os = "linux")]
pub async fn forward_to_host(listener: TcpListener, shutdown: watch::Receiver<bool>) {
    use sealant_control::vsock::{SESSION_PORT, VMADDR_CID_HOST, VsockStream};
    forward(
        listener,
        || VsockStream::connect(VMADDR_CID_HOST, SESSION_PORT),
        shutdown,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    /// A stand-in for the host's `session.sock`: answers each connection with what it read,
    /// upper-cased, then closes.
    fn upstream(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("session.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64];
                    let read = stream.read(&mut buf).await.unwrap_or(0);
                    let reply = String::from_utf8_lossy(&buf[..read]).to_uppercase();
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        path
    }

    #[tokio::test]
    async fn each_loopback_connection_is_relayed_to_its_own_upstream_stream() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = upstream(&dir);
        let listener = bind().await.expect("bind");
        let url = endpoint(&listener).expect("endpoint");
        assert!(url.starts_with("http://127.0.0.1:"), "{url}");
        let address = listener.local_addr().expect("addr");
        let (stop, stopped) = watch::channel(false);
        let relay = tokio::spawn(forward(
            listener,
            move || UnixStream::connect(socket.clone()),
            stopped,
        ));

        for word in ["get /git", "post /mcp"] {
            let mut client = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            client.write_all(word.as_bytes()).await.expect("write");
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.expect("read");
            assert_eq!(reply, word.to_uppercase());
        }

        stop.send(true).expect("stop");
        relay.await.expect("join");
        assert!(
            tokio::net::TcpStream::connect(address).await.is_err(),
            "the listener is gone after the stop"
        );
    }

    #[tokio::test]
    async fn a_failed_dial_closes_that_connection_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = upstream(&dir);
        let listener = bind().await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let (_stop, stopped) = watch::channel(false);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        tokio::spawn(forward(
            listener,
            move || {
                let first = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
                let socket = socket.clone();
                async move {
                    if first {
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    } else {
                        UnixStream::connect(socket).await
                    }
                }
            },
            stopped,
        ));

        let mut refused = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let mut nothing = Vec::new();
        refused
            .read_to_end(&mut nothing)
            .await
            .expect("closed cleanly");
        assert!(nothing.is_empty());

        let mut served = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        served.write_all(b"ok").await.expect("write");
        let mut reply = String::new();
        served.read_to_string(&mut reply).await.expect("read");
        assert_eq!(reply, "OK");
    }
}
