//! The network runtime: capability-aware proxy startup, child proxy-env injection, source evidence.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sealant_protocol::{ExecutionId, NetworkMode};
use sealant_telemetry::EventBus;

use crate::capability::detect_mode;
use crate::proxy::{ProxyContext, start_proxy};

/// Network telemetry configuration.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Requested mode (may be degraded by [`detect_mode`]).
    pub mode: NetworkMode,
    /// Execution to correlate observations with.
    pub execution_id: Option<ExecutionId>,
}

/// Owns the egress proxy task and exposes the child proxy-env to inject.
pub struct NetworkRuntime {
    bus: Arc<EventBus>,
    config: NetworkConfig,
    started: AtomicBool,
    effective_mode: Mutex<NetworkMode>,
    proxy_addr: Mutex<Option<SocketAddr>>,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for NetworkRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkRuntime")
            .field("requested_mode", &self.config.mode)
            .finish_non_exhaustive()
    }
}

impl NetworkRuntime {
    /// Create a network runtime (not yet started).
    #[must_use]
    pub fn new(bus: Arc<EventBus>, config: NetworkConfig) -> Self {
        Self {
            bus,
            config,
            started: AtomicBool::new(false),
            effective_mode: Mutex::new(NetworkMode::Off),
            proxy_addr: Mutex::new(None),
            handle: Mutex::new(None),
        }
    }

    fn set_mode(&self, mode: NetworkMode) {
        *self
            .effective_mode
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = mode;
    }

    /// Start observation. Returns the **effective** mode (degraded to `Off` if the proxy can't bind).
    pub async fn start(&self) -> NetworkMode {
        self.started.store(true, Ordering::Relaxed);
        let mode = detect_mode(self.config.mode);
        if mode == NetworkMode::Off {
            self.set_mode(NetworkMode::Off);
            return NetworkMode::Off;
        }
        // Metadata/Privileged degraded to Proxy by detect_mode (or genuinely Proxy): run the proxy.
        match start_proxy(ProxyContext {
            bus: self.bus.clone(),
            execution_id: self.config.execution_id.clone(),
        })
        .await
        {
            Ok((addr, handle)) => {
                *self.proxy_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
                *self.handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
                self.set_mode(NetworkMode::Proxy);
                tracing::info!(%addr, "egress proxy started");
                NetworkMode::Proxy
            }
            Err(error) => {
                tracing::warn!(%error, "egress proxy failed to bind; network observation disabled");
                self.set_mode(NetworkMode::Off);
                NetworkMode::Off
            }
        }
    }

    /// The effective mode after [`NetworkRuntime::start`].
    #[must_use]
    pub fn effective_mode(&self) -> NetworkMode {
        *self
            .effective_mode
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The mode to report in capabilities: the live effective mode once started, otherwise the
    /// mode capability detection *would* select (so pre-flight `--print-capabilities` is honest).
    #[must_use]
    pub fn capability_mode(&self) -> NetworkMode {
        if self.started.load(Ordering::Relaxed) {
            self.effective_mode()
        } else {
            detect_mode(self.config.mode)
        }
    }

    /// The bound proxy address, if running.
    #[must_use]
    pub fn proxy_addr(&self) -> Option<SocketAddr> {
        *self.proxy_addr.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Proxy environment variables to inject into child processes (empty if no proxy is running).
    #[must_use]
    pub fn proxy_env(&self) -> Vec<(String, String)> {
        let Some(addr) = self.proxy_addr() else {
            return Vec::new();
        };
        let url = format!("http://{addr}");
        sealant_runtime_core::PROXY_ENV_KEYS
            .iter()
            .map(|key| ((*key).to_owned(), url.clone()))
            .collect()
    }

    /// Stop the proxy task.
    pub fn shutdown(&self) {
        if let Some(handle) = self.handle.lock().unwrap_or_else(|e| e.into_inner()).take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_protocol::{EventEnvelope, EventPayload, NetworkScheme};
    use sealant_runtime_core::{Clock, IdGenerator, new_runtime_id};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::broadcast::Receiver;

    fn bus() -> Arc<EventBus> {
        let rt = new_runtime_id();
        Arc::new(EventBus::new(
            rt.clone(),
            Arc::new(Clock::new()),
            Arc::new(IdGenerator::new(&rt)),
            1024,
        ))
    }

    async fn wait_for(rx: &mut Receiver<EventEnvelope>, event_type: &str) -> Option<EventEnvelope> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(env)) if env.event_type() == event_type => return Some(env),
                Ok(Ok(_)) => {}
                _ => return None,
            }
        }
    }

    /// No process's secret env may name a variable the proxy sets on it, so none replaces the
    /// proxy's routing or loses to it.
    #[tokio::test]
    async fn a_secret_env_may_name_no_proxy_variable() {
        use sealant_process::secret_env::{Rule, SecretEnv};
        let net = NetworkRuntime::new(
            bus(),
            NetworkConfig {
                mode: NetworkMode::Proxy,
                execution_id: None,
            },
        );
        assert_eq!(net.start().await, NetworkMode::Proxy);
        let set = net.proxy_env();
        assert!(!set.is_empty());
        for (key, _) in set {
            let secret = sealant_protocol::SecretEnvVar {
                key: key.clone(),
                value: "fake-pg-password-5d1e".to_owned(),
            };
            let refused = SecretEnv::parse(vec![secret], &[]).err();
            assert_eq!(refused.map(|r| r.rule), Some(Rule::NameProxy), "{key}");
        }
        net.shutdown();
    }

    #[tokio::test]
    async fn proxies_plain_http_and_emits_request() {
        // Origin server: respond 200 + body, then close.
        let origin = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind origin");
        let origin_addr = origin.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut s, _)) = origin.accept().await {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
                    )
                    .await;
            }
        });

        let bus = bus();
        let mut rx = bus.subscribe();
        let net = NetworkRuntime::new(
            bus.clone(),
            NetworkConfig {
                mode: NetworkMode::Proxy,
                execution_id: None,
            },
        );
        assert_eq!(net.start().await, NetworkMode::Proxy);
        let proxy_addr = net.proxy_addr().expect("proxy addr");

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
        let request =
            format!("GET http://{origin_addr}/hello HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
        client.write_all(request.as_bytes()).await.expect("write");
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("read");
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("200 OK"), "response: {text}");
        assert!(text.ends_with("hi"), "response: {text}");

        let event = wait_for(&mut rx, "network.request")
            .await
            .expect("network.request");
        match event.payload {
            EventPayload::NetworkRequest(r) => {
                assert_eq!(r.scheme, NetworkScheme::Http);
                assert_eq!(r.method.as_deref(), Some("GET"));
                assert_eq!(r.path.as_deref(), Some("/hello"));
                assert_eq!(r.status, Some(200));
                assert_eq!(r.host, "127.0.0.1");
                assert_eq!(r.port, origin_addr.port());
            }
            other => panic!("expected network.request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tunnels_connect_and_counts_bytes() {
        // Echo server stands in for an HTTPS endpoint behind CONNECT.
        let echo = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind echo");
        let echo_addr = echo.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo.accept().await {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let bus = bus();
        let mut rx = bus.subscribe();
        let net = NetworkRuntime::new(
            bus.clone(),
            NetworkConfig {
                mode: NetworkMode::Privileged, // degrades to proxy without caps
                execution_id: None,
            },
        );
        assert_eq!(net.start().await, NetworkMode::Proxy);
        let proxy_addr = net.proxy_addr().expect("proxy addr");

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
        client
            .write_all(format!("CONNECT {echo_addr} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("write connect");
        let mut established = [0u8; 64];
        let n = client.read(&mut established).await.expect("read 200");
        assert!(
            String::from_utf8_lossy(&established[..n]).contains("200"),
            "no 200 established"
        );

        client.write_all(b"ping").await.expect("write ping");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("read echo");
        assert_eq!(&echoed, b"ping");
        client.shutdown().await.expect("shutdown");
        drop(client);

        let event = wait_for(&mut rx, "network.request")
            .await
            .expect("network.request");
        match event.payload {
            EventPayload::NetworkRequest(r) => {
                assert_eq!(r.scheme, NetworkScheme::HttpsConnect);
                assert_eq!(r.host, "127.0.0.1");
                assert_eq!(r.port, echo_addr.port());
                assert!(r.bytes_sent >= 4, "bytes_sent={}", r.bytes_sent);
                assert!(r.bytes_received >= 4, "bytes_received={}", r.bytes_received);
            }
            other => panic!("expected network.request, got {other:?}"),
        }
    }
}
