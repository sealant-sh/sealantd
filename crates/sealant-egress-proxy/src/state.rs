//! Shared state: the loaded policy, the revocation watermark, the disconnected lease, and the
//! registry of live connections that revocation and lease expiry close.
//!
//! A connection is admitted under the same lock that policy updates and revocations take, so a
//! connection is either registered before a revocation scans the registry (and is closed by it) or
//! admitted after it against the new policy (and refused). There is no window between the two.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::dns::resolver::Resolver;
use crate::events::{Event, EventHub};
use crate::policy::{Mode, Policy, normalize_host};

/// How long a revocation waits for the connections it cancelled to report closed.
const CLOSE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ingress {
    Explicit,
    TransparentHttp,
    TransparentHttps,
    TransparentTcp,
    TransparentResource,
    Dns,
}

impl Ingress {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::TransparentHttp => "transparent_http",
            Self::TransparentHttps => "transparent_https",
            Self::TransparentTcp => "transparent_tcp",
            Self::TransparentResource => "transparent_resource",
            Self::Dns => "dns",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnKind {
    PlainHttp,
    Passthrough,
    Mitm,
    RawTcp,
    Resource,
}

/// Which lease a connection rides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnClass {
    /// Standard, non-secret traffic: no revocable lease, survives a disconnected control plane.
    Public,
    /// Restricted egress: closed when the lease lapses.
    Restricted,
    /// Carries brokered credentials: closed when the lease lapses.
    Brokered,
}

#[derive(Clone, Debug)]
pub(crate) struct ConnTags {
    pub(crate) kind: ConnKind,
    /// The hostname the connection was admitted for (the resource name for resources).
    pub(crate) host: Option<String>,
    /// The destination port (the guest-side port for resources).
    pub(crate) port: u16,
    /// The validated destination address, when known at admission.
    pub(crate) ip: Option<IpAddr>,
    /// Admitted as a mirror, whose private address is allowed only while the mirror is.
    pub(crate) mirror: bool,
    pub(crate) class: ConnClass,
    /// For inspected connections: the brokered secrets bound to the host at admission.
    pub(crate) secret_ids: Vec<String>,
}

impl ConnTags {
    pub(crate) fn new(policy: &Policy, kind: ConnKind, host: Option<String>, port: u16) -> Self {
        let secret_ids = match (&host, kind) {
            (Some(host), ConnKind::Mitm) => policy.secret_ids_for(host),
            _ => Vec::new(),
        };
        let mut tags = Self {
            kind,
            host,
            port,
            ip: None,
            mirror: false,
            class: ConnClass::Public,
            secret_ids,
        };
        tags.class = class_for(policy, &tags);
        tags
    }
}

pub(crate) fn class_for(policy: &Policy, tags: &ConnTags) -> ConnClass {
    if tags.kind == ConnKind::Mitm && !tags.secret_ids.is_empty() {
        ConnClass::Brokered
    } else if policy.mode == Mode::Restricted {
        ConnClass::Restricted
    } else {
        ConnClass::Public
    }
}

/// Whether a live connection admitted with `tags` is still allowed under `policy`.
pub(crate) fn still_permitted(policy: &Policy, tags: &ConnTags) -> bool {
    if tags.host.as_deref().is_some_and(|h| policy.host_denied(h)) {
        return false;
    }
    let current_ids = match (&tags.host, tags.kind) {
        (Some(host), ConnKind::Mitm) => policy.secret_ids_for(host),
        _ => Vec::new(),
    };
    if current_ids != tags.secret_ids {
        return false;
    }
    let reclassified = ConnTags {
        secret_ids: current_ids,
        ..tags.clone()
    };
    if class_for(policy, &reclassified) != tags.class {
        return false;
    }
    if tags.mirror {
        let Some(host) = &tags.host else {
            return false;
        };
        if policy.mirror_for(host, tags.port).is_none() {
            return false;
        }
    } else if tags.kind != ConnKind::Resource
        && let Some(ip) = tags.ip
        && policy.addresses.verdict(ip).is_err()
    {
        return false;
    }
    let restricted = policy.mode == Mode::Restricted;
    match tags.kind {
        ConnKind::Mitm => tags.host.as_deref().is_some_and(|host| {
            policy.inspects_on(host, tags.port)
                && (!restricted || policy.restricted_allows(host, tags.port))
        }),
        ConnKind::PlainHttp | ConnKind::Passthrough | ConnKind::RawTcp => {
            !restricted
                || tags
                    .host
                    .as_deref()
                    .is_some_and(|host| policy.restricted_allows(host, tags.port))
        }
        ConnKind::Resource => tags
            .host
            .as_deref()
            .and_then(|name| policy.resource_named(name))
            .is_some_and(|r| r.port == tags.port),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Denial {
    NotInitialized,
    LeaseExpired,
    Revoked,
}

impl Denial {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "not_initialized",
            Self::LeaseExpired => "lease_expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StateError {
    #[error("the proxy has no policy yet")]
    NotInitialized,
    #[error("revocationWatermark {requested} is behind the current {current}")]
    WatermarkRollback { requested: u64, current: u64 },
    #[error("{0} connection(s) did not confirm closing")]
    CloseTimeout(usize),
}

struct ConnEntry {
    tags: ConnTags,
    cancel: CancellationToken,
    done: watch::Receiver<()>,
}

/// What revocations at the current watermark removed, so a policy re-sent at that same watermark
/// (a retry, or one computed before the revoke) cannot bring any of it back.
#[derive(Default)]
struct Tombstones {
    watermark: u64,
    all: bool,
    hosts: std::collections::BTreeSet<String>,
    secret_ids: std::collections::BTreeSet<String>,
    inspection_ports: std::collections::BTreeSet<u16>,
}

impl Tombstones {
    fn advance_to(&mut self, watermark: u64) {
        if watermark > self.watermark {
            *self = Self {
                watermark,
                ..Self::default()
            };
        }
    }

    fn apply(&self, policy: &mut Policy) {
        if self.all {
            policy.revoke_all();
        }
        for id in &self.secret_ids {
            policy.revoke_secret(id);
        }
        for host in &self.hosts {
            policy.revoke_host(host);
        }
        policy
            .revoked_inspection_ports
            .extend(self.inspection_ports.iter().copied());
    }

    /// Record everything `policy` has revoked: its own tombstones and any applied to it.
    fn absorb(&mut self, policy: &Policy) {
        self.hosts.extend(policy.denied_hosts.iter().cloned());
        self.secret_ids
            .extend(policy.revoked_secret_ids.iter().cloned());
        self.inspection_ports
            .extend(policy.revoked_inspection_ports.iter().copied());
    }
}

struct Inner {
    policy: Option<Arc<Policy>>,
    watermark: u64,
    /// A heartbeat named a watermark the proxy has not seen the revocations for.
    resync_required: bool,
    lease_deadline: Instant,
    lease_expired: bool,
    conns: HashMap<u64, ConnEntry>,
    tombstones: Tombstones,
}

impl Inner {
    fn lease_ok(&self, now: Instant) -> bool {
        !self.resync_required && !self.lease_expired && now < self.lease_deadline
    }

    fn take_matching(&self, mut pred: impl FnMut(&ConnTags) -> bool) -> Vec<Closing> {
        self.conns
            .values()
            .filter(|entry| pred(&entry.tags))
            .map(|entry| Closing {
                cancel: entry.cancel.clone(),
                done: entry.done.clone(),
            })
            .collect()
    }
}

pub(crate) struct Closing {
    cancel: CancellationToken,
    done: watch::Receiver<()>,
}

/// A consistent view for one decision.
pub(crate) struct Snapshot {
    pub(crate) policy: Arc<Policy>,
    pub(crate) lease_ok: bool,
}

pub(crate) struct Shared {
    inner: Mutex<Inner>,
    next_id: AtomicU64,
    pub(crate) events: EventHub,
    pub(crate) resolver: Resolver,
    pub(crate) upstream_tls: Arc<ClientConfig>,
    pub(crate) upstream_roots: Arc<RootCertStore>,
    pub(crate) connect_timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevokeRequest {
    pub(crate) revocation_watermark: u64,
    #[serde(default)]
    pub(crate) revoke_secret_ids: Vec<String>,
    #[serde(default)]
    pub(crate) revoke_hosts: Vec<String>,
    #[serde(default)]
    pub(crate) revoke_all: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeartbeatRequest {
    /// Required: a heartbeat that cannot say which revocations Sealant holds renews nothing.
    pub(crate) revocation_watermark: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Health {
    pub(crate) initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_hash: Option<String>,
    pub(crate) revocation_watermark: u64,
    pub(crate) active_connections: usize,
    pub(crate) lease_remaining_ms: u64,
    pub(crate) lease_expired: bool,
    pub(crate) resync_required: bool,
}

impl Shared {
    pub(crate) fn new(
        resolver: Resolver,
        upstream_tls: Arc<ClientConfig>,
        upstream_roots: Arc<RootCertStore>,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                policy: None,
                watermark: 0,
                resync_required: false,
                lease_deadline: Instant::now(),
                lease_expired: true,
                conns: HashMap::new(),
                tombstones: Tombstones::default(),
            }),
            next_id: AtomicU64::new(1),
            events: EventHub::new(),
            resolver,
            upstream_tls,
            upstream_roots,
            connect_timeout,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        let inner = self.lock();
        let policy = inner.policy.clone()?;
        Some(Snapshot {
            policy,
            lease_ok: inner.lease_ok(Instant::now()),
        })
    }

    /// The policy a new document should be validated against (for CA reuse).
    pub(crate) fn current_policy(&self) -> Option<Arc<Policy>> {
        self.lock().policy.clone()
    }

    /// Register a connection, rechecking it against the current policy under the lock.
    pub(crate) fn admit(self: &Arc<Self>, tags: ConnTags) -> Result<ConnGuard, Denial> {
        let mut inner = self.lock();
        let Some(policy) = inner.policy.clone() else {
            return Err(Denial::NotInitialized);
        };
        if tags.class != ConnClass::Public && !inner.lease_ok(Instant::now()) {
            return Err(Denial::LeaseExpired);
        }
        if !still_permitted(&policy, &tags) {
            return Err(Denial::Revoked);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        let (done_tx, done_rx) = watch::channel(());
        inner.conns.insert(
            id,
            ConnEntry {
                tags,
                cancel: cancel.clone(),
                done: done_rx,
            },
        );
        Ok(ConnGuard {
            shared: self.clone(),
            id,
            cancel,
            _done: done_tx,
        })
    }

    pub(crate) async fn apply_policy(&self, mut policy: Policy) -> Result<usize, StateError> {
        let closing = {
            let mut inner = self.lock();
            if policy.revocation_watermark < inner.watermark {
                return Err(StateError::WatermarkRollback {
                    requested: policy.revocation_watermark,
                    current: inner.watermark,
                });
            }
            // A later watermark is Sealant's authoritative state, durable tombstones included
            // (`revokedHosts`, `revokedSecretIds`). The same watermark keeps what was revoked at it.
            inner.tombstones.advance_to(policy.revocation_watermark);
            // Tombstones a policy carries (`revokedHosts`, `revokedSecretIds`) join the ones held at
            // its watermark, so a retry at that watermark that omits them cannot undo them.
            if inner.tombstones.watermark == policy.revocation_watermark {
                inner.tombstones.apply(&mut policy);
                inner.tombstones.absorb(&policy);
            }
            inner.watermark = policy.revocation_watermark;
            inner.resync_required = false;
            inner.lease_deadline = Instant::now() + policy.lease_ttl;
            inner.lease_expired = false;
            let closing = inner.take_matching(|tags| !still_permitted(&policy, tags));
            self.events.emit(Event {
                policy_hash: Some(policy.policy_hash.clone()),
                revocation_watermark: Some(policy.revocation_watermark),
                reason: Some(policy.mode.as_str().to_string()),
                closed: Some(closing.len()),
                ..Event::new("policy_loaded")
            });
            inner.policy = Some(Arc::new(policy));
            closing
        };
        close_all(closing).await
    }

    pub(crate) async fn revoke(&self, request: RevokeRequest) -> Result<usize, StateError> {
        let closing = {
            let mut inner = self.lock();
            let Some(current) = inner.policy.clone() else {
                return Err(StateError::NotInitialized);
            };
            if request.revocation_watermark < inner.watermark {
                return Err(StateError::WatermarkRollback {
                    requested: request.revocation_watermark,
                    current: inner.watermark,
                });
            }
            let mut policy = (*current).clone();
            inner.tombstones.advance_to(request.revocation_watermark);
            inner.tombstones.all |= request.revoke_all;
            inner.tombstones.secret_ids.extend(
                request
                    .revoke_secret_ids
                    .iter()
                    .map(|id| id.trim().to_string()),
            );
            if request.revoke_all {
                policy.revoke_all();
            }
            for id in &request.revoke_secret_ids {
                policy.revoke_secret(id.trim());
            }
            for host in &request.revoke_hosts {
                let host = normalize_host(host).unwrap_or_else(|| host.trim().to_ascii_lowercase());
                policy.revoke_host(&host);
                inner.tombstones.hosts.insert(host);
            }
            policy.revocation_watermark = request.revocation_watermark;
            inner.tombstones.absorb(&policy);
            inner.watermark = request.revocation_watermark;
            let closing = inner.take_matching(|tags| {
                (request.revoke_all && tags.class != ConnClass::Public)
                    || !still_permitted(&policy, tags)
            });
            self.events.emit(Event {
                revocation_watermark: Some(request.revocation_watermark),
                secret_ids: request.revoke_secret_ids.clone(),
                host: (!request.revoke_hosts.is_empty()).then(|| request.revoke_hosts.join(",")),
                reason: request.revoke_all.then(|| "revoke_all".to_string()),
                closed: Some(closing.len()),
                ..Event::new("revoked")
            });
            inner.policy = Some(Arc::new(policy));
            closing
        };
        close_all(closing).await
    }

    /// Renew the lease. A watermark ahead of the proxy's means revocations it has not been
    /// given: it advances, and lease-bound traffic stays closed until a policy at that watermark.
    pub(crate) async fn heartbeat(&self, request: HeartbeatRequest) -> Result<bool, StateError> {
        let (closing, resync) = {
            let mut inner = self.lock();
            let Some(policy) = inner.policy.clone() else {
                return Err(StateError::NotInitialized);
            };
            let mut closing = Vec::new();
            let watermark = request.revocation_watermark;
            if watermark < inner.watermark {
                return Err(StateError::WatermarkRollback {
                    requested: watermark,
                    current: inner.watermark,
                });
            }
            if watermark > inner.watermark {
                inner.watermark = watermark;
                inner.resync_required = true;
                closing = inner.take_matching(|tags| tags.class != ConnClass::Public);
                self.events.emit(Event {
                    revocation_watermark: Some(watermark),
                    closed: Some(closing.len()),
                    ..Event::new("resync_required")
                });
            }
            inner.lease_deadline = Instant::now() + policy.lease_ttl;
            inner.lease_expired = false;
            (closing, inner.resync_required)
        };
        close_all(closing).await?;
        Ok(resync)
    }

    /// Close lease-bound connections once the lease lapses. Returns how many were closed, once.
    pub(crate) async fn expire_lease_if_due(&self) -> Option<usize> {
        let closing = {
            let mut inner = self.lock();
            if inner.policy.is_none()
                || inner.lease_expired
                || Instant::now() < inner.lease_deadline
            {
                return None;
            }
            inner.lease_expired = true;
            inner.take_matching(|tags| tags.class != ConnClass::Public)
        };
        let count = closing.len();
        self.events.emit(Event {
            closed: Some(count),
            ..Event::new("lease_expired")
        });
        let _ = close_all(closing).await;
        Some(count)
    }

    pub(crate) fn health(&self) -> Health {
        let inner = self.lock();
        let now = Instant::now();
        let remaining = if inner.lease_ok(now) {
            inner.lease_deadline.saturating_duration_since(now)
        } else {
            Duration::ZERO
        };
        Health {
            initialized: inner.policy.is_some(),
            mode: inner.policy.as_ref().map(|p| p.mode.as_str()),
            policy_hash: inner.policy.as_ref().map(|p| p.policy_hash.clone()),
            revocation_watermark: inner.watermark,
            active_connections: inner.conns.len(),
            lease_remaining_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
            lease_expired: inner.policy.is_some() && !inner.lease_ok(now),
            resync_required: inner.resync_required,
        }
    }

    fn release(&self, id: u64) {
        self.lock().conns.remove(&id);
    }
}

/// Cancel every connection and wait until each has dropped its sockets.
async fn close_all(closing: Vec<Closing>) -> Result<usize, StateError> {
    let count = closing.len();
    for c in &closing {
        c.cancel.cancel();
    }
    let waits = closing.into_iter().map(|mut c| async move {
        // `changed` errors once the connection's guard, and with it its sockets, is dropped.
        while c.done.changed().await.is_ok() {}
    });
    let all = futures_join_all(waits);
    match tokio::time::timeout(CLOSE_CONFIRM_TIMEOUT, all).await {
        Ok(()) => Ok(count),
        Err(_) => Err(StateError::CloseTimeout(count)),
    }
}

async fn futures_join_all<F: Future<Output = ()>>(futures: impl IntoIterator<Item = F>) {
    let mut set = Vec::new();
    for f in futures {
        set.push(Box::pin(f));
    }
    for f in set {
        f.await;
    }
}

/// A registered connection. Dropping it removes the registration and confirms the close.
pub(crate) struct ConnGuard {
    shared: Arc<Shared>,
    id: u64,
    cancel: CancellationToken,
    _done: watch::Sender<()>,
}

impl ConnGuard {
    /// Run `work` (which owns the connection's sockets) until it ends or the connection is
    /// cancelled; either way the sockets are dropped before the guard confirms the close.
    pub(crate) async fn run<F: Future<Output = ()>>(self, work: F) {
        let cancel = self.cancel.clone();
        tokio::select! {
            biased;
            () = cancel.cancelled() => {}
            () = work => {}
        }
        drop(self);
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.shared.release(self.id);
    }
}
