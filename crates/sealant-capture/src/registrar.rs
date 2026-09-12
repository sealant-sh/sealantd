//! `Registrar`: the session-channel calls, each carrying the epoch (ADR-0015 amendment decision
//! 9). The wire shape is provisional until Mend's ADR-0002 lands, so the HTTP adapter and every
//! request/response type live in this one module; the in-memory double is what tests use.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;

/// `plan.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanGetRequest {
    /// Worktree.
    pub worktree_id: String,
    /// Caller's epoch.
    pub epoch: u64,
}

/// The chain head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadInfo {
    /// Position.
    pub n: u64,
    /// Capture id.
    pub capture_id: String,
    /// Manifest key.
    pub manifest_key: String,
    /// The manifest.
    pub manifest: Manifest,
}

/// `plan.get` response: the head to materialize and GET URLs for what it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanGetResponse {
    /// Head, or none for an empty chain.
    pub head: Option<HeadInfo>,
    /// Key → presigned GET URL (empty when the sink is a directory).
    #[serde(default)]
    pub get_urls: BTreeMap<String, String>,
}

/// `upload.urls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadUrlsRequest {
    /// Worktree.
    pub worktree_id: String,
    /// Caller's epoch.
    pub epoch: u64,
    /// Keys under the caller's epoch prefix.
    pub keys: Vec<String>,
}

/// `upload.urls` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadUrlsResponse {
    /// Key → presigned PUT URL.
    pub urls: BTreeMap<String, String>,
}

/// `capture.register`: the compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Worktree.
    pub worktree_id: String,
    /// Caller's epoch.
    pub epoch: u64,
    /// Position.
    pub n: u64,
    /// Expected parent (the current head), or none for an empty chain.
    pub parent: Option<String>,
    /// Capture id.
    pub capture_id: String,
    /// Manifest key.
    pub manifest_key: String,
    /// The manifest.
    pub manifest: Manifest,
}

/// `capture.register` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Head position after the call.
    pub head_n: u64,
    /// Head capture id after the call.
    pub head_capture_id: String,
}

/// `lease.heartbeat`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// Worktree.
    pub worktree_id: String,
    /// Caller's epoch.
    pub epoch: u64,
}

/// `lease.heartbeat` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// Seconds until the lease expires without another heartbeat.
    pub expires_in_secs: u64,
}

/// `change.summary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSummaryRequest {
    /// Worktree.
    pub worktree_id: String,
    /// Caller's epoch.
    pub epoch: u64,
    /// The checkpoint capture the summary belongs to (must be the chain head).
    pub capture_id: String,
    /// The summary (numstat, name-status, patches), shape owned by Mend.
    pub summary: serde_json::Value,
}

/// Registrar errors.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RegistrarError {
    /// 409 on a stale epoch: stop shipping, pause the agent.
    #[error("epoch {epoch} is stale (live epoch {live})")]
    Fenced {
        /// The caller's epoch.
        epoch: u64,
        /// The live epoch.
        live: u64,
    },
    /// 409 on a wrong parent.
    #[error("wrong parent: chain head is n={head_n} {head_capture_id}")]
    WrongParent {
        /// Head position.
        head_n: u64,
        /// Head capture id.
        head_capture_id: String,
    },
    /// Heartbeat found no lease row.
    #[error("lease lost")]
    LeaseLost,
    /// Summary refused (capture is not the head).
    #[error("summary refused: {0}")]
    SummaryRefused(String),
    /// Transport failure (retryable).
    #[error("transport: {0}")]
    Transport(String),
    /// Unexpected answer.
    #[error("protocol: {0}")]
    Protocol(String),
}

impl RegistrarError {
    /// Whether a retry can help.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport(_))
    }
}

/// The session-channel port.
pub trait Registrar: Send + Sync {
    /// Head manifest and GET URLs for materialize.
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError>;
    /// PUT URLs for a key list (minted only while the lease predicate holds).
    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError>;
    /// The CAS. A register that reports the chain already at `n` with the same capture id is a
    /// lost ack, not a conflict.
    fn capture_register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegistrarError>;
    /// Zero rows = lost.
    fn lease_heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError>;
    /// Accepted only against the chain head.
    fn change_summary(&self, req: &ChangeSummaryRequest) -> Result<(), RegistrarError>;
}

#[derive(Debug, Default)]
struct InMemoryState {
    live_epoch: u64,
    chain: Vec<HeadInfo>,
    lease_alive: bool,
    summaries: Vec<ChangeSummaryRequest>,
    url_requests: u64,
}

/// In-memory registrar: one worktree, one chain, a live epoch, a lease flag.
#[derive(Debug)]
pub struct InMemoryRegistrar {
    state: Mutex<InMemoryState>,
    url_base: Option<String>,
}

impl InMemoryRegistrar {
    /// A registrar whose live epoch is `epoch`. With `url_base`, URLs are `<base>/<key>`.
    #[must_use]
    pub fn new(epoch: u64, url_base: Option<String>) -> Self {
        Self {
            state: Mutex::new(InMemoryState {
                live_epoch: epoch,
                chain: Vec::new(),
                lease_alive: true,
                summaries: Vec::new(),
                url_requests: 0,
            }),
            url_base,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, InMemoryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fence: bump the live epoch (a replacement executor claimed the worktree).
    pub fn set_live_epoch(&self, epoch: u64) {
        self.lock().live_epoch = epoch;
    }

    /// Whether heartbeats find a lease.
    pub fn set_lease_alive(&self, alive: bool) {
        self.lock().lease_alive = alive;
    }

    /// The chain.
    #[must_use]
    pub fn chain(&self) -> Vec<HeadInfo> {
        self.lock().chain.clone()
    }

    /// Head.
    #[must_use]
    pub fn head(&self) -> Option<HeadInfo> {
        self.lock().chain.last().cloned()
    }

    /// Summaries accepted.
    #[must_use]
    pub fn summaries(&self) -> Vec<ChangeSummaryRequest> {
        self.lock().summaries.clone()
    }

    /// `upload.urls` calls made.
    #[must_use]
    pub fn url_requests(&self) -> u64 {
        self.lock().url_requests
    }

    fn check_epoch(state: &InMemoryState, epoch: u64) -> Result<(), RegistrarError> {
        if epoch != state.live_epoch {
            return Err(RegistrarError::Fenced {
                epoch,
                live: state.live_epoch,
            });
        }
        Ok(())
    }

    fn url(&self, key: &str) -> String {
        match &self.url_base {
            Some(b) => format!("{}/{key}", b.trim_end_matches('/')),
            None => String::new(),
        }
    }
}

impl Registrar for InMemoryRegistrar {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        let state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        let head = state.chain.last().cloned();
        let mut get_urls = BTreeMap::new();
        if let (Some(h), Some(_)) = (&head, &self.url_base) {
            let s = &h.manifest.sections;
            let bulk_packs: Vec<String> = s
                .bulk
                .section()
                .map(|b| b.packs.clone())
                .unwrap_or_default();
            let keys = s
                .git
                .packs
                .iter()
                .flat_map(|k| [k.clone(), format!("{k}.idx")])
                .chain(s.workspace.packs.iter().cloned())
                .chain(bulk_packs)
                .chain([h.manifest_key.clone()]);
            for k in keys {
                get_urls.insert(k.clone(), self.url(&k));
            }
        }
        Ok(PlanGetResponse { head, get_urls })
    }

    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        let mut state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        if !state.lease_alive {
            return Err(RegistrarError::LeaseLost);
        }
        state.url_requests += 1;
        let prefix = format!("captures/{}/{}/", req.worktree_id, req.epoch);
        let urls = req
            .keys
            .iter()
            .filter(|k| k.starts_with(&prefix))
            .map(|k| (k.clone(), self.url(k)))
            .collect();
        Ok(UploadUrlsResponse { urls })
    }

    fn capture_register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegistrarError> {
        let mut state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        let head = state.chain.last();
        // Lost ack: the chain is already at n with this id.
        if let Some(h) = head
            && h.n == req.n
            && h.capture_id == req.capture_id
        {
            return Ok(RegisterResponse {
                head_n: h.n,
                head_capture_id: h.capture_id.clone(),
            });
        }
        let head_id = head.map(|h| h.capture_id.clone());
        let expected_n = head.map_or(0, |h| h.n + 1);
        if head_id != req.parent || req.n != expected_n {
            return Err(RegistrarError::WrongParent {
                head_n: head.map_or(0, |h| h.n),
                head_capture_id: head_id.unwrap_or_default(),
            });
        }
        state.chain.push(HeadInfo {
            n: req.n,
            capture_id: req.capture_id.clone(),
            manifest_key: req.manifest_key.clone(),
            manifest: req.manifest.clone(),
        });
        Ok(RegisterResponse {
            head_n: req.n,
            head_capture_id: req.capture_id.clone(),
        })
    }

    fn lease_heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError> {
        let state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        if !state.lease_alive {
            return Err(RegistrarError::LeaseLost);
        }
        Ok(HeartbeatResponse {
            expires_in_secs: 30,
        })
    }

    fn change_summary(&self, req: &ChangeSummaryRequest) -> Result<(), RegistrarError> {
        let mut state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        match state.chain.last() {
            Some(h) if h.capture_id == req.capture_id => {
                state.summaries.push(req.clone());
                Ok(())
            }
            _ => Err(RegistrarError::SummaryRefused(
                "capture is not the chain head".to_owned(),
            )),
        }
    }
}

/// HTTP registrar: `POST <endpoint>/<call>` with a bearer token and a JSON body. Provisional
/// wire shape (Mend ADR-0002 owns it).
pub struct HttpRegistrar {
    agent: ureq::Agent,
    endpoint: String,
    token: String,
}

impl std::fmt::Debug for HttpRegistrar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRegistrar")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct ConflictBody {
    #[serde(default)]
    reason: String,
    #[serde(default)]
    live_epoch: Option<u64>,
    #[serde(default)]
    head_n: Option<u64>,
    #[serde(default)]
    head_capture_id: Option<String>,
}

impl HttpRegistrar {
    /// `endpoint` is `SEALANT_CAPTURE_ENDPOINT`, `token` is `SEALANT_CAPTURE_TOKEN`.
    #[must_use]
    pub fn new(endpoint: &str, token: &str, timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
        }
    }

    fn call<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        name: &str,
        req: &Req,
        epoch: u64,
    ) -> Result<Resp, RegistrarError> {
        let body = serde_json::to_vec(req).map_err(|e| RegistrarError::Protocol(e.to_string()))?;
        let mut resp = self
            .agent
            .post(format!("{}/{name}", self.endpoint))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send(&body[..])
            .map_err(|e| RegistrarError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(64 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| RegistrarError::Transport(e.to_string()))?;
        match status {
            200..=299 => {
                serde_json::from_slice(&bytes).map_err(|e| RegistrarError::Protocol(e.to_string()))
            }
            409 => {
                let c: ConflictBody = serde_json::from_slice(&bytes).unwrap_or(ConflictBody {
                    reason: String::new(),
                    live_epoch: None,
                    head_n: None,
                    head_capture_id: None,
                });
                if let Some(live) = c.live_epoch.filter(|l| *l != epoch) {
                    Err(RegistrarError::Fenced { epoch, live })
                } else if c.reason == "stale-epoch" {
                    Err(RegistrarError::Fenced { epoch, live: 0 })
                } else if name == "change.summary" {
                    Err(RegistrarError::SummaryRefused(c.reason))
                } else {
                    Err(RegistrarError::WrongParent {
                        head_n: c.head_n.unwrap_or(0),
                        head_capture_id: c.head_capture_id.unwrap_or_default(),
                    })
                }
            }
            404 if name == "lease.heartbeat" => Err(RegistrarError::LeaseLost),
            s if s >= 500 || s == 429 || s == 408 => {
                Err(RegistrarError::Transport(format!("{name}: http {s}")))
            }
            s => Err(RegistrarError::Protocol(format!("{name}: http {s}"))),
        }
    }
}

impl Registrar for HttpRegistrar {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        self.call("plan.get", req, req.epoch)
    }

    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        self.call("upload.urls", req, req.epoch)
    }

    fn capture_register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegistrarError> {
        self.call("capture.register", req, req.epoch)
    }

    fn lease_heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError> {
        self.call("lease.heartbeat", req, req.epoch)
    }

    fn change_summary(&self, req: &ChangeSummaryRequest) -> Result<(), RegistrarError> {
        let _: serde_json::Value = self.call("change.summary", req, req.epoch)?;
        Ok(())
    }
}

/// A [`crate::sink::UrlMinter`] over a registrar: PUT URLs come from `upload.urls`, GET URLs
/// from the plan (with `upload.urls`-style fallback for keys the plan did not list).
#[derive(Debug)]
pub struct RegistrarMinter<R: Registrar> {
    registrar: std::sync::Arc<R>,
    worktree_id: String,
    epoch: u64,
    put_cache: Mutex<BTreeMap<String, String>>,
    get_urls: Mutex<BTreeMap<String, String>>,
}

impl<R: Registrar> RegistrarMinter<R> {
    /// Mint for `worktree_id` at `epoch`, seeded with the plan's GET URLs.
    #[must_use]
    pub fn new(
        registrar: std::sync::Arc<R>,
        worktree_id: &str,
        epoch: u64,
        get_urls: BTreeMap<String, String>,
    ) -> Self {
        Self {
            registrar,
            worktree_id: worktree_id.to_owned(),
            epoch,
            put_cache: Mutex::new(BTreeMap::new()),
            get_urls: Mutex::new(get_urls),
        }
    }

    /// Pre-mint PUT URLs for a batch of keys (one channel call).
    pub fn prefetch_put(&self, keys: &[String]) -> Result<(), RegistrarError> {
        let resp = self.registrar.upload_urls(&UploadUrlsRequest {
            worktree_id: self.worktree_id.clone(),
            epoch: self.epoch,
            keys: keys.to_vec(),
        })?;
        self.put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(resp.urls);
        Ok(())
    }
}

impl<R: Registrar> crate::sink::UrlMinter for RegistrarMinter<R> {
    fn put_url(&self, key: &str) -> Result<String, String> {
        if let Some(u) = self
            .put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key)
        {
            return Ok(u);
        }
        self.prefetch_put(&[key.to_owned()])
            .map_err(|e| e.to_string())?;
        self.put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key)
            .ok_or_else(|| format!("no PUT url minted for {key}"))
    }

    fn get_url(&self, key: &str) -> Result<String, String> {
        self.get_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
            .ok_or_else(|| format!("no GET url in plan for {key}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        BulkState, CaptureKind, FsckStatus, GitSection, Sections, WorkspaceSection,
    };

    fn manifest(n: u64, parent: Option<&str>) -> Manifest {
        Manifest {
            worktree_id: "wt".into(),
            n,
            parent: parent.map(str::to_owned),
            epoch: 1,
            seq: 0,
            kind: CaptureKind::Auto,
            created_at: "2026-09-12T00:00:00Z".into(),
            sections: Sections {
                git: GitSection {
                    packs: vec![],
                    refs: BTreeMap::new(),
                    head: "refs/heads/main".into(),
                    fsck: FsckStatus::Verified,
                },
                workspace: WorkspaceSection {
                    root: "r".into(),
                    packs: vec![],
                },
                bulk: BulkState::pending(),
            },
            checkpoint: None,
        }
    }

    fn register(n: u64, parent: Option<&str>, id: &str, epoch: u64) -> RegisterRequest {
        RegisterRequest {
            worktree_id: "wt".into(),
            epoch,
            n,
            parent: parent.map(str::to_owned),
            capture_id: id.into(),
            manifest_key: format!("captures/wt/1/manifests/{id}"),
            manifest: manifest(n, parent),
        }
    }

    #[test]
    fn cas_lost_ack_wrong_parent_and_fence() {
        let r = InMemoryRegistrar::new(1, None);
        r.capture_register(&register(0, None, "a", 1)).unwrap();
        // Lost ack: same n and id is fine.
        r.capture_register(&register(0, None, "a", 1)).unwrap();
        assert!(matches!(
            r.capture_register(&register(1, None, "b", 1)),
            Err(RegistrarError::WrongParent { .. })
        ));
        r.capture_register(&register(1, Some("a"), "b", 1)).unwrap();
        assert_eq!(r.head().unwrap().capture_id, "b");
        r.set_live_epoch(2);
        assert!(matches!(
            r.capture_register(&register(2, Some("b"), "c", 1)),
            Err(RegistrarError::Fenced { epoch: 1, live: 2 })
        ));
        assert!(matches!(
            r.lease_heartbeat(&HeartbeatRequest {
                worktree_id: "wt".into(),
                epoch: 1
            }),
            Err(RegistrarError::Fenced { .. })
        ));
    }

    #[test]
    fn urls_only_under_own_prefix_and_summary_only_on_head() {
        let r = InMemoryRegistrar::new(1, Some("http://x".into()));
        let resp = r
            .upload_urls(&UploadUrlsRequest {
                worktree_id: "wt".into(),
                epoch: 1,
                keys: vec![
                    "captures/wt/1/packs/a".into(),
                    "captures/wt/0/packs/b".into(),
                    "projects/p/x".into(),
                ],
            })
            .unwrap();
        assert_eq!(resp.urls.len(), 1);
        assert_eq!(
            resp.urls["captures/wt/1/packs/a"],
            "http://x/captures/wt/1/packs/a"
        );
        r.capture_register(&register(0, None, "a", 1)).unwrap();
        let summary = |id: &str| ChangeSummaryRequest {
            worktree_id: "wt".into(),
            epoch: 1,
            capture_id: id.into(),
            summary: serde_json::json!({}),
        };
        assert!(r.change_summary(&summary("zzz")).is_err());
        r.change_summary(&summary("a")).unwrap();
        assert_eq!(r.summaries().len(), 1);
        let plan = r
            .plan_get(&PlanGetRequest {
                worktree_id: "wt".into(),
                epoch: 1,
            })
            .unwrap();
        assert_eq!(plan.head.unwrap().capture_id, "a");
    }
}
