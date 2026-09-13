//! `Registrar`: the session-channel calls, each carrying the epoch (ADR-0015 amendment decision
//! 9). The wire shape is provisional until Mend's ADR-0002 lands, so the HTTP adapter and every
//! request/response type live in this one module; the in-memory double is what tests use.
//!
//! # Multipart wire extension
//!
//! Large objects (git packs above 64 MiB; any pack at or above the shipper's threshold, default
//! 16 MiB) are uploaded as S3-style multipart uploads without the executor ever holding bucket
//! credentials: the registrar performs `CreateMultipartUpload` and `CompleteMultipartUpload`
//! server-side, the executor only PUTs parts to presigned part URLs and reports their ETags.
//!
//! `upload.urls` request gains an optional `sizes` map (key → bytes) for the keys the executor
//! would like as multipart; the response gains `multipart` (key → `{upload_id, part_size,
//! part_urls}`) for the keys the registrar chose to take that way — the object is cut into
//! `part_size`-byte parts (the last one shorter), part `i` (1-based) goes to `part_urls[i-1]`,
//! and `urls` omits such a key. A key listed in `sizes` but answered in `urls` is a single PUT
//! (below the registrar's threshold, or a store without multipart).
//!
//! ```json
//! → {"worktree_id":"wt","epoch":3,"keys":["captures/wt/3/packs/<sha>"],
//!    "sizes":{"captures/wt/3/packs/<sha>":150000000}}
//! ← {"urls":{},
//!    "multipart":{"captures/wt/3/packs/<sha>":{"upload_id":"…","part_size":16777216,
//!                 "part_urls":["https://…partNumber=1&uploadId=…","…"]}}}
//! ```
//!
//! `upload.complete` finishes one such upload; the registrar sends `If-None-Match: *` on the
//! complete (R2 and S3 both honour it) and answers 409 `{"reason":"exists"}` when the key is
//! already there — which the executor treats as an identical object already present, keys
//! being content-addressed. The response may carry the assembled object's `size`.
//!
//! ```json
//! → {"worktree_id":"wt","epoch":3,"key":"captures/wt/3/packs/<sha>","upload_id":"…",
//!    "parts":[{"part_number":1,"etag":"\"9b2c…\""},{"part_number":2,"etag":"\"…\""}]}
//! ← {"size":150000000}          |  409 {"reason":"exists"}
//! ```
//!
//! ETags travel verbatim as the store returned them (quotes included). Part URLs are minted
//! only while the lease predicate holds, like PUT URLs, and count against the same URL quota.
//! A multipart upload the executor abandons (it dies, or a part fails past its retries and the
//! object is retried under a fresh `upload_id`) is the registrar's to expire: a bucket lifecycle
//! rule for incomplete multipart uploads, no `upload.abort` call in v1.
//!
//! # `platform` on `plan.get`
//!
//! The request names the executor's `<os>-<arch>-<libc>` (the key the bulk class stamps on its
//! captures, `engine::default_platform`). A registrar answers the head's bulk section as
//! `"pending"` when it was captured for another platform — the executor must not restore a
//! dependency tree built elsewhere; the install runs on the control plane's side instead — and
//! leaves the plan unchanged when the field is absent (an older executor) or the platforms
//! match. The materializer treats `"pending"` as "nothing to restore, nothing to sweep".
//!
//! ```json
//! → {"worktree_id":"wt","epoch":0,"platform":"linux-x86_64-gnu"}
//! ← {"worktree_id":"wt","epoch":3,"head":{"n":7,"capture_id":"…","manifest_key":"…",
//!    "manifest":{…,"sections":{…,"bulk":"pending"}}},"get_urls":{…}}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::{BulkState, Manifest};

/// `plan.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanGetRequest {
    /// Worktree, when the executor knows it (`SEALANT_CAPTURE_WORKTREE_ID`); otherwise the
    /// session token identifies it and the response says which.
    pub worktree_id: Option<String>,
    /// Caller's epoch; 0 = not claimed yet (the plan of a booting executor claims the lease).
    pub epoch: u64,
    /// The executor's `<os>-<arch>-<libc>`: the registrar answers the bulk section as
    /// `"pending"` when the head's was captured for another platform. Absent = the head as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

impl PlanGetRequest {
    /// The request a booting executor sends: `epoch` 0 and this build's platform.
    #[must_use]
    pub fn booting(worktree_id: Option<String>) -> Self {
        Self {
            worktree_id,
            epoch: 0,
            platform: Some(crate::engine::default_platform()),
        }
    }
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
    /// The worktree the session token is scoped to.
    pub worktree_id: String,
    /// The lease epoch this session holds (Mend claims the lease at launch; the executor learns
    /// its epoch here and carries it on every later call).
    pub epoch: u64,
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
    /// Sizes of the keys the caller would upload as multipart (a subset of `keys`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sizes: BTreeMap<String, u64>,
}

impl UploadUrlsRequest {
    /// Single-PUT URLs for `keys`.
    #[must_use]
    pub fn new(worktree_id: &str, epoch: u64, keys: Vec<String>) -> Self {
        Self {
            worktree_id: worktree_id.to_owned(),
            epoch,
            keys,
            sizes: BTreeMap::new(),
        }
    }
}

/// One multipart upload the registrar created for a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartUrls {
    /// The store's upload id; echoed on `upload.complete`.
    pub upload_id: String,
    /// Bytes per part (the last part is shorter).
    pub part_size: u64,
    /// One presigned `UploadPart` URL per part, in part-number order.
    pub part_urls: Vec<String>,
}

/// `upload.urls` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadUrlsResponse {
    /// Key → presigned PUT URL.
    pub urls: BTreeMap<String, String>,
    /// Key → multipart upload, for keys the registrar takes as multipart (absent from `urls`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub multipart: BTreeMap<String, MultipartUrls>,
}

/// One uploaded part, as reported on `upload.complete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedPart {
    /// 1-based part number.
    pub part_number: u32,
    /// The ETag the store answered the part PUT with, verbatim.
    pub etag: String,
}

/// `upload.complete`: the registrar's server-side `CompleteMultipartUpload` with
/// `If-None-Match: *`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadCompleteRequest {
    /// Worktree.
    pub worktree_id: String,
    /// Caller's epoch.
    pub epoch: u64,
    /// Key.
    pub key: String,
    /// The upload id from `upload.urls`.
    pub upload_id: String,
    /// Every part, in part-number order.
    pub parts: Vec<CompletedPart>,
}

/// `upload.complete` response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadCompleteResponse {
    /// Size of the assembled object, when the registrar reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
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
    /// 409 `exists` on `upload.complete`: the key already holds an object.
    #[error("key exists: {key}")]
    KeyExists {
        /// Key.
        key: String,
    },
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
    /// Complete a multipart upload write-once; [`RegistrarError::KeyExists`] when the key is
    /// already there.
    fn upload_complete(
        &self,
        req: &UploadCompleteRequest,
    ) -> Result<UploadCompleteResponse, RegistrarError>;
    /// The CAS. A register that reports the chain already at `n` with the same capture id is a
    /// lost ack, not a conflict.
    fn capture_register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegistrarError>;
    /// Zero rows = lost.
    fn lease_heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError>;
    /// Accepted only against the chain head.
    fn change_summary(&self, req: &ChangeSummaryRequest) -> Result<(), RegistrarError>;
}

/// How the in-memory registrar answers `sizes`: a key of at least `threshold` bytes is created
/// as a multipart upload cut at `part_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartPolicy {
    /// Smallest size taken as multipart.
    pub threshold: u64,
    /// Bytes per part.
    pub part_size: u64,
}

/// Why a completer refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteRefusal {
    /// The key already holds an object (the store's 412 on `If-None-Match: *`).
    Exists,
    /// The parts do not assemble (unknown ETag, missing part).
    BadParts(String),
}

/// What the in-memory registrar's `upload.complete` drives: the stand-in for the bucket's
/// `CompleteMultipartUpload`. Tests plug the object server in; the default remembers keys.
pub trait MultipartCompleter: Send + Sync {
    /// Assemble `parts` at `key`; the assembled size when known.
    fn complete(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<Option<u64>, CompleteRefusal>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingUpload {
    key: String,
    parts: u32,
}

#[derive(Debug, Default)]
struct InMemoryState {
    live_epoch: u64,
    chain: Vec<HeadInfo>,
    lease_alive: bool,
    summaries: Vec<ChangeSummaryRequest>,
    url_requests: u64,
    uploads: BTreeMap<String, PendingUpload>,
    /// Keys completed through this registrar (the default existence check).
    completed: BTreeSet<String>,
    completes: u64,
    next_upload: u64,
}

/// In-memory registrar: one worktree, one chain, a live epoch, a lease flag.
pub struct InMemoryRegistrar {
    state: Mutex<InMemoryState>,
    worktree_id: Mutex<String>,
    url_base: Option<String>,
    multipart: Option<MultipartPolicy>,
    completer: Option<Arc<dyn MultipartCompleter>>,
}

impl std::fmt::Debug for InMemoryRegistrar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryRegistrar")
            .field("worktree_id", &self.worktree_id())
            .field("url_base", &self.url_base)
            .field("multipart", &self.multipart)
            .finish_non_exhaustive()
    }
}

impl InMemoryRegistrar {
    /// A registrar for `worktree_id` whose live epoch is `epoch`. With `url_base`, URLs are
    /// `<base>/<key>`.
    #[must_use]
    pub fn new(worktree_id: &str, epoch: u64, url_base: Option<String>) -> Self {
        Self {
            worktree_id: Mutex::new(worktree_id.to_owned()),
            state: Mutex::new(InMemoryState {
                live_epoch: epoch,
                chain: Vec::new(),
                lease_alive: true,
                summaries: Vec::new(),
                url_requests: 0,
                uploads: BTreeMap::new(),
                completed: BTreeSet::new(),
                completes: 0,
                next_upload: 0,
            }),
            url_base,
            multipart: None,
            completer: None,
        }
    }

    /// Take keys of at least `policy.threshold` bytes as multipart (needs a `url_base`); the
    /// `completer` stands in for the bucket's complete, or keys are only remembered.
    #[must_use]
    pub fn with_multipart(
        mut self,
        policy: MultipartPolicy,
        completer: Option<Arc<dyn MultipartCompleter>>,
    ) -> Self {
        self.multipart = Some(policy);
        self.completer = completer;
        self
    }

    /// Pretend `key` already holds an object: the next complete of it answers `exists`.
    pub fn mark_existing(&self, key: &str) {
        self.lock().completed.insert(key.to_owned());
    }

    /// `upload.complete` calls that reached the store (completed or refused as existing).
    #[must_use]
    pub fn completes(&self) -> u64 {
        self.lock().completes
    }

    /// Multipart uploads created and not yet completed.
    #[must_use]
    pub fn open_uploads(&self) -> usize {
        self.lock().uploads.len()
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

    /// The worktree `plan.get` answers.
    #[must_use]
    pub fn worktree_id(&self) -> String {
        self.worktree_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Answer `plan.get` as `worktree_id` from now on: the standby's placeholder gave way to
    /// the worktree the control plane assigned (tests of `capture.replan`).
    pub fn set_worktree_id(&self, worktree_id: &str) {
        *self
            .worktree_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = worktree_id.to_owned();
    }

    /// Re-stamp the head's bulk section as captured for `platform` (tests of the `plan.get`
    /// platform rule); a head without a bulk section is left alone.
    pub fn set_bulk_platform(&self, platform: &str) {
        if let Some(head) = self.lock().chain.last_mut()
            && let BulkState::Ready(bulk) = &mut head.manifest.sections.bulk
        {
            bulk.platform = platform.to_owned();
        }
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
        if req.epoch != 0 {
            Self::check_epoch(&state, req.epoch)?;
        }
        let worktree_id = self.worktree_id();
        if req.worktree_id.as_ref().is_some_and(|w| *w != worktree_id) {
            return Err(RegistrarError::Protocol(
                "token is scoped to another worktree".into(),
            ));
        }
        let mut head = state.chain.last().cloned();
        // Another platform's dependency tree is not this executor's to restore.
        if let (Some(h), Some(platform)) = (head.as_mut(), &req.platform)
            && h.manifest
                .sections
                .bulk
                .section()
                .is_some_and(|b| b.platform != *platform)
        {
            h.manifest.sections.bulk = BulkState::pending();
        }
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
        Ok(PlanGetResponse {
            worktree_id,
            epoch: state.live_epoch,
            head,
            get_urls,
        })
    }

    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        let mut state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        if !state.lease_alive {
            return Err(RegistrarError::LeaseLost);
        }
        state.url_requests += 1;
        let prefix = format!("captures/{}/{}/", req.worktree_id, req.epoch);
        let mut urls = BTreeMap::new();
        let mut multipart = BTreeMap::new();
        for k in req.keys.iter().filter(|k| k.starts_with(&prefix)) {
            let policy = self
                .multipart
                .filter(|_| self.url_base.is_some())
                .zip(req.sizes.get(k).copied())
                .filter(|(p, size)| *size >= p.threshold && p.part_size > 0);
            match policy {
                Some((p, size)) => {
                    state.next_upload += 1;
                    let upload_id = format!("mpu-{}", state.next_upload);
                    let parts = size.div_ceil(p.part_size);
                    let part_urls = (1..=parts)
                        .map(|n| format!("{}?partNumber={n}&uploadId={upload_id}", self.url(k)))
                        .collect();
                    state.uploads.insert(
                        upload_id.clone(),
                        PendingUpload {
                            key: k.clone(),
                            parts: u32::try_from(parts).unwrap_or(u32::MAX),
                        },
                    );
                    multipart.insert(
                        k.clone(),
                        MultipartUrls {
                            upload_id,
                            part_size: p.part_size,
                            part_urls,
                        },
                    );
                }
                None => {
                    urls.insert(k.clone(), self.url(k));
                }
            }
        }
        Ok(UploadUrlsResponse { urls, multipart })
    }

    fn upload_complete(
        &self,
        req: &UploadCompleteRequest,
    ) -> Result<UploadCompleteResponse, RegistrarError> {
        let mut state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        if !state.lease_alive {
            return Err(RegistrarError::LeaseLost);
        }
        let Some(pending) = state.uploads.get(&req.upload_id).cloned() else {
            return Err(RegistrarError::Protocol(format!(
                "no such upload {}",
                req.upload_id
            )));
        };
        if pending.key != req.key {
            return Err(RegistrarError::Protocol(format!(
                "upload {} is for {}",
                req.upload_id, pending.key
            )));
        }
        let numbers: Vec<u32> = req.parts.iter().map(|p| p.part_number).collect();
        let expected: Vec<u32> = (1..=pending.parts).collect();
        if numbers != expected || req.parts.iter().any(|p| p.etag.is_empty()) {
            return Err(RegistrarError::Protocol(format!(
                "parts {numbers:?} do not complete {} parts",
                pending.parts
            )));
        }
        state.completes += 1;
        if state.completed.contains(&req.key) {
            state.uploads.remove(&req.upload_id);
            return Err(RegistrarError::KeyExists {
                key: req.key.clone(),
            });
        }
        let size = match &self.completer {
            Some(c) => match c.complete(&req.key, &req.upload_id, &req.parts) {
                Ok(size) => size,
                Err(CompleteRefusal::Exists) => {
                    state.completed.insert(req.key.clone());
                    state.uploads.remove(&req.upload_id);
                    return Err(RegistrarError::KeyExists {
                        key: req.key.clone(),
                    });
                }
                Err(CompleteRefusal::BadParts(reason)) => {
                    return Err(RegistrarError::Protocol(reason));
                }
            },
            None => None,
        };
        state.completed.insert(req.key.clone());
        state.uploads.remove(&req.upload_id);
        Ok(UploadCompleteResponse { size })
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
    #[serde(default)]
    key: Option<String>,
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
                    key: None,
                });
                if let Some(live) = c.live_epoch.filter(|l| *l != epoch) {
                    Err(RegistrarError::Fenced { epoch, live })
                } else if c.reason == "stale-epoch" {
                    Err(RegistrarError::Fenced { epoch, live: 0 })
                } else if name == "change.summary" {
                    Err(RegistrarError::SummaryRefused(c.reason))
                } else if name == "upload.complete" {
                    if c.reason == "exists" {
                        Err(RegistrarError::KeyExists {
                            key: c.key.unwrap_or_default(),
                        })
                    } else {
                        Err(RegistrarError::Protocol(format!(
                            "upload.complete refused: {}",
                            c.reason
                        )))
                    }
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

    fn upload_complete(
        &self,
        req: &UploadCompleteRequest,
    ) -> Result<UploadCompleteResponse, RegistrarError> {
        self.call("upload.complete", req, req.epoch)
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

/// A [`crate::sink::UrlMinter`] over a registrar: PUT and part URLs come from `upload.urls`,
/// multipart completes go to `upload.complete`, GET URLs come from the plan. A re-plan
/// ([`Self::reset`]) moves it to the new identity and the new plan's GET URLs.
#[derive(Debug)]
pub struct RegistrarMinter<R: Registrar + ?Sized> {
    registrar: std::sync::Arc<R>,
    identity: Mutex<(String, u64)>,
    put_cache: Mutex<BTreeMap<String, String>>,
    get_urls: Mutex<BTreeMap<String, String>>,
}

impl<R: Registrar + ?Sized> RegistrarMinter<R> {
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
            identity: Mutex::new((worktree_id.to_owned(), epoch)),
            put_cache: Mutex::new(BTreeMap::new()),
            get_urls: Mutex::new(get_urls),
        }
    }

    /// The worktree and epoch URLs are minted for.
    #[must_use]
    pub fn identity(&self) -> (String, u64) {
        self.identity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Mint for `worktree_id` at `epoch` from now on, with `get_urls` from the new plan;
    /// PUT URLs minted under the previous identity are forgotten.
    pub fn reset(&self, worktree_id: &str, epoch: u64, get_urls: BTreeMap<String, String>) {
        *self
            .identity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (worktree_id.to_owned(), epoch);
        self.put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        *self
            .get_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = get_urls;
    }

    /// Pre-mint PUT URLs for a batch of keys (one channel call).
    pub fn prefetch_put(&self, keys: &[String]) -> Result<(), RegistrarError> {
        let (worktree_id, epoch) = self.identity();
        let resp = self.registrar.upload_urls(&UploadUrlsRequest::new(
            &worktree_id,
            epoch,
            keys.to_vec(),
        ))?;
        self.put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(resp.urls);
        Ok(())
    }
}

impl<R: Registrar + ?Sized> crate::sink::UrlMinter for RegistrarMinter<R> {
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

    fn multipart_urls(&self, key: &str, size: u64) -> Result<Option<MultipartUrls>, String> {
        let (worktree_id, epoch) = self.identity();
        let mut req = UploadUrlsRequest::new(&worktree_id, epoch, vec![key.to_owned()]);
        req.sizes.insert(key.to_owned(), size);
        let mut resp = self
            .registrar
            .upload_urls(&req)
            .map_err(|e| e.to_string())?;
        let multipart = resp.multipart.remove(key);
        // A registrar that answered with a plain PUT URL (below its threshold, or no multipart
        // support) has minted it now; keep it for the single-PUT fallback.
        self.put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(resp.urls);
        Ok(multipart)
    }

    fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<crate::sink::Completed, crate::sink::SinkError> {
        use crate::sink::{Completed, PutOutcome, SinkError};
        let (worktree_id, epoch) = self.identity();
        match self.registrar.upload_complete(&UploadCompleteRequest {
            worktree_id,
            epoch,
            key: key.to_owned(),
            upload_id: upload_id.to_owned(),
            parts: parts.to_vec(),
        }) {
            Ok(resp) => Ok(Completed {
                outcome: PutOutcome::Stored,
                size: resp.size,
            }),
            Err(RegistrarError::KeyExists { .. }) => Ok(Completed {
                outcome: PutOutcome::AlreadyPresent,
                size: None,
            }),
            Err(RegistrarError::Transport(reason)) => Err(SinkError::Transport {
                method: "COMPLETE",
                key: key.to_owned(),
                reason,
            }),
            Err(e) => Err(SinkError::Multipart {
                key: key.to_owned(),
                reason: e.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        BulkSection, BulkState, CaptureKind, FsckStatus, GitSection, Sections, WorkspaceSection,
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
        let r = InMemoryRegistrar::new("wt", 1, None);
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
        let r = InMemoryRegistrar::new("wt", 1, Some("http://x".into()));
        let resp = r
            .upload_urls(&UploadUrlsRequest::new(
                "wt",
                1,
                vec![
                    "captures/wt/1/packs/a".into(),
                    "captures/wt/0/packs/b".into(),
                    "projects/p/x".into(),
                ],
            ))
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
                worktree_id: None,
                epoch: 1,
                platform: None,
            })
            .unwrap();
        assert_eq!(plan.head.unwrap().capture_id, "a");
    }

    /// `plan.get` names the executor's platform; a head whose bulk section was captured for
    /// another one comes back with bulk `"pending"` and no bulk packs to fetch, an absent or
    /// matching platform gets the head as is, and the field stays off the wire when unset.
    #[test]
    fn plan_get_answers_bulk_pending_for_another_platform() {
        let r = InMemoryRegistrar::new("wt", 1, Some("http://x".into()));
        let mut m = manifest(0, None);
        m.sections.bulk = BulkState::Ready(BulkSection {
            root: "captures/wt/1/trees/b".into(),
            packs: vec!["captures/wt/1/packs/bulkpack".into()],
            platform: "linux-x86_64-gnu".into(),
        });
        r.capture_register(&RegisterRequest {
            manifest: m,
            ..register(0, None, "a", 1)
        })
        .unwrap();
        let plan = |platform: Option<&str>| {
            r.plan_get(&PlanGetRequest {
                worktree_id: None,
                epoch: 0,
                platform: platform.map(str::to_owned),
            })
            .unwrap()
        };
        let same = plan(Some("linux-x86_64-gnu"));
        assert!(
            same.head
                .unwrap()
                .manifest
                .sections
                .bulk
                .section()
                .is_some()
        );
        assert!(same.get_urls.contains_key("captures/wt/1/packs/bulkpack"));
        let absent = plan(None);
        assert!(
            absent
                .head
                .unwrap()
                .manifest
                .sections
                .bulk
                .section()
                .is_some()
        );
        let other = plan(Some("linux-aarch64-musl"));
        let head = other.head.unwrap();
        assert_eq!(head.manifest.sections.bulk, BulkState::pending());
        assert!(!other.get_urls.contains_key("captures/wt/1/packs/bulkpack"));
        assert_eq!(head.capture_id, "a", "the head itself is unchanged");

        let booting = PlanGetRequest::booting(Some("wt".into()));
        let json = serde_json::to_value(&booting).unwrap();
        assert_eq!(json["epoch"], 0);
        assert_eq!(json["platform"], crate::engine::default_platform());
        let bare = serde_json::to_value(PlanGetRequest {
            worktree_id: None,
            epoch: 1,
            platform: None,
        })
        .unwrap();
        assert!(bare.get("platform").is_none());
        let back: PlanGetRequest =
            serde_json::from_str(r#"{"worktree_id":null,"epoch":2}"#).unwrap();
        assert_eq!(back.platform, None);
    }

    fn parts(n: u32) -> Vec<CompletedPart> {
        (1..=n)
            .map(|part_number| CompletedPart {
                part_number,
                etag: format!("\"e{part_number}\""),
            })
            .collect()
    }

    /// Create/Complete semantics of the double: threshold, part count, exact part list, 409 on
    /// an existing key, and the wire shape of both calls.
    #[test]
    fn multipart_create_and_complete() {
        let r = InMemoryRegistrar::new("wt", 1, Some("http://x".into())).with_multipart(
            MultipartPolicy {
                threshold: 100,
                part_size: 40,
            },
            None,
        );
        let big = "captures/wt/1/packs/big".to_owned();
        let small = "captures/wt/1/packs/small".to_owned();
        let mut req = UploadUrlsRequest::new("wt", 1, vec![big.clone(), small.clone()]);
        req.sizes.insert(big.clone(), 100);
        req.sizes.insert(small.clone(), 99);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["sizes"][&big], 100);
        let resp = r.upload_urls(&req).unwrap();
        assert_eq!(resp.urls.len(), 1, "the small key is a single PUT");
        assert!(resp.urls.contains_key(&small));
        let mp = &resp.multipart[&big];
        assert_eq!(mp.part_size, 40);
        assert_eq!(mp.part_urls.len(), 3);
        assert_eq!(
            mp.part_urls[2],
            format!("http://x/{big}?partNumber=3&uploadId={}", mp.upload_id)
        );
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["multipart"][&big]["upload_id"], mp.upload_id);
        assert!(json["urls"].get(&big).is_none());
        // Without sizes the response has no `multipart` member at all.
        let plain = r
            .upload_urls(&UploadUrlsRequest::new("wt", 1, vec![big.clone()]))
            .unwrap();
        assert!(
            serde_json::to_value(&plain)
                .unwrap()
                .get("multipart")
                .is_none()
        );
        assert_eq!(r.open_uploads(), 1);

        let complete = |parts: Vec<CompletedPart>| UploadCompleteRequest {
            worktree_id: "wt".into(),
            epoch: 1,
            key: big.clone(),
            upload_id: mp.upload_id.clone(),
            parts,
        };
        assert!(matches!(
            r.upload_complete(&complete(parts(2))),
            Err(RegistrarError::Protocol(_))
        ));
        assert_eq!(r.completes(), 0);
        let json = serde_json::to_value(complete(parts(3))).unwrap();
        assert_eq!(json["parts"][0]["part_number"], 1);
        assert_eq!(json["parts"][0]["etag"], "\"e1\"");
        assert_eq!(
            r.upload_complete(&complete(parts(3))).unwrap(),
            UploadCompleteResponse { size: None }
        );
        assert_eq!(r.open_uploads(), 0);
        assert!(
            matches!(
                r.upload_complete(&complete(parts(3))),
                Err(RegistrarError::Protocol(_))
            ),
            "an upload completes once"
        );
        // A second upload of the same key: created, then refused as existing on complete.
        let resp = r.upload_urls(&req).unwrap();
        let again = &resp.multipart[&big];
        assert!(matches!(
            r.upload_complete(&UploadCompleteRequest {
                upload_id: again.upload_id.clone(),
                ..complete(parts(3))
            }),
            Err(RegistrarError::KeyExists { .. })
        ));
        assert_eq!(r.completes(), 2);
        r.set_live_epoch(2);
        assert!(matches!(
            r.upload_urls(&req),
            Err(RegistrarError::Fenced { .. })
        ));
    }
}
