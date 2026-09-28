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
//! # Keys the bucket already holds: `present`
//!
//! Stored objects are write-once (cross-repo decision 19). `upload.urls` mints no URL for a key
//! the bucket already holds: the registrar verifies the stored bytes against what the key names
//! and answers the key in `present`, in neither `urls` nor `multipart`. The executor takes such
//! a key as uploaded (`PutOutcome::AlreadyPresent`) and moves on. Every presigned PUT carries
//! `If-None-Match: *`; a 412 on it (the object landed since the mint) is the same answer. A key
//! the executor asked for that comes back in none of the three is an error, never an upload
//! skipped.
//!
//! ```json
//! ← {"urls":{"captures/wt/3/packs/<a>":"https://…"},"multipart":{},
//!    "present":["captures/wt/3/packs/<b>"]}
//! ```
//!
//! `present` is negotiated (cross-repo decision 20). An executor from before it requires a URL
//! for every key it asks for and fails on a `present` answer; a retained disk keeps running
//! that older binary until it is recovered. So every `plan.get` request of this build lists the
//! answer shapes it reads beyond a URL in `upload_answers` ([`UPLOAD_ANSWERS`]), and a
//! registrar answers `present` only to an executor whose `plan.get` listed it — to any other it
//! mints a (conditional) URL as before, whose PUT meets a 412 the executor takes as uploaded.
//! The registrar binds what the executor listed to the launch that sent it: a later call of
//! that launch is answered as its `plan.get` asked.
//!
//! ```json
//! → {"worktree_id":null,"epoch":0,…,"upload_answers":["present"]}
//! ```
//!
//! ETags travel verbatim as the store returned them (quotes included). Part URLs are minted
//! only while the lease predicate holds, like PUT URLs, and count against the same URL quota.
//! A multipart upload the executor abandons (it dies, or a part fails past its retries and the
//! object is retried under a fresh `upload_id`) is the registrar's to expire: a bucket lifecycle
//! rule for incomplete multipart uploads, no `upload.abort` call in v1.
//!
//! # Byte-quota refusals
//!
//! A session has a byte budget. The registrar prices a key once and refuses a call that would
//! take the session past the budget: `upload.urls` answers 413 before minting anything, and
//! `capture.register` backstops keys that were never sized with 409 of the same body. Both are
//! [`RegistrarError::QuotaRefused`]. The shipper drops nothing: the capture is held in the queue
//! with its staged bytes, its class reported refused in `capture.status`, and asked for again
//! after a backoff (30 s, doubling, 10 min at most) until the budget allows
//! ([`crate::ship::HeldCapture`]).
//!
//! ```json
//! ← 413 {"reason":"byte-quota","limit":8589934592,"used":8570000000,"requested":775000000}
//! ← 409 {"reason":"byte-quota","limit":8589934592,"used":8570000000,"requested":775000000}
//! ```
//!
//! So a whole batch can be priced before a URL is minted, `upload.urls` carries `sizes` for
//! **every** key it asks for, not only the ones that would go up as multipart. A single-key
//! fallback mint declares that object's length too ([`crate::sink::UrlMinter::put_url`] takes
//! it): a registrar may bind the signature to the exact content length — Mend's upload length
//! binding — and a stand-in size would mint a URL the PUT cannot use.
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
//! Another platform's bulk section is never dropped from the chain. The executor keeps it in
//! the manifest's `sections.other_bulk` (keyed by platform), carries it through every capture,
//! and its own bulk snap fills `bulk` beside it. A registrar answering an executor of platform
//! P answers `bulk` when it was captured on P, else `other_bulk[P]` (with its packs in
//! `get_urls`), else `"pending"`; it keeps every pack `other_bulk` names alive in retention.
//!
//! ```json
//! "sections":{…,"bulk":{"root":"…","packs":[…],"platform":"linux-x86_64-gnu"},
//!             "other_bulk":{"linux-aarch64-gnu":{"root":"…","packs":[…],"platform":"linux-aarch64-gnu"}}}
//! ```
//!
//! # `lease-lost`
//!
//! A 409 `{"reason":"lease-lost"}` (the lease lapsed, was released, or a standby is not claimed
//! yet) is [`RegistrarError::LeaseLost`] from every call — unless it names a `live_epoch` other
//! than the caller's, which is a fence. The shipper pauses and asks again after a backoff (1 s,
//! doubling, 30 s at most), keeping everything staged. It used to read as a wrong parent — a
//! chain conflict — which ended a final flush with the captures still on the disk.
//!
//! # Register refusals: `missing-objects`, `unrestorable`
//!
//! A registrar acknowledges only a capture it can restore. `capture.register` answers 422 when
//! an object the manifest names is not in the store (`missing-objects`, the keys in `missing`)
//! or a section's tree would not restore from what it names (`unrestorable`, no keys):
//!
//! ```json
//! ← 422 {"reason":"missing-objects","message":"1 pack(s) the manifest names are not in the bucket",
//!        "missing":["captures/wt/3/packs/<sha256>"]}
//! ```
//!
//! This is [`RegistrarError::RegisterRefused`]. The shipper never drops the capture: the engine
//! rebuilds it from disk in its place with the named packs forgotten
//! ([`crate::ship::RepairRequest`]; every pack of the capture's sections when none is named),
//! reported in `capture.status`. It never puts a key again once a register naming it was
//! refused (cross-repo decision 6: a refused key may be one retention condemned, which the
//! registrar refuses for good, and a delete retention paused would take it back out from under
//! a capture that named it again): the rebuild first moves the staging's key generation on, so
//! every object it uploads — the same bytes included — goes up under a new key,
//! `captures/<worktree>/<epoch>/g<generation>/…` ([`crate::keys`]). A registrar keeps a key's
//! tombstone forever and refuses it by name (`missing-objects`); a key without a `g<n>`
//! segment was written before generations and is read as before.
//!
//! # `manifest_format` on `plan.get`
//!
//! The answer names the highest section format the registrar reads (`manifest.rs`): what it
//! walks to presign a plan, HEADs and prices at register, keeps alive in retention. Absent = 1,
//! one object per directory. At 2 the executor writes a chunked section's dir objects into dir
//! packs (`dir_packs`, keyed `…/packs/<sha256>` like any pack) and names them by digest; below
//! it the executor writes format 1 as before, so an executor never writes a capture its
//! registrar cannot restore. Either way the executor reads both formats.
//!
//! ```json
//! ← {"worktree_id":"wt","epoch":3,"head":{…},"get_urls":{…},"manifest_format":2}
//! ```
//!
//! # `manifest_features` on `plan.get`
//!
//! `manifest_format` says how dir objects are stored, not what a manifest means. The request
//! also lists every manifest feature this build reads ([`MANIFEST_FEATURES`]); a registrar
//! refuses a head holding one the list leaves out (409 `manifest-features`, naming them in
//! `missing`) before it claims the lease, because an executor that ignores one restores less
//! than was saved or drops it from the captures it writes next. The answer lists the features
//! the registrar reads, validates and keeps. A feature is held when: `worktree_meta` — the
//! answered workspace section has `worktree_meta`; `symrefs` — the git section has a non-empty
//! `symrefs`; `other_bulk` — the stored head has a non-empty `other_bulk`, or its ready `bulk`
//! was captured on another platform than the request names; `raw_names` — a dir entry of the
//! answered workspace or bulk section carries `raw_name` or `raw_target`; `final_seal` — the
//! head carries `final_seal`; `git_trees` — the git section carries `worktree_tree`.
//!
//! The executor writes `git_trees` only for a registrar whose answer lists it (else the trees
//! ride `refs` as pseudo-refs, as before): the git section then names `worktree_tree`,
//! `index_tree` (absent when the index has unmerged entries) and `raw_tree` in their own fields,
//! and `refs` holds the repository's refs only, whatever their names — a ref under
//! `refs/sealant/capture/` is the user's. A registrar that reads it takes the worktree tree from
//! `worktree_tree` when present (else the `refs/sealant/capture/worktree` entry), treats every
//! `refs` entry as a ref in a section that has it, keeps all three trees' objects alive (they are
//! pack tips like any ref), and restores `raw_tree`'s blobs byte for byte: no smudge filter, no
//! end-of-line or encoding conversion.
//!
//! ```json
//! → {"worktree_id":null,"epoch":0,"platform":"linux-x86_64-gnu","manifest_format":2,
//!    "manifest_features":["worktree_meta","symrefs","other_bulk","raw_names","final_seal","git_trees"]}
//! ← 409 {"reason":"manifest-features","message":"…","missing":["final_seal"]}
//! ```
//!
//! # `executor` on `plan.get`, and the final seal
//!
//! A final flush that completes registers one more capture carrying `final_seal: {complete:
//! true, epoch, executor}` ([`crate::manifest::FinalSeal`]) and reports `complete` only once
//! that register is acknowledged. `executor` is the plan's `executor` — the launch id the
//! session token was issued for (cross-repo decision 5) — and nothing else: a plan that names
//! none gets no seal, and a re-plan replaces it (a seal never carries over to another launch).
//! The registrar records the seal on the chain only when it is complete, names the registering
//! epoch and names that executor. The seal also says where it stands in that executor's own
//! order (cross-repo decision 17, [`crate::position`]): `boot_id`, `boot_generation` and
//! `observation`, beside the manifest's `n`, in the same order as every `capture.status` and
//! final `capture.flush` answer's position (`CaptureStatusReport` fields 27–30). A registrar
//! that does not read them ignores them; none of them is part of whose seal it is.
//!
//! ```json
//! ← {"worktree_id":"wt","epoch":3,…,"manifest_features":[…],"executor":"<executor id>"}
//! ```
//!
//! # Sources beside the worktree
//!
//! A capture-source workspace mounts nothing from the host, so content the control plane wants
//! beside the repository — Mend's organization folders and reference repositories — travels on
//! the plan as `sources`: a gzipped tar per source, at a key whose GET URL rides `get_urls`,
//! with the archive's `sha256` as both the integrity check and the stamp that says whether the
//! copy on disk is already current. Paths are absolute, inside the workspace and outside the
//! worktree, so nothing laid down here is ever captured back.
//!
//! ```json
//! ← {…,"sources":[{"name":"docs","path":"/workspace/home/docs",
//!    "key":"projects/p/sources/<sha256>","sha256":"<sha256>","bytes":40960,
//!    "read_only":true}]}
//! ```
//!
//! # Remotes of the worktree
//!
//! The executor builds the worktree's repository itself (`git init`, then the head's packs), so
//! it has no remotes: the ones the control plane's own copy carries never travel in a capture.
//! A harness that runs `git push origin` would find no `origin`. The plan therefore names the
//! remotes the repository should have, and the executor sets each one it lacks after it
//! materializes a base (an empty chain, or a head that carries no `.git/config`); a head that
//! carries one is a session's own configuration and is left as it is. Only the name and the URL travel; how the remote is authenticated stays the control
//! plane's business (Mend routes git's ssh through the session channel).
//!
//! ```json
//! ← {…,"remotes":[{"name":"origin","url":"git@github.com:acme/api.git"}]}
//! ```
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

use crate::manifest::{
    BulkState, FORMAT_DIR_OBJECTS, FinalSeal, MAX_SECTION_FORMAT, Manifest, TreeRef,
};

/// Every manifest feature this build reads, validates and carries on (`plan.get`
/// `manifest_features`): see the module docs.
pub const MANIFEST_FEATURES: [&str; 7] = [
    "worktree_meta",
    "symrefs",
    "other_bulk",
    "raw_names",
    "final_seal",
    "git_trees",
    "object_format",
];
use crate::transport::{ChannelTransport, TransportError};

/// `plan.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanGetRequest {
    /// Worktree, when the executor knows it (`SEALANT_CAPTURE_WORKTREE_ID`); otherwise the
    /// session token identifies it and the response says which.
    pub worktree_id: Option<String>,
    /// Caller's epoch; 0 = not claimed yet (the plan of a booting executor claims the lease).
    pub epoch: u64,
    /// The executor's `<os>-<arch>-<libc>`: the registrar answers the head's bulk section when
    /// it was captured on this platform, else the one `other_bulk` carries for it, else
    /// `"pending"`. Absent = the head as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// The highest section format this executor reads ([`MAX_SECTION_FORMAT`]). The registrar
    /// answers `manifest_format` no higher than it and refuses (409 `manifest-format`) a head
    /// holding a section above it: an older reader takes a format-2 root digest for a key.
    /// Absent = 1 (an executor from before format 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_format: Option<u32>,
    /// The manifest features this executor reads ([`MANIFEST_FEATURES`]). The registrar
    /// refuses (409 `manifest-features`) a head holding one the list leaves out. Absent = none
    /// (an executor from before the list).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_features: Option<Vec<String>>,
    /// The launch this executor is (cross-repo decision 11), from its first `plan.get` on: as
    /// its launcher named it (`SEALANT_CAPTURE_LAUNCH_ID`), else as its own disk last recorded
    /// it (a restart or a recovery boot of a launch that predates the variable). The session
    /// token binds the launch already; a registrar refuses a request whose `launch` is not the
    /// token's (409 `launch-mismatch`), and binds the lease to that launch, so an old launch's
    /// executor never joins a newer launch's epoch. Absent = the executor does not know (an
    /// older daemon, or a first boot with no launch named): the token alone decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
    /// The `upload.urls` answer shapes this executor reads beyond a URL ([`UPLOAD_ANSWERS`]):
    /// `present`, a key the bucket already holds, taken as uploaded (cross-repo decision 20).
    /// A registrar answers a shape only to an executor that names it here; to one that does
    /// not (absent: an executor from before the list), it answers a URL as before — its PUT
    /// meets the store's 412 on `If-None-Match: *`, which every executor takes as uploaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_answers: Option<Vec<String>>,
}

/// Every `upload.urls` answer shape beyond a URL this build reads (`plan.get`
/// `upload_answers`): see the module docs.
pub const UPLOAD_ANSWERS: [&str; 1] = ["present"];

impl PlanGetRequest {
    /// The request a booting executor sends: `epoch` 0, this build's platform and the highest
    /// section format it reads.
    #[must_use]
    pub fn booting(worktree_id: Option<String>) -> Self {
        Self {
            worktree_id,
            epoch: 0,
            platform: Some(crate::engine::default_platform()),
            manifest_format: Some(MAX_SECTION_FORMAT),
            manifest_features: Some(MANIFEST_FEATURES.iter().map(|f| (*f).to_owned()).collect()),
            launch: None,
            upload_answers: Some(UPLOAD_ANSWERS.iter().map(|a| (*a).to_owned()).collect()),
        }
    }

    /// This request naming the launch the executor is ([`Self::launch`]).
    #[must_use]
    pub fn with_launch(mut self, launch: Option<String>) -> Self {
        self.launch = launch;
        self
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
    /// Read-only content to lay down beside the worktree, outside it: the control plane's
    /// folders and reference repositories, which a capture-source workspace cannot reach as a
    /// host mount. Absent from an older registrar's answer, which means "nothing beside the
    /// worktree".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<PlanSource>,
    /// Remotes the worktree's repository should have. The executor builds that repository
    /// itself, so without these it has none. Absent from an older registrar's answer, which
    /// means "leave the repository's remotes alone".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remotes: Vec<PlanRemote>,
    /// The highest section format the registrar reads (`manifest.rs`); 1 when absent. At 2 the
    /// executor writes dir packs ([`crate::manifest::DirFormat::for_registrar`]).
    #[serde(default = "manifest_format_one")]
    pub manifest_format: u32,
    /// The manifest features the registrar reads, validates and keeps. Absent from an older
    /// registrar's answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifest_features: Vec<String>,
    /// The executor the session token was issued for: what a completed final flush's seal
    /// names ([`crate::manifest::FinalSeal`]). Absent from a registrar that does not say, and
    /// then no seal is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
}

fn manifest_format_one() -> u32 {
    FORMAT_DIR_OBJECTS
}

/// The highest section format a plan asks its reader to read: its workspace section and the
/// bulk section answered to the executor (Mend's `planFormatOf`).
fn plan_format(manifest: &Manifest) -> u32 {
    let bulk = manifest.sections.bulk.section().map_or(0, |b| b.format);
    manifest.sections.workspace.format.max(bulk)
}

/// The manifest features `planned` (the head as the executor would restore it; `stored` as
/// registered) holds that `reads` leaves out, as Mend's `missingManifestFeatures` decides them.
/// `raw_names` needs the dir objects walked, which this does not do: it is decided only when the
/// caller says (`raw_names`).
#[must_use]
pub fn missing_manifest_features(
    stored: &Manifest,
    planned: &Manifest,
    platform: Option<&str>,
    reads: &[String],
    raw_names: bool,
) -> Vec<String> {
    let stored_bulk_elsewhere = platform.is_some_and(|platform| {
        stored
            .sections
            .bulk
            .section()
            .is_some_and(|b| b.platform != platform)
    });
    [
        (
            "worktree_meta",
            planned.sections.workspace.worktree_meta.is_some(),
        ),
        ("symrefs", !planned.sections.git.symrefs.is_empty()),
        (
            "other_bulk",
            !stored.sections.other_bulk.is_empty() || stored_bulk_elsewhere,
        ),
        ("raw_names", raw_names),
        ("final_seal", planned.final_seal.is_some()),
        ("git_trees", planned.sections.git.has_tree_fields()),
        (
            "object_format",
            planned.sections.git.object_format.is_some(),
        ),
    ]
    .into_iter()
    .filter(|(feature, held)| *held && !reads.iter().any(|r| r == feature))
    .map(|(feature, _)| feature.to_owned())
    .collect()
}

/// The store keys a chunked section names for its dir objects: the root key in format 1 (the
/// rest are found by walking it), the dir packs in format 2.
#[must_use]
pub fn tree_keys(tree: TreeRef<'_>) -> Vec<String> {
    if tree.format == FORMAT_DIR_OBJECTS {
        vec![tree.root.to_owned()]
    } else {
        tree.dir_packs.to_vec()
    }
}

/// One remote of the worktree's repository: what `git remote add <name> <url>` takes. Nothing
/// about authentication travels here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRemote {
    /// The remote's name, e.g. `origin`.
    pub name: String,
    /// The URL git dials, in any form git accepts (`https://…`, `ssh://…`, `git@host:path`).
    pub url: String,
}

/// One archive the plan names to lay down beside the worktree. The bytes are a gzipped tar at
/// `key`, fetched through the same presigned GET URLs as the head's objects, and `sha256` is
/// both the integrity check and the stamp that decides whether the copy on disk is current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSource {
    /// A short name for logs and errors; never a path component.
    pub name: String,
    /// Absolute path inside the workspace, outside the worktree: content under the worktree
    /// would be captured back into the store.
    pub path: String,
    /// Object key of the gzipped tar; its GET URL rides `get_urls`.
    pub key: String,
    /// sha256 of the archive bytes, lowercase hex.
    pub sha256: String,
    /// Archive length in bytes.
    pub bytes: u64,
    /// Take the writable bit off the extracted copy. Either way nothing here travels back: a
    /// source is a copy, and it sits outside every capture root.
    #[serde(default = "default_read_only")]
    pub read_only: bool,
}

fn default_read_only() -> bool {
    true
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
    /// Size of each key the caller can size (any key, not only multipart candidates): the
    /// registrar prices the batch from these before it mints anything.
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
    /// Keys the bucket already holds, with the bytes their names say (the registrar verified
    /// them): no URL is minted for them, and the executor takes each as uploaded. Absent from an
    /// older registrar.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub present: Vec<String>,
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
    /// What the registrar did with the final seal the registered capture carries
    /// ([`crate::manifest::FinalSeal`]; cross-repo decision 22): answered whenever the capture
    /// (`n`, `capture_id`) carries one, on a lost-ack answer (the chain already at `n` with
    /// this id) too. Absent when the capture carries none — and from a registrar that does not
    /// say, which an executor takes as a seal that does not stand (fail closed, decision 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealAnswer>,
}

/// What a registrar did with a registered capture's final seal (`capture.register`'s `seal`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealAnswer {
    /// `recorded`, `withheld` or `refused`.
    pub state: SealState,
    /// Why, for `withheld` and `refused`: a short code (`verifying`, `write-authority`,
    /// `executor`, …), for logs and the flush's report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Where a registered final seal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SealState {
    /// Recorded, and standing now: the registrar attests this executor's completion on it
    /// (its plans and stop attestations may name it). The only answer a final flush is
    /// complete on.
    Recorded,
    /// The capture registered, but the seal does not stand yet (the registrar is still
    /// verifying what it names, or write authority it issued over those objects is still
    /// outstanding). The executor asks again by sending the same register (a lost-ack answer
    /// that says where the seal stands now); until the answer is `recorded` the final flush is
    /// incomplete (`sealing`).
    Withheld,
    /// The registrar will not record this seal (it names another executor or epoch, or what
    /// it names does not restore). The final flush is incomplete (`sealing`).
    Refused,
}

impl SealAnswer {
    /// A `recorded` answer.
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            state: SealState::Recorded,
            reason: None,
        }
    }

    /// A `withheld` or `refused` answer with its reason.
    #[must_use]
    pub fn not_standing(state: SealState, reason: &str) -> Self {
        Self {
            state,
            reason: Some(reason.to_owned()),
        }
    }
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
    /// The bytes are over the session's quota: 413 on `upload.urls` (before a URL is minted) or
    /// 409 `byte-quota` on `capture.register`. Terminal for the capture that asked.
    #[error("refused ({reason}): limit {}, used {}, requested {}", opt(.limit), opt(.used), opt(.requested))]
    QuotaRefused {
        /// The registrar's reason code (`byte-quota`).
        reason: String,
        /// The session's budget in bytes, when the answer names it.
        limit: Option<u64>,
        /// Bytes priced against the session so far.
        used: Option<u64>,
        /// Bytes this call asked for.
        requested: Option<u64>,
    },
    /// 422 `missing-objects` or `unrestorable` on `capture.register`: the registrar will not
    /// acknowledge a capture it could not restore — an object it names is not in the store
    /// (retention removed a pack the executor's chunk index still pointed at, an upload that
    /// never landed) or a section's tree would not restore. Nothing is registered, nothing is
    /// dropped: the shipper uploads the named objects again, and rebuilds the capture from disk
    /// when that is not enough ([`crate::ship::RepairRequest`]).
    #[error("register refused ({reason}): {message}")]
    RegisterRefused {
        /// `missing-objects` or `unrestorable`.
        reason: String,
        /// The keys the registrar named (`missing`); empty when it named none.
        missing: Vec<String>,
        /// The registrar's message.
        message: String,
    },
    /// 409 `worktree-leased` on `plan.get`: another launch holds the worktree's lease, and this
    /// executor is given no epoch. It adopts none: a boot waits and asks again, a re-plan keeps
    /// the identity it has (Mend round 4).
    #[error("worktree leased by another launch: no epoch is given to this one")]
    WorktreeLeased,
    /// Transport failure (retryable).
    #[error("transport: {0}")]
    Transport(String),
    /// Unexpected answer.
    #[error("protocol: {0}")]
    Protocol(String),
}

/// A number the registrar may or may not have named.
pub(crate) fn opt(v: &Option<u64>) -> String {
    v.map_or_else(|| "?".to_owned(), |n| n.to_string())
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
    /// Bytes priced per key (a key is priced once, as Mend prices it).
    priced: BTreeMap<String, u64>,
    /// Every size the caller declared on `upload.urls`, for tests of what the wire carried.
    sizes_seen: BTreeMap<String, u64>,
    chain: Vec<HeadInfo>,
    lease_alive: bool,
    summaries: Vec<ChangeSummaryRequest>,
    url_requests: u64,
    uploads: BTreeMap<String, PendingUpload>,
    /// Keys completed through this registrar (the default existence check).
    completed: BTreeSet<String>,
    completes: u64,
    next_upload: u64,
    /// Content the plan names beside the worktree.
    sources: Vec<PlanSource>,
    /// Remotes the plan names for the worktree's repository.
    remotes: Vec<PlanRemote>,
    /// Final seals recorded on the chain: the capture's `n` and the seal, as Mend records them
    /// (complete, the registering epoch, this registrar's executor).
    seals: Vec<(u64, FinalSeal)>,
    /// Every `plan.get` asked, oldest first.
    plan_requests: Vec<PlanGetRequest>,
    /// Registers of a sealing capture still to answer `withheld` (the seal is recorded, and
    /// answered `recorded`, at the first one after these).
    seals_withheld: usize,
    /// Answer no `seal` on `capture.register`, as a registrar from before decision 22.
    seal_answers_off: bool,
    /// `plan.get`s still to refuse with 409 `worktree-leased` (another launch holds the lease).
    leased_plans: usize,
}

/// In-memory registrar: one worktree, one chain, a live epoch, a lease flag.
pub struct InMemoryRegistrar {
    state: Mutex<InMemoryState>,
    worktree_id: Mutex<String>,
    url_base: Option<String>,
    multipart: Option<MultipartPolicy>,
    completer: Option<Arc<dyn MultipartCompleter>>,
    /// Bytes this session may hold, and where a register-time price comes from.
    quota: Mutex<Option<ByteQuota>>,
    /// The `manifest_format` `plan.get` answers.
    manifest_format: u32,
    /// The `manifest_features` `plan.get` answers (default: every one this build reads).
    manifest_features: Vec<String>,
    /// The executor the token is scoped to: answered on `plan.get`, and the only one whose
    /// final seal is recorded.
    executor: Option<String>,
}

/// The in-memory registrar's byte budget: keys are priced from the `sizes` of `upload.urls`, and
/// a key a register names that was never sized is priced from `store` (the bucket's report, which
/// is what Mend's backstop does).
struct ByteQuota {
    limit: u64,
    store: Option<Arc<dyn crate::sink::BlobSink>>,
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
            quota: Mutex::new(None),
            state: Mutex::new(InMemoryState {
                live_epoch: epoch,
                priced: BTreeMap::new(),
                sizes_seen: BTreeMap::new(),
                chain: Vec::new(),
                lease_alive: true,
                summaries: Vec::new(),
                url_requests: 0,
                uploads: BTreeMap::new(),
                sources: Vec::new(),
                remotes: Vec::new(),
                seals: Vec::new(),
                plan_requests: Vec::new(),
                seals_withheld: 0,
                seal_answers_off: false,
                leased_plans: 0,
                completed: BTreeSet::new(),
                completes: 0,
                next_upload: 0,
            }),
            url_base,
            multipart: None,
            completer: None,
            manifest_format: MAX_SECTION_FORMAT,
            manifest_features: MANIFEST_FEATURES.iter().map(|f| (*f).to_owned()).collect(),
            executor: None,
        }
    }

    /// Answer `executor` on `plan.get`, and record a final seal only when it names this
    /// executor (as Mend does).
    #[must_use]
    pub fn with_executor(mut self, executor: &str) -> Self {
        self.executor = Some(executor.to_owned());
        self
    }

    /// The final seals recorded on the chain: `(n, seal)`, oldest first.
    #[must_use]
    pub fn seals(&self) -> Vec<(u64, FinalSeal)> {
        self.lock().seals.clone()
    }

    /// Answer the next `count` registers of a sealing capture (a lost-ack register asking
    /// again included) `withheld`, recording nothing: a registrar still verifying what the
    /// seal names (decision 22). The one after them records the seal.
    pub fn withhold_seals(&self, count: usize) {
        self.lock().seals_withheld = count;
    }

    /// Answer no `seal` on `capture.register`, as a registrar from before decision 22 (seals
    /// are recorded as before).
    pub fn without_seal_answers(&self) {
        self.lock().seal_answers_off = true;
    }

    /// Where the final seal `seal` of the capture at `n`, registered under `epoch`, stands —
    /// recording it when it holds and is no longer withheld (Mend's register, decision 22).
    fn answer_seal(
        &self,
        state: &mut InMemoryState,
        n: u64,
        epoch: u64,
        seal: &FinalSeal,
    ) -> Option<SealAnswer> {
        let answer = if !seal.complete {
            SealAnswer::not_standing(SealState::Refused, "incomplete")
        } else if seal.epoch != epoch {
            SealAnswer::not_standing(SealState::Refused, "epoch")
        } else if self.executor.as_deref() != Some(seal.executor.as_str()) {
            SealAnswer::not_standing(SealState::Refused, "executor")
        } else if state.seals_withheld > 0 {
            state.seals_withheld -= 1;
            SealAnswer::not_standing(SealState::Withheld, "verifying")
        } else {
            if !state.seals.iter().any(|(sealed, _)| *sealed == n) {
                state.seals.push((n, seal.clone()));
            }
            SealAnswer::recorded()
        };
        if answer.state != SealState::Recorded {
            tracing::warn!(n, ?seal, ?answer, "a final seal that does not stand");
        }
        (!state.seal_answers_off).then_some(answer)
    }

    /// Refuse the next `count` `plan.get`s as Mend does while another launch holds the lease
    /// (409 `worktree-leased`, no epoch given).
    pub fn refuse_plans_leased(&self, count: usize) {
        self.lock().leased_plans = count;
    }

    /// Every `plan.get` this registrar was asked, oldest first.
    #[must_use]
    pub fn plan_requests(&self) -> Vec<PlanGetRequest> {
        self.lock().plan_requests.clone()
    }

    /// Answer `manifest_features` on `plan.get` (default: every one this build reads): a
    /// registrar that leaves one out stands for one that does not read it.
    #[must_use]
    pub fn with_manifest_features(mut self, features: &[&str]) -> Self {
        self.manifest_features = features.iter().map(|f| (*f).to_owned()).collect();
        self
    }

    /// Answer `manifest_format` on `plan.get` (default: the highest this build reads). At 1 the
    /// registrar stands for one that does not read dir packs.
    #[must_use]
    pub fn with_manifest_format(mut self, manifest_format: u32) -> Self {
        self.manifest_format = manifest_format;
        self
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

    /// Refuse past `limit` bytes. Keys are priced once, from the `sizes` of `upload.urls`
    /// (refused there, before a URL is minted) and — for a key a register names that was never
    /// sized — from `store`, standing in for the bucket's report (refused at the register).
    #[must_use]
    pub fn with_byte_quota(
        self,
        limit: u64,
        store: Option<Arc<dyn crate::sink::BlobSink>>,
    ) -> Self {
        self.set_byte_quota(Some(limit), store);
        self
    }

    /// Change (or lift) the byte budget.
    pub fn set_byte_quota(
        &self,
        limit: Option<u64>,
        store: Option<Arc<dyn crate::sink::BlobSink>>,
    ) {
        *self
            .quota
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            limit.map(|limit| ByteQuota { limit, store });
    }

    /// Bytes priced against the session so far.
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.lock().priced.values().sum()
    }

    /// Every size an `upload.urls` call declared, by key.
    #[must_use]
    pub fn sizes_seen(&self) -> BTreeMap<String, u64> {
        self.lock().sizes_seen.clone()
    }

    /// Price `keys` (each at most once) and refuse the lot when the budget cannot take them.
    fn price(
        &self,
        state: &mut InMemoryState,
        keys: impl IntoIterator<Item = (String, u64)>,
    ) -> Result<(), RegistrarError> {
        let new: Vec<(String, u64)> = keys
            .into_iter()
            .filter(|(k, _)| !state.priced.contains_key(k))
            .collect();
        let guard = self
            .quota
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(quota) = guard.as_ref() {
            let used: u64 = state.priced.values().sum();
            let requested: u64 = new.iter().map(|(_, b)| *b).sum();
            if used.saturating_add(requested) > quota.limit {
                return Err(RegistrarError::QuotaRefused {
                    reason: "byte-quota".to_owned(),
                    limit: Some(quota.limit),
                    used: Some(used),
                    requested: Some(requested),
                });
            }
        }
        drop(guard);
        state.priced.extend(new);
        Ok(())
    }

    /// The size a register-time price uses for `key`: what the store holds, when it is there.
    fn stored_size(&self, key: &str) -> Option<u64> {
        let guard = self
            .quota
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let store = guard.as_ref()?.store.as_ref()?;
        store.get(key).ok().map(|b| b.len() as u64)
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

    /// What `plan.get` answers as content beside the worktree.
    pub fn set_sources(&self, sources: Vec<PlanSource>) {
        self.lock().sources = sources;
    }

    /// What `plan.get` answers as the remotes of the worktree's repository.
    pub fn set_remotes(&self, remotes: Vec<PlanRemote>) {
        self.lock().remotes = remotes;
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

/// Every store key a register names: git packs (and their indexes), the workspace and bulk tree
/// roots (format 1) or dir packs (format 2) and packs, and the manifest itself.
fn manifest_keys(req: &RegisterRequest) -> Vec<String> {
    let s = &req.manifest.sections;
    let mut keys: Vec<String> = s
        .git
        .packs
        .iter()
        .flat_map(|k| [k.clone(), format!("{k}.idx")])
        .collect();
    keys.extend(tree_keys(s.workspace.tree()));
    keys.extend(s.workspace.packs.iter().cloned());
    if let Some(bulk) = s.bulk.section() {
        keys.extend(tree_keys(bulk.tree()));
        keys.extend(bulk.packs.iter().cloned());
    }
    keys.push(req.manifest_key.clone());
    keys
}

impl Registrar for InMemoryRegistrar {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        let mut state = self.lock();
        state.plan_requests.push(req.clone());
        if state.leased_plans > 0 {
            state.leased_plans -= 1;
            return Err(RegistrarError::WorktreeLeased);
        }
        // Mend's launch gate (cross-repo decision 11): the token is scoped to `executor`, and a
        // request naming another launch is refused before anything is claimed.
        if let (Some(launch), Some(executor)) = (&req.launch, &self.executor)
            && launch != executor
        {
            return Err(RegistrarError::Protocol(format!(
                "plan.get refused: launch-mismatch (the token is launch {executor}; the executor \
                 says it is {launch})"
            )));
        }
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
        // Another platform's dependency tree is not this executor's to restore; one captured
        // on this executor's platform and carried in `other_bulk` is.
        if let (Some(h), Some(platform)) = (head.as_mut(), &req.platform) {
            let sections = &mut h.manifest.sections;
            if sections
                .bulk
                .section()
                .is_none_or(|b| b.platform != *platform)
            {
                sections.bulk = sections
                    .other_bulk
                    .get(platform)
                    .cloned()
                    .map_or(BulkState::pending(), BulkState::Ready);
            }
        }
        // Mend's reader gate: a plan holding a section format above what the executor reads
        // (its workspace section and the bulk section answered to it) is refused before the
        // claim, and the executor is told to write no higher.
        let reads = req.manifest_format.unwrap_or(FORMAT_DIR_OBJECTS);
        if let Some(holds) = head.as_ref().map(|h| plan_format(&h.manifest))
            && holds > reads
        {
            return Err(RegistrarError::Protocol(format!(
                "plan.get refused: manifest-format (the head holds format {holds}; the executor reads {reads})"
            )));
        }
        // Mend's feature gate, before the claim: a head holding a manifest feature the
        // executor does not say it reads (raw names aside: this double does not walk dir
        // objects).
        if let (Some(planned), Some(stored)) = (&head, state.chain.last()) {
            let missing = missing_manifest_features(
                &stored.manifest,
                &planned.manifest,
                req.platform.as_deref(),
                req.manifest_features.as_deref().unwrap_or_default(),
                false,
            );
            if !missing.is_empty() {
                return Err(RegistrarError::Protocol(format!(
                    "plan.get refused: manifest-features (the head holds {})",
                    missing.join(", ")
                )));
            }
        }
        let mut get_urls = BTreeMap::new();
        if let (Some(h), Some(_)) = (&head, &self.url_base) {
            let s = &h.manifest.sections;
            let bulk_packs: Vec<String> = s
                .bulk
                .section()
                .map(|b| b.packs.iter().chain(&b.dir_packs).cloned().collect())
                .unwrap_or_default();
            let keys = s
                .git
                .packs
                .iter()
                .flat_map(|k| [k.clone(), format!("{k}.idx")])
                .chain(s.workspace.packs.iter().cloned())
                .chain(s.workspace.dir_packs.iter().cloned())
                .chain(bulk_packs)
                .chain([h.manifest_key.clone()]);
            for k in keys {
                get_urls.insert(k.clone(), self.url(&k));
            }
        }
        let sources = state.sources.clone();
        if self.url_base.is_some() {
            for source in &sources {
                get_urls.insert(source.key.clone(), self.url(&source.key));
            }
        }
        Ok(PlanGetResponse {
            worktree_id,
            epoch: state.live_epoch,
            head,
            get_urls,
            sources,
            remotes: state.remotes.clone(),
            manifest_format: self.manifest_format.min(reads),
            manifest_features: self.manifest_features.clone(),
            executor: self.executor.clone(),
        })
    }

    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        let mut state = self.lock();
        Self::check_epoch(&state, req.epoch)?;
        if !state.lease_alive {
            return Err(RegistrarError::LeaseLost);
        }
        state.url_requests += 1;
        state.sizes_seen.extend(req.sizes.clone());
        let prefix = format!("captures/{}/{}/", req.worktree_id, req.epoch);
        // Priced before anything is minted: a refused batch leaves no URL behind.
        let sized: Vec<(String, u64)> = req
            .keys
            .iter()
            .filter(|k| k.starts_with(&prefix))
            .filter_map(|k| req.sizes.get(k).map(|b| (k.clone(), *b)))
            .collect();
        self.price(&mut state, sized)?;
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
        Ok(UploadUrlsResponse {
            urls,
            multipart,
            present: Vec::new(),
        })
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
        // Mend's lease predicate: the lease must be live to register (409 `lease-lost`).
        if !state.lease_alive {
            return Err(RegistrarError::LeaseLost);
        }
        // The backstop: keys this capture names that no `upload.urls` call ever sized are priced
        // here, from what the store holds.
        let unsized_keys: Vec<(String, u64)> = manifest_keys(req)
            .into_iter()
            .filter(|k| !state.priced.contains_key(k))
            .filter_map(|k| self.stored_size(&k).map(|b| (k, b)))
            .collect();
        self.price(&mut state, unsized_keys)?;
        let head = state.chain.last();
        // Lost ack: the chain is already at n with this id — and where its seal stands now.
        if let Some(h) = head
            && h.n == req.n
            && h.capture_id == req.capture_id
        {
            let (head_n, head_capture_id) = (h.n, h.capture_id.clone());
            let seal = h.manifest.final_seal.clone();
            let registered_epoch = h.manifest.epoch;
            let seal =
                seal.and_then(|seal| self.answer_seal(&mut state, head_n, registered_epoch, &seal));
            return Ok(RegisterResponse {
                head_n,
                head_capture_id,
                seal,
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
        // The seal is recorded with the CAS, only when it holds (Mend's register), and the
        // answer says where it stands (decision 22).
        let seal = req
            .manifest
            .final_seal
            .as_ref()
            .and_then(|seal| self.answer_seal(&mut state, req.n, req.epoch, seal));
        state.chain.push(HeadInfo {
            n: req.n,
            capture_id: req.capture_id.clone(),
            manifest_key: req.manifest_key.clone(),
            manifest: req.manifest.clone(),
        });
        Ok(RegisterResponse {
            head_n: req.n,
            head_capture_id: req.capture_id.clone(),
            seal,
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
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    used: Option<u64>,
    #[serde(default)]
    requested: Option<u64>,
    /// 422 on `capture.register`: the keys the registrar found missing.
    #[serde(default)]
    missing: Vec<String>,
    #[serde(default)]
    message: String,
}

impl ConflictBody {
    fn empty() -> Self {
        Self {
            reason: String::new(),
            live_epoch: None,
            head_n: None,
            head_capture_id: None,
            key: None,
            limit: None,
            used: None,
            requested: None,
            missing: Vec::new(),
            message: String::new(),
        }
    }

    fn quota_refused(self) -> RegistrarError {
        RegistrarError::QuotaRefused {
            reason: if self.reason.is_empty() {
                "byte-quota".to_owned()
            } else {
                self.reason
            },
            limit: self.limit,
            used: self.used,
            requested: self.requested,
        }
    }
}

impl HttpRegistrar {
    /// `endpoint` is `SEALANT_CAPTURE_ENDPOINT`, `token` is `SEALANT_CAPTURE_TOKEN`. The
    /// endpoint is checked against `transport` here, before the token is ever sent: plain HTTP
    /// beyond loopback is refused unless the launcher allowed it, certificates are always
    /// verified, and no redirect is followed (a 3xx answers as a protocol error).
    ///
    /// # Errors
    /// [`TransportError`] when the endpoint is not one `transport` dials.
    pub fn new(
        endpoint: &str,
        token: &str,
        timeout: Duration,
        transport: &ChannelTransport,
    ) -> Result<Self, TransportError> {
        let endpoint = endpoint.trim().trim_end_matches('/');
        transport.check("the session channel (SEALANT_CAPTURE_ENDPOINT)", endpoint)?;
        Ok(Self {
            agent: transport.channel_agent(timeout),
            endpoint: endpoint.to_owned(),
            token: token.to_owned(),
        })
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
            s => Err(refusal(name, s, &bytes, epoch)),
        }
    }
}

/// The error a non-2xx answer of `name` is, for a caller at `epoch`.
fn refusal(name: &str, status: u16, bytes: &[u8], epoch: u64) -> RegistrarError {
    match status {
        409 => {
            let c: ConflictBody =
                serde_json::from_slice(bytes).unwrap_or_else(|_| ConflictBody::empty());
            if c.reason == "worktree-leased" {
                // Another launch holds the lease: no epoch is this executor's, whatever a
                // `live_epoch` says (it is the holder's, never one to adopt).
                RegistrarError::WorktreeLeased
            } else if let Some(live) = c.live_epoch.filter(|l| *l != epoch) {
                RegistrarError::Fenced { epoch, live }
            } else if c.reason == "stale-epoch" {
                RegistrarError::Fenced { epoch, live: 0 }
            } else if c.reason == "lease-lost" {
                // The lease is not live (released, lapsed, or a standby not claimed yet),
                // and no other epoch holds the worktree: nothing about the chain is wrong.
                // Before, this read as a wrong parent — a chain conflict, which ends a
                // final flush with everything still staged.
                RegistrarError::LeaseLost
            } else if c.reason == "byte-quota" {
                // The bytes, not the chain: no parent to fix, nothing a retry can change.
                c.quota_refused()
            } else if c.reason == "manifest-format" {
                // The head holds a section this build does not read: nothing to retry.
                RegistrarError::Protocol(format!("{name} refused: manifest-format"))
            } else if c.reason == "manifest-features" {
                // The head holds manifest features this build does not say it reads: nothing
                // to retry; a sealantd that reads them must restore it.
                RegistrarError::Protocol(format!(
                    "{name} refused: manifest-features (the head holds {}; this sealantd reads {})",
                    if c.missing.is_empty() {
                        "features it does not name".to_owned()
                    } else {
                        c.missing.join(", ")
                    },
                    MANIFEST_FEATURES.join(", ")
                ))
            } else if name == "change.summary" {
                RegistrarError::SummaryRefused(c.reason)
            } else if name == "upload.complete" {
                if c.reason == "exists" {
                    RegistrarError::KeyExists {
                        key: c.key.unwrap_or_default(),
                    }
                } else {
                    RegistrarError::Protocol(format!("upload.complete refused: {}", c.reason))
                }
            } else {
                RegistrarError::WrongParent {
                    head_n: c.head_n.unwrap_or(0),
                    head_capture_id: c.head_capture_id.unwrap_or_default(),
                }
            }
        }
        413 => serde_json::from_slice::<ConflictBody>(bytes)
            .unwrap_or_else(|_| ConflictBody::empty())
            .quota_refused(),
        422 if name == "capture.register" => {
            let c: ConflictBody =
                serde_json::from_slice(bytes).unwrap_or_else(|_| ConflictBody::empty());
            if c.reason == "missing-objects" || c.reason == "unrestorable" {
                RegistrarError::RegisterRefused {
                    reason: c.reason,
                    missing: c.missing,
                    message: c.message,
                }
            } else {
                RegistrarError::Protocol(format!("{name}: http 422 {}", c.reason))
            }
        }
        404 if name == "lease.heartbeat" => RegistrarError::LeaseLost,
        s if s >= 500 || s == 429 || s == 408 => {
            RegistrarError::Transport(format!("{name}: http {s}"))
        }
        s => RegistrarError::Protocol(format!("{name}: http {s}")),
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

/// A [`crate::sink::UrlMinter`] over a registrar: PUT and part URLs come from `upload.urls`
/// (a batch at a time through [`Self::prefetch_put`], one key on a cache miss), multipart
/// completes go to `upload.complete`, GET URLs come from the plan. A re-plan
/// ([`Self::reset`]) moves it to the new identity and the new plan's GET URLs.
#[derive(Debug)]
pub struct RegistrarMinter<R: Registrar + ?Sized> {
    registrar: std::sync::Arc<R>,
    identity: Mutex<(String, u64)>,
    /// PUT URLs minted and not settled yet ([`crate::sink::UrlMinter::settled`]), with when
    /// they were minted: a PUT that failed on the store's side retries on the same URL.
    put_cache: Mutex<BTreeMap<String, (String, std::time::Instant)>>,
    /// Multipart uploads created and not settled yet, with when: a multipart upload that failed
    /// on the store's side resumes under the same upload and part URLs.
    multipart_cache: Mutex<BTreeMap<String, (MultipartUrls, std::time::Instant)>>,
    /// Keys `upload.urls` answered `present` (the bucket holds them, verified) and whose upload
    /// has not settled yet: nothing is PUT for them ([`crate::sink::PutTarget::Present`]).
    present: Mutex<BTreeSet<String>>,
    get_urls: Mutex<BTreeMap<String, String>>,
}

/// How long a minted PUT URL is used before it is minted again. The registrar chooses the
/// URL's lifetime (Mend presigns for 15 minutes); this stays well inside any sane one. A bulk
/// upload that stops mid-batch for a capture staged ahead of it resumes on the URLs it holds
/// instead of spending another `upload.urls` call on them.
pub const PUT_URL_REUSE: std::time::Duration = std::time::Duration::from_secs(5 * 60);

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
            multipart_cache: Mutex::new(BTreeMap::new()),
            present: Mutex::new(BTreeSet::new()),
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
        self.multipart_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.present
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        *self
            .get_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = get_urls;
    }

    /// Pre-mint PUT URLs for a batch of `(key, bytes)` (one channel call). Every key travels
    /// with its size, so the registrar can price the whole batch before it mints anything. Keys
    /// that already hold a URL minted within [`PUT_URL_REUSE`] are not asked for again; when
    /// every key does, no call is made.
    pub fn prefetch_put(&self, keys: &[(String, u64)]) -> Result<(), RegistrarError> {
        let wanted: Vec<(String, u64)> = {
            let mut cache = self
                .put_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.retain(|_, (_, at)| at.elapsed() < PUT_URL_REUSE);
            let present = self
                .present
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            keys.iter()
                .filter(|(k, _)| !cache.contains_key(k) && !present.contains(k))
                .cloned()
                .collect()
        };
        if wanted.is_empty() {
            return Ok(());
        }
        let (worktree_id, epoch) = self.identity();
        let mut req = UploadUrlsRequest::new(
            &worktree_id,
            epoch,
            wanted.iter().map(|(k, _)| k.clone()).collect(),
        );
        req.sizes = wanted.into_iter().collect();
        let resp = self.registrar.upload_urls(&req)?;
        self.note_present(&req.keys, resp.present);
        self.cache_puts(resp.urls);
        Ok(())
    }

    /// Record the keys of `asked` the registrar answered `present`. A key it names that was not
    /// asked for is ignored: `present` vouches only for what this call asked about.
    fn note_present(&self, asked: &[String], present: Vec<String>) {
        if present.is_empty() {
            return;
        }
        let asked: BTreeSet<&String> = asked.iter().collect();
        let mut known = self
            .present
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in present {
            if asked.contains(&key) {
                known.insert(key);
            } else {
                tracing::warn!(%key, "upload.urls answered present a key it was not asked for; ignored");
            }
        }
    }

    fn is_present(&self, key: &str) -> bool {
        self.present
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(key)
    }

    /// Where `key`'s bytes go: a fresh cached PUT URL, nowhere when the bucket holds the key
    /// (`present`), else one more `upload.urls` for it. `None` when that call answered the key
    /// in neither.
    fn target(&self, key: &str) -> Option<crate::sink::PutTarget> {
        if let Some(url) = self.take_put(key) {
            return Some(crate::sink::PutTarget::Url(url));
        }
        self.is_present(key)
            .then_some(crate::sink::PutTarget::Present)
    }

    fn cache_puts(&self, urls: BTreeMap<String, String>) {
        let now = std::time::Instant::now();
        self.put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(urls.into_iter().map(|(k, u)| (k, (u, now))));
    }

    /// The cached PUT URL for `key`, when it is fresh. It stays cached until the upload of
    /// `key` settles ([`crate::sink::UrlMinter::settled`]): before, it was taken out on first
    /// use, and every retry of a PUT the store refused for now minted another — a store that
    /// stayed down spent the registrar's `upload.urls` call quota (Docker end to end, round 5).
    fn take_put(&self, key: &str) -> Option<String> {
        let mut cache = self
            .put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match cache.get(key) {
            Some((url, at)) if at.elapsed() < PUT_URL_REUSE => Some(url.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }
}

impl<R: Registrar + ?Sized> crate::sink::UrlMinter for RegistrarMinter<R> {
    fn prefetch_put(&self, keys: &[(String, u64)]) -> Result<(), crate::sink::SinkError> {
        Self::prefetch_put(self, keys).map_err(|e| mint_error(&keys_label(keys), e))
    }

    fn put_url(&self, key: &str, size: u64) -> Result<String, crate::sink::SinkError> {
        match self.put_target(key, size)? {
            crate::sink::PutTarget::Url(url) => Ok(url),
            crate::sink::PutTarget::Present => Err(crate::sink::SinkError::NoUrl {
                key: key.to_owned(),
                reason: "the bucket holds this key already (upload.urls answered it present)"
                    .to_owned(),
            }),
        }
    }

    fn put_target(
        &self,
        key: &str,
        size: u64,
    ) -> Result<crate::sink::PutTarget, crate::sink::SinkError> {
        if let Some(target) = self.target(key) {
            return Ok(target);
        }
        // The fallback for a key no batch minted, and it declares that key's real length: a
        // registrar may sign the URL for exactly those bytes (Mend's upload length binding), so
        // a stand-in size would mint a URL the PUT cannot use.
        Self::prefetch_put(self, &[(key.to_owned(), size)]).map_err(|e| mint_error(key, e))?;
        // Neither minted nor present: an error, never an upload taken as done.
        self.target(key)
            .ok_or_else(|| crate::sink::SinkError::NoUrl {
                key: key.to_owned(),
                reason: "the registrar answered upload.urls with neither a URL nor `present` \
                         for this key"
                    .to_owned(),
            })
    }

    fn settled(&self, key: &str) {
        self.present
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
        self.put_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
        self.multipart_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }

    fn get_url(&self, key: &str) -> Result<String, crate::sink::SinkError> {
        self.get_urls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
            .ok_or_else(|| crate::sink::SinkError::NoUrl {
                key: key.to_owned(),
                reason: "no GET url in plan".to_owned(),
            })
    }

    fn multipart_urls(
        &self,
        key: &str,
        size: u64,
    ) -> Result<Option<MultipartUrls>, crate::sink::SinkError> {
        // The bucket holds it: no upload to open (the single-PUT path answers it present).
        if self.is_present(key) {
            return Ok(None);
        }
        if let Some(plan) = self
            .multipart_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .filter(|(_, at)| at.elapsed() < PUT_URL_REUSE)
            .map(|(plan, _)| plan.clone())
        {
            return Ok(Some(plan));
        }
        let (worktree_id, epoch) = self.identity();
        let mut req = UploadUrlsRequest::new(&worktree_id, epoch, vec![key.to_owned()]);
        req.sizes.insert(key.to_owned(), size);
        let mut resp = self
            .registrar
            .upload_urls(&req)
            .map_err(|e| mint_error(key, e))?;
        self.note_present(&req.keys, std::mem::take(&mut resp.present));
        let multipart = resp.multipart.remove(key);
        if let Some(plan) = &multipart {
            self.multipart_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(key.to_owned(), (plan.clone(), std::time::Instant::now()));
        }
        // A registrar that answered with a plain PUT URL (below its threshold, or no multipart
        // support) has minted it now; keep it for the single-PUT fallback.
        self.cache_puts(resp.urls);
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
            Err(RegistrarError::LeaseLost) => Err(SinkError::LeaseLost {
                key: key.to_owned(),
            }),
            Err(e) => Err(SinkError::Multipart {
                key: key.to_owned(),
                reason: e.to_string(),
            }),
        }
    }
}

/// A quota refusal stays itself on the way to the sink (it holds the capture, with its numbers); a transient
/// failure of the call (transport, 5xx, the registrar's 429 call quota) stays retryable; anything
/// else is "no url for this key". A 429 used to become `NoUrl`, which the shipper does not retry,
/// so one throttled mint failed the whole pass as `no url for <key>: transport: upload.urls: http
/// 429`.
fn mint_error(key: &str, error: RegistrarError) -> crate::sink::SinkError {
    match error {
        RegistrarError::QuotaRefused {
            reason,
            limit,
            used,
            requested,
        } => crate::sink::SinkError::QuotaRefused {
            reason,
            limit,
            used,
            requested,
        },
        RegistrarError::Transport(reason) => crate::sink::SinkError::Transport {
            method: "upload.urls",
            key: key.to_owned(),
            reason,
        },
        // The lease is not live right now: the shipper pauses and asks again.
        RegistrarError::LeaseLost => crate::sink::SinkError::LeaseLost {
            key: key.to_owned(),
        },
        other => crate::sink::SinkError::NoUrl {
            key: key.to_owned(),
            reason: other.to_string(),
        },
    }
}

fn keys_label(keys: &[(String, u64)]) -> String {
    match keys.first() {
        Some((first, _)) => format!("{} keys from {first}", keys.len()),
        None => "no keys".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mend's `upload.urls` answer names the keys the bucket holds in `present` (decision 19);
    /// an older registrar's answer has none.
    #[test]
    fn upload_urls_answers_present_keys() {
        let resp: UploadUrlsResponse = serde_json::from_str(
            r#"{"urls":{"captures/wt/3/packs/a":"https://s/a"},"multipart":{},
                "present":["captures/wt/3/packs/b"]}"#,
        )
        .unwrap();
        assert_eq!(resp.present, vec!["captures/wt/3/packs/b".to_owned()]);
        let old: UploadUrlsResponse = serde_json::from_str(r#"{"urls":{}}"#).unwrap();
        assert!(old.present.is_empty());
        assert!(
            !serde_json::to_string(&old).unwrap().contains("present"),
            "an empty list is not sent"
        );
    }
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
                    symrefs: BTreeMap::new(),
                    worktree_tree: None,
                    index_tree: None,
                    raw_tree: None,
                    object_format: None,
                },
                workspace: WorkspaceSection::objects("r", vec![]),
                bulk: BulkState::pending(),
                other_bulk: BTreeMap::new(),
            },
            checkpoint: None,
            final_seal: None,
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
                manifest_format: Some(MAX_SECTION_FORMAT),
                manifest_features: None,
                launch: None,
                upload_answers: None,
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
            format: crate::manifest::FORMAT_DIR_OBJECTS,
            dir_packs: vec![],
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
                manifest_format: Some(MAX_SECTION_FORMAT),
                manifest_features: PlanGetRequest::booting(None).manifest_features,
                launch: None,
                upload_answers: None,
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
            manifest_format: None,
            manifest_features: None,
            launch: None,
            upload_answers: None,
        })
        .unwrap();
        assert!(bare.get("platform").is_none());
        let back: PlanGetRequest =
            serde_json::from_str(r#"{"worktree_id":null,"epoch":2}"#).unwrap();
        assert_eq!(back.platform, None);
    }

    /// Mend's 422 on `capture.register` (`missing-objects` with the keys, `unrestorable`) is a
    /// refusal of this capture, never a transport failure to retry as it is (it used to answer
    /// `protocol: capture.register: http 422`, retried every pass for good).
    #[test]
    fn a_422_register_refusal_names_the_missing_keys() {
        let body = br#"{"reason":"missing-objects","message":"1 pack(s) the manifest names are not in the bucket","missing":["captures/wt/1/packs/abc"]}"#;
        match refusal("capture.register", 422, body, 1) {
            RegistrarError::RegisterRefused {
                reason,
                missing,
                message,
            } => {
                assert_eq!(reason, "missing-objects");
                assert_eq!(missing, vec!["captures/wt/1/packs/abc".to_owned()]);
                assert!(message.contains("not in the bucket"));
            }
            other => panic!("{other:?}"),
        }
        let unrestorable = refusal(
            "capture.register",
            422,
            br#"{"reason":"unrestorable","message":"chunk c is in no listed pack"}"#,
            1,
        );
        assert!(
            matches!(&unrestorable, RegistrarError::RegisterRefused { reason, missing, .. }
                if reason == "unrestorable" && missing.is_empty()),
            "{unrestorable:?}"
        );
        assert!(!unrestorable.is_retryable());
        let other = refusal(
            "capture.register",
            422,
            br#"{"reason":"capture-id-mismatch"}"#,
            1,
        );
        assert!(matches!(other, RegistrarError::Protocol(_)), "{other:?}");
    }

    /// A booting executor says which section format it reads (`manifest_format` 2, the highest
    /// this build reads); a request without it is a format-1 reader. The test double answers as
    /// Mend does: never above what the executor reads, and a head it could not read is refused
    /// (409 `manifest-format`, never read as a chain conflict).
    #[test]
    fn plan_get_sends_the_manifest_format_it_reads() {
        assert_eq!(MAX_SECTION_FORMAT, 2);
        let booting = serde_json::to_value(PlanGetRequest::booting(None)).unwrap();
        assert_eq!(booting["manifest_format"], 2);
        let bare = PlanGetRequest {
            worktree_id: None,
            epoch: 0,
            platform: None,
            manifest_format: None,
            manifest_features: None,
            launch: None,
            upload_answers: None,
        };
        assert!(
            serde_json::to_value(&bare)
                .unwrap()
                .get("manifest_format")
                .is_none()
        );
        let back: PlanGetRequest =
            serde_json::from_str(r#"{"worktree_id":null,"epoch":2}"#).unwrap();
        assert_eq!(back.manifest_format, None);

        let r = InMemoryRegistrar::new("wt", 1, None);
        assert_eq!(r.plan_get(&bare).unwrap().manifest_format, 1);
        assert_eq!(
            r.plan_get(&PlanGetRequest::booting(None))
                .unwrap()
                .manifest_format,
            2
        );
        let mut m = manifest(0, None);
        m.sections.workspace.format = crate::manifest::FORMAT_DIR_PACKS;
        r.capture_register(&RegisterRequest {
            manifest: m,
            ..register(0, None, "a", 1)
        })
        .unwrap();
        let refused = r.plan_get(&bare).unwrap_err();
        assert!(refused.to_string().contains("manifest-format"), "{refused}");
        let plan = r.plan_get(&PlanGetRequest::booting(None)).unwrap();
        assert_eq!(plan.head.unwrap().capture_id, "a");

        let http = refusal("plan.get", 409, br#"{"reason":"manifest-format"}"#, 0);
        assert!(
            matches!(&http, RegistrarError::Protocol(m) if m.contains("manifest-format")),
            "{http:?}"
        );
    }

    /// A booting executor lists every manifest feature it reads (Mend's `manifest_features`,
    /// PLATFORM-FEEDBACK 2026-09-28); a request without the list reads none. The test double
    /// refuses, as Mend does, a head holding a feature the list leaves out — before the claim,
    /// naming the features — and answers the ones it reads; an HTTP 409 `manifest-features` is
    /// a protocol error naming what is missing, never a chain conflict.
    #[test]
    fn plan_get_lists_the_manifest_features_it_reads() {
        let booting = serde_json::to_value(PlanGetRequest::booting(None)).unwrap();
        assert_eq!(
            booting["manifest_features"],
            serde_json::json!([
                "worktree_meta",
                "symrefs",
                "other_bulk",
                "raw_names",
                "final_seal",
                "git_trees",
                "object_format"
            ])
        );
        let bare = PlanGetRequest {
            worktree_id: None,
            epoch: 0,
            platform: None,
            manifest_format: Some(MAX_SECTION_FORMAT),
            manifest_features: None,
            launch: None,
            upload_answers: None,
        };
        assert!(
            serde_json::to_value(&bare)
                .unwrap()
                .get("manifest_features")
                .is_none()
        );

        let r = InMemoryRegistrar::new("wt", 1, None).with_executor("exec-1");
        // A head holding no feature is handed to any executor.
        r.capture_register(&register(0, None, "a", 1)).unwrap();
        let plan = r.plan_get(&bare).unwrap();
        assert_eq!(plan.head.unwrap().capture_id, "a");
        assert_eq!(plan.manifest_features.len(), MANIFEST_FEATURES.len());
        assert_eq!(plan.executor.as_deref(), Some("exec-1"));
        // One holding a seal and a symbolic ref is not, and says which.
        let mut m = manifest(1, Some("a"));
        m.sections.git.symrefs.insert(
            "refs/remotes/origin/HEAD".into(),
            "refs/remotes/origin/main".into(),
        );
        m.final_seal = Some(FinalSeal {
            complete: true,
            epoch: 1,
            executor: "exec-1".into(),
            boot_id: None,
            boot_generation: None,
            observation: None,
        });
        r.capture_register(&RegisterRequest {
            manifest: m,
            ..register(1, Some("a"), "b", 1)
        })
        .unwrap();
        assert_eq!(r.seals().len(), 1, "the seal is recorded with the CAS");
        let refused = r.plan_get(&bare).unwrap_err();
        let text = refused.to_string();
        assert!(
            text.contains("manifest-features") && text.contains("symrefs, final_seal"),
            "{text}"
        );
        let only_some = PlanGetRequest {
            manifest_features: Some(vec!["symrefs".into()]),
            launch: None,
            ..bare.clone()
        };
        let text = r.plan_get(&only_some).unwrap_err().to_string();
        assert!(text.contains("(the head holds final_seal)"), "{text}");
        let plan = r.plan_get(&PlanGetRequest::booting(None)).unwrap();
        assert_eq!(plan.head.unwrap().capture_id, "b");

        let http = refusal(
            "plan.get",
            409,
            br#"{"reason":"manifest-features","message":"refused","missing":["final_seal"]}"#,
            0,
        );
        assert!(
            matches!(&http, RegistrarError::Protocol(m)
                if m.contains("manifest-features") && m.contains("the head holds final_seal")),
            "{http:?}"
        );
        assert!(!http.is_retryable());
    }

    /// The feature rules, one by one (Mend's `missingManifestFeatures`).
    #[test]
    fn manifest_features_are_held_as_mend_decides_them() {
        let none: Vec<String> = Vec::new();
        let plain = manifest(0, None);
        assert!(missing_manifest_features(&plain, &plain, None, &none, false).is_empty());
        assert_eq!(
            missing_manifest_features(&plain, &plain, None, &none, true),
            vec!["raw_names"]
        );
        // A ready bulk section of another platform than the request names: the executor must
        // carry it into `other_bulk`.
        let mut stored = manifest(0, None);
        stored.sections.bulk = BulkState::Ready(crate::manifest::BulkSection {
            root: "r".into(),
            packs: vec![],
            platform: "linux-aarch64-gnu".into(),
            format: FORMAT_DIR_OBJECTS,
            dir_packs: vec![],
        });
        assert_eq!(
            missing_manifest_features(&stored, &plain, Some("linux-x86_64-gnu"), &none, false),
            vec!["other_bulk"]
        );
        assert!(
            missing_manifest_features(&stored, &plain, Some("linux-aarch64-gnu"), &none, false)
                .is_empty()
        );
        // Trees in their own fields: an executor that does not read them would take a user ref
        // for the worktree tree, or restore no tree at all.
        let mut trees = manifest(0, None);
        trees.sections.git.worktree_tree = Some("t".into());
        assert_eq!(
            missing_manifest_features(&trees, &trees, None, &none, false),
            vec!["git_trees"]
        );
        let all: Vec<String> = MANIFEST_FEATURES.iter().map(|f| (*f).to_owned()).collect();
        assert!(missing_manifest_features(&stored, &plain, Some("x"), &all, true).is_empty());
        assert!(missing_manifest_features(&trees, &trees, None, &all, false).is_empty());
    }

    /// Every key of a prefetch batch travels with its size (not only multipart candidates), so
    /// the registrar can price the batch before it mints; a batch past the budget is refused
    /// whole, with the numbers, and nothing is minted.
    #[test]
    fn prefetch_sizes_every_key_and_a_batch_past_the_budget_is_refused() {
        use crate::sink::UrlMinter;

        let r = Arc::new(InMemoryRegistrar::new("wt", 1, Some("http://x".into())));
        let keys: Vec<(String, u64)> = (0..3)
            .map(|i| (format!("captures/wt/1/trees/{i}"), 100 + i))
            .collect();
        let minter = RegistrarMinter::new(
            Arc::clone(&r) as Arc<dyn Registrar>,
            "wt",
            1,
            BTreeMap::new(),
        );
        UrlMinter::prefetch_put(&minter, &keys).unwrap();
        assert_eq!(
            r.sizes_seen(),
            keys.iter().cloned().collect::<BTreeMap<_, _>>(),
            "every key in the batch was sized"
        );
        assert_eq!(
            minter.put_url(&keys[0].0, keys[0].1).unwrap(),
            format!("http://x/{}", keys[0].0)
        );
        assert_eq!(r.used_bytes(), 303);

        // A key no batch minted falls back to a one-key call, and that call declares the
        // object's real length — never a zero stand-in, which a registrar that binds the
        // signature to the content length would mint an unusable URL for.
        let missed = "captures/wt/1/trees/missed".to_owned();
        assert_eq!(
            minter.put_url(&missed, 64).unwrap(),
            format!("http://x/{missed}")
        );
        assert_eq!(r.sizes_seen().get(&missed).copied(), Some(64));
        assert_eq!(r.used_bytes(), 367);

        // 367 bytes are priced; 100 more is one too many, and a priced key costs nothing again.
        r.set_byte_quota(Some(466), None);
        let more = [("captures/wt/1/trees/new".to_owned(), 100)];
        let err = UrlMinter::prefetch_put(&minter, &more).unwrap_err();
        assert!(
            matches!(
                &err,
                crate::sink::SinkError::QuotaRefused { reason, limit, used, requested }
                    if reason == "byte-quota"
                        && *limit == Some(466)
                        && *used == Some(367)
                        && *requested == Some(100)
            ),
            "{err}"
        );
        assert!(!err.is_retryable());
        assert_eq!(r.used_bytes(), 367, "a refused batch prices nothing");
        UrlMinter::prefetch_put(&minter, &keys).expect("priced keys cost nothing again");
    }

    /// A 409 `lease-lost` is a lost lease — pause and ask again — not a wrong parent, which
    /// the shipper reads as a chain conflict and a final flush stops on. With a `live_epoch`
    /// other than the caller's it is a fence, as before; the other refusals keep their reading.
    #[test]
    fn a_409_lease_lost_is_a_lost_lease_not_a_conflict() {
        for name in [
            "capture.register",
            "upload.urls",
            "upload.complete",
            "lease.heartbeat",
        ] {
            assert_eq!(
                refusal(name, 409, br#"{"reason":"lease-lost","message":"m"}"#, 3),
                RegistrarError::LeaseLost,
                "{name}"
            );
            assert_eq!(
                refusal(name, 409, br#"{"reason":"lease-lost","live_epoch":3}"#, 3),
                RegistrarError::LeaseLost,
                "{name}: the caller's own epoch is not a fence"
            );
            assert_eq!(
                refusal(name, 409, br#"{"reason":"lease-lost","live_epoch":4}"#, 3),
                RegistrarError::Fenced { epoch: 3, live: 4 },
                "{name}"
            );
        }
        assert_eq!(
            refusal("lease.heartbeat", 404, b"", 3),
            RegistrarError::LeaseLost
        );
        assert_eq!(
            refusal(
                "lease.heartbeat",
                404,
                br#"{"reason":"lease-lost","message":"m"}"#,
                3
            ),
            RegistrarError::LeaseLost
        );
        // Mend round 4: another launch holds the worktree. No epoch is given — not even the
        // holder's `live_epoch`, which is never one to adopt (nor a fence of this executor).
        for body in [
            &br#"{"reason":"worktree-leased","message":"m"}"#[..],
            br#"{"reason":"worktree-leased","live_epoch":7}"#,
        ] {
            assert_eq!(
                refusal("plan.get", 409, body, 0),
                RegistrarError::WorktreeLeased
            );
        }
        assert!(matches!(
            refusal(
                "capture.register",
                409,
                br#"{"reason":"wrong-parent","head_n":4,"head_capture_id":"h"}"#,
                3
            ),
            RegistrarError::WrongParent { head_n: 4, .. }
        ));
        assert!(matches!(
            refusal("capture.register", 409, br#"{"reason":"byte-quota"}"#, 3),
            RegistrarError::QuotaRefused { .. }
        ));
        // Through the minter it stays a lost lease, which the shipper pauses on.
        assert!(matches!(
            mint_error("captures/wt/3/packs/p", RegistrarError::LeaseLost),
            crate::sink::SinkError::LeaseLost { .. }
        ));
    }

    /// The double answers `plan.get` for a platform from `other_bulk` when the head's own bulk
    /// section was captured elsewhere, and `"pending"` when it holds none for it.
    #[test]
    fn plan_get_answers_a_carried_bulk_section_for_its_platform() {
        let r = InMemoryRegistrar::new("wt", 1, Some("http://x".into()));
        let section = |platform: &str, root: &str| BulkSection {
            root: root.into(),
            packs: vec![format!("captures/wt/1/packs/{root}")],
            platform: platform.into(),
            format: crate::manifest::FORMAT_DIR_OBJECTS,
            dir_packs: vec![],
        };
        let mut req = register(0, None, "a", 1);
        req.manifest.sections.bulk = BulkState::Ready(section("linux-x86_64-gnu", "x86"));
        req.manifest.sections.other_bulk.insert(
            "linux-aarch64-gnu".into(),
            section("linux-aarch64-gnu", "arm"),
        );
        r.capture_register(&req).unwrap();
        let plan = |platform: &str| {
            r.plan_get(&PlanGetRequest {
                worktree_id: None,
                epoch: 0,
                platform: Some(platform.into()),
                manifest_format: Some(MAX_SECTION_FORMAT),
                manifest_features: PlanGetRequest::booting(None).manifest_features,
                launch: None,
                upload_answers: None,
            })
            .unwrap()
        };
        let arm = plan("linux-aarch64-gnu");
        let bulk = arm.head.unwrap().manifest.sections.bulk;
        assert_eq!(bulk.section().unwrap().root, "arm");
        assert!(arm.get_urls.contains_key("captures/wt/1/packs/arm"));
        assert!(!arm.get_urls.contains_key("captures/wt/1/packs/x86"));
        let x86 = plan("linux-x86_64-gnu")
            .head
            .unwrap()
            .manifest
            .sections
            .bulk;
        assert_eq!(x86.section().unwrap().root, "x86");
        let riscv = plan("linux-riscv64-musl")
            .head
            .unwrap()
            .manifest
            .sections
            .bulk;
        assert_eq!(riscv, BulkState::pending());
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
