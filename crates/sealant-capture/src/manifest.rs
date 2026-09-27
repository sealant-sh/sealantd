//! The capture manifest (ADR-0015 *Manifest*): JSON, written last, one PUT. The capture id is the
//! sha256 of the manifest bytes; the manifest does not carry its own id (amendment decision 1).
//!
//! Serialization is deterministic: struct field order is fixed, `refs` is a `BTreeMap`, and the
//! encoding is compact JSON, so a lost-ack retry re-registers the same id from identical bytes.
//!
//! Layout conventions this crate adds on top of the ADR fields:
//!
//! - `sections.git.refs` carries two pseudo-refs beside the repository's refs:
//!   [`WORKTREE_TREE_REF`] (a tree object of the working tree at snap time: tracked files with
//!   their uncommitted edits plus untracked, non-ignored files) and [`INDEX_TREE_REF`] (the tree
//!   written from the index). Both are pack closure tips; the materializer never writes them to
//!   `packed-refs`.
//! - The workspace dir object's root has three children: `.git/` (the repository's bookkeeping
//!   minus objects, refs, `HEAD` and `packed-refs`), `tree/` (git-ignored files and nested
//!   repositories under the worktree that are not bulk) and `harness/` (the harness home).
//! - The bulk dir object's root is the worktree root restricted to bulk directories.
//!
//! The chunked sections are versioned one by one (`format`), because a manifest can carry one
//! of each: a capture staged by this build over a head an older executor or the control plane
//! wrote keeps that head's bulk section as it is.
//!
//! - Format 1 ([`FORMAT_DIR_OBJECTS`], `format` absent): every dir object is its own object at
//!   `…/trees/<sha256>`; `root` and every `child` are those keys.
//! - Format 2 ([`FORMAT_DIR_PACKS`]): dir objects travel in dir packs — the CDC pack container
//!   ([`crate::pack`]), one zstd entry per dir object, the entry hash being the dir object's
//!   sha256 — keyed `…/packs/<sha256>` like any pack and listed in `dir_packs`. `root` and every
//!   `child` are dir object digests, so a dir object's bytes do not depend on where it is
//!   stored, and a reader resolves a digest through the listed packs' trailing indexes.
//!
//! The git section can carry `symrefs` (symbolic refs other than `HEAD`, name → target; each is
//! in `refs` too, by the sha it resolved to). The workspace section can carry `worktree_meta` ([`WorktreeMeta`]): the worktree metadata
//! overlay (modes, nanosecond mtimes, untracked directories and hardlink groups of the working
//! tree the worktree pseudo-ref describes), a JSON document chunked into the section's own packs.
//! Absent in every capture before it, and then restored as git checks the tree out.
//!
//! The engine writes format 2 only for a registrar whose `plan.get` announces
//! `manifest_format` ≥ 2 ([`DirFormat::for_registrar`]); a reader refuses a section whose format
//! is above [`MAX_SECTION_FORMAT`].

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chunk::{ChunkId, sha256_hex};

/// Pseudo-ref naming the working-tree tree object in `sections.git.refs`.
pub const WORKTREE_TREE_REF: &str = "refs/sealant/capture/worktree";
/// Pseudo-ref naming the index tree object in `sections.git.refs`.
pub const INDEX_TREE_REF: &str = "refs/sealant/capture/index";
/// Prefix of every pseudo-ref the materializer must not write to `packed-refs`.
pub const PSEUDO_REF_PREFIX: &str = "refs/sealant/capture/";

/// Why a capture was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureKind {
    /// Cadence-driven.
    Auto,
    /// Agent turn boundary.
    Turn,
    /// Explicit checkpoint.
    Checkpoint,
    /// Suspend hook.
    Suspend,
    /// Session end.
    Final,
}

impl CaptureKind {
    /// The `kind` string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Turn => "turn",
            Self::Checkpoint => "checkpoint",
            Self::Suspend => "suspend",
            Self::Final => "final",
        }
    }

    /// Parse a `kind` string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "turn" => Some(Self::Turn),
            "checkpoint" => Some(Self::Checkpoint),
            "suspend" => Some(Self::Suspend),
            "final" => Some(Self::Final),
            _ => None,
        }
    }
}

/// `git fsck --connectivity-only` outcome for the git section (amendment decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsckStatus {
    /// The packed closure verified.
    Verified,
    /// fsck reported a problem.
    Failed,
    /// Retries were exhausted; shipped without verification.
    Unverified,
}

/// The git section: self-contained packs plus refs and `HEAD`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSection {
    /// Every git pack key the section needs, across epochs.
    pub packs: Vec<String>,
    /// Ref name → sha, including the pseudo-refs. Each name is a [`crate::tree::key_of`] key of
    /// the ref's bytes (the name itself unless it is not UTF-8), written back as
    /// [`crate::tree::bytes_of`] — two names that differ only in bytes that are not UTF-8 stay
    /// two refs.
    pub refs: BTreeMap<String, String>,
    /// `HEAD`: a ref name (a key, as in `refs`) or a sha.
    pub head: String,
    /// fsck outcome.
    pub fsck: FsckStatus,
    /// Symbolic refs other than `HEAD` (`refs/remotes/origin/HEAD` → `refs/remotes/origin/main`):
    /// name → the ref it points at, both keys as in `refs`. Each whose target resolves is in
    /// `refs` as well, by the sha it resolved to, so a reader that knows only `refs` reads what
    /// it always did; a dangling one (its target does not exist) is here only. Absent when
    /// empty, so a manifest without one encodes exactly as before.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub symrefs: BTreeMap<String, String>,
}

/// Section format 1: every dir object is its own object at `…/trees/<sha256>`, and `root` and
/// every `child` are those keys. What every capture before dir packs holds, and what a registrar
/// that does not announce [`FORMAT_DIR_PACKS`] gets.
pub const FORMAT_DIR_OBJECTS: u32 = 1;
/// Section format 2: dir objects travel in dir packs (the CDC pack container, one entry per dir
/// object, keyed by its sha256) listed in `dir_packs`, and `root` and every `child` are dir
/// object digests, not keys.
pub const FORMAT_DIR_PACKS: u32 = 2;
/// The highest section format this build reads and writes.
pub const MAX_SECTION_FORMAT: u32 = FORMAT_DIR_PACKS;

fn format_dir_objects() -> u32 {
    FORMAT_DIR_OBJECTS
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` passes a reference.
fn is_format_dir_objects(format: &u32) -> bool {
    *format == FORMAT_DIR_OBJECTS
}

/// How the engine writes a chunked section's dir objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirFormat {
    /// One object per directory ([`FORMAT_DIR_OBJECTS`]).
    Objects,
    /// Dir packs ([`FORMAT_DIR_PACKS`]).
    Packs,
}

impl DirFormat {
    /// What to write for a registrar that reads sections up to `manifest_format` (the
    /// `manifest_format` of its `plan.get` answer; 1 when absent).
    #[must_use]
    pub fn for_registrar(manifest_format: u32) -> Self {
        if manifest_format >= FORMAT_DIR_PACKS {
            Self::Packs
        } else {
            Self::Objects
        }
    }

    /// The section `format` this writes.
    #[must_use]
    pub fn section_format(self) -> u32 {
        match self {
            Self::Objects => FORMAT_DIR_OBJECTS,
            Self::Packs => FORMAT_DIR_PACKS,
        }
    }
}

/// Where a chunked section's dir objects are: its root, its format and its dir packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeRef<'a> {
    /// Format 1: the root dir object's key. Format 2: its digest.
    pub root: &'a str,
    /// The section format.
    pub format: u32,
    /// Format 2: every dir pack the tree needs. Empty in format 1.
    pub dir_packs: &'a [String],
}

/// Format of the worktree metadata document ([`WorktreeMeta`]) this build reads and writes.
pub const WORKTREE_META_FORMAT: u32 = 1;

/// The worktree metadata overlay: what a git tree does not carry about the working tree the
/// [`WORKTREE_TREE_REF`] tree describes — exact mode bits, nanosecond mtimes of files, symlinks
/// and directories (the root included), directories git does not track (empty ones among them)
/// and hardlink groups. The document is JSON ([`crate::worktree_meta::MetaDocument`]), CDC
/// chunked into the workspace section's packs: every key in `packs` is also in the section's
/// `packs`, so a registrar that presigns and retains the section's packs covers it unchanged.
/// A materializer applies it after every class it restores; a manifest without it restores the
/// working tree as git checks it out, as before the overlay existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeMeta {
    /// Document format ([`WORKTREE_META_FORMAT`]); a reader refuses one above it before
    /// writing anything.
    pub format: u32,
    /// Length of the document in bytes.
    pub size: u64,
    /// sha256 of the whole document.
    pub sha256: String,
    /// The document's chunks, in order.
    pub chunks: Vec<ChunkId>,
    /// The packs holding those chunks (a subset of the workspace section's `packs`).
    pub packs: Vec<String>,
}

/// The workspace section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSection {
    /// Root dir object: its key in format 1, its digest in format 2.
    pub root: String,
    /// Every CDC pack key the section needs, across epochs.
    pub packs: Vec<String>,
    /// Section format ([`FORMAT_DIR_OBJECTS`] when absent, and then not written, so a format-1
    /// section encodes exactly as before dir packs).
    #[serde(
        default = "format_dir_objects",
        skip_serializing_if = "is_format_dir_objects"
    )]
    pub format: u32,
    /// Format 2: every dir pack the tree needs, across epochs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dir_packs: Vec<String>,
    /// The worktree metadata overlay. Absent in every capture before it (and then not written,
    /// so such a section encodes exactly as before).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_meta: Option<WorktreeMeta>,
}

impl WorkspaceSection {
    /// A format-1 section (one object per directory).
    #[must_use]
    pub fn objects(root: impl Into<String>, packs: Vec<String>) -> Self {
        Self {
            root: root.into(),
            packs,
            format: FORMAT_DIR_OBJECTS,
            dir_packs: Vec::new(),
            worktree_meta: None,
        }
    }

    /// Where the section's dir objects are.
    #[must_use]
    pub fn tree(&self) -> TreeRef<'_> {
        TreeRef {
            root: &self.root,
            format: self.format,
            dir_packs: &self.dir_packs,
        }
    }
}

/// The bulk section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkSection {
    /// Root dir object: its key in format 1, its digest in format 2.
    pub root: String,
    /// Every CDC pack key the section needs, across epochs.
    pub packs: Vec<String>,
    /// `<os>-<arch>-<libc>`.
    pub platform: String,
    /// Section format, as [`WorkspaceSection::format`].
    #[serde(
        default = "format_dir_objects",
        skip_serializing_if = "is_format_dir_objects"
    )]
    pub format: u32,
    /// Format 2: every dir pack the tree needs, across epochs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dir_packs: Vec<String>,
}

impl BulkSection {
    /// Where the section's dir objects are.
    #[must_use]
    pub fn tree(&self) -> TreeRef<'_> {
        TreeRef {
            root: &self.root,
            format: self.format,
            dir_packs: &self.dir_packs,
        }
    }
}

/// The literal `"pending"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingTag {
    /// Not captured yet.
    Pending,
}

/// The bulk section or the literal `"pending"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BulkState {
    /// Captured.
    Ready(BulkSection),
    /// Not captured yet.
    Pending(PendingTag),
}

impl BulkState {
    /// The `"pending"` value.
    #[must_use]
    pub const fn pending() -> Self {
        Self::Pending(PendingTag::Pending)
    }

    /// The section, if captured.
    #[must_use]
    pub fn section(&self) -> Option<&BulkSection> {
        match self {
            Self::Ready(s) => Some(s),
            Self::Pending(_) => None,
        }
    }
}

/// Sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sections {
    /// Git objects.
    pub git: GitSection,
    /// `.git` bookkeeping, ignored work files, harness home.
    pub workspace: WorkspaceSection,
    /// Dependencies and build outputs, as this chain last captured them on the platform that
    /// wrote the capture (or `"pending"`).
    pub bulk: BulkState,
    /// Bulk sections captured on other platforms, keyed by `<os>-<arch>-<libc>`, carried from
    /// capture to capture unchanged so each stays restorable on its own platform. An executor
    /// that continues a head whose bulk section was captured elsewhere (the registrar answered
    /// it `"pending"`) keeps that section here instead of dropping it; its own bulk snap then
    /// fills `bulk`, and the other platform's section stays. Absent when empty, so a manifest
    /// without one encodes exactly as before.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub other_bulk: BTreeMap<String, BulkSection>,
}

impl Sections {
    /// Every bulk section this manifest holds, by platform: `bulk` (when captured) and
    /// `other_bulk`. `bulk` wins over an `other_bulk` entry of the same platform.
    #[must_use]
    pub fn bulk_by_platform(&self) -> BTreeMap<String, BulkSection> {
        let mut all = self.other_bulk.clone();
        if let Some(bulk) = self.bulk.section() {
            all.insert(bulk.platform.clone(), bulk.clone());
        }
        all
    }

    /// The sections an executor continues the chain from when the registrar answered
    /// `answered` for this head's bulk section: `bulk` is the answered section when it is one
    /// of this manifest's (the one to restore here), `"pending"` otherwise; every other bulk
    /// section this manifest holds moves to (or stays in) `other_bulk`. Nothing is dropped.
    #[must_use]
    pub fn with_bulk_answer(&self, answered: &BulkState) -> Self {
        let mut other_bulk = self.bulk_by_platform();
        let bulk = match answered.section() {
            Some(chosen) if other_bulk.get(&chosen.platform) == Some(chosen) => {
                other_bulk.remove(&chosen.platform);
                BulkState::Ready(chosen.clone())
            }
            _ => BulkState::pending(),
        };
        Self {
            git: self.git.clone(),
            workspace: self.workspace.clone(),
            bulk,
            other_bulk,
        }
    }

    /// `other_bulk` for a capture whose bulk section is `bulk`, following a capture whose
    /// sections are `previous`: the previous capture's other platforms, plus its own bulk
    /// section when that was captured on another platform than `bulk`'s; `bulk`'s own platform
    /// is never listed twice.
    #[must_use]
    pub fn other_bulk_after(previous: &Self, bulk: &BulkState) -> BTreeMap<String, BulkSection> {
        // Still pending here: the previous capture's bulk section, whatever its platform, is
        // not this capture's to restore, but it is kept.
        let mut other = previous.bulk_by_platform();
        if let Some(own) = bulk.section() {
            other.remove(&own.platform);
        }
        other
    }
}

/// Checkpoint stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint ordinal within the session.
    pub ordinal: u64,
    /// Commit sha.
    pub sha: String,
    /// Hidden ref name.
    #[serde(rename = "ref")]
    pub ref_name: String,
}

/// The manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Worktree id.
    pub worktree_id: String,
    /// Position on the chain.
    pub n: u64,
    /// Parent capture id.
    pub parent: Option<String>,
    /// Lease epoch.
    pub epoch: u64,
    /// Execution sequence at snap start.
    pub seq: u64,
    /// Kind.
    pub kind: CaptureKind,
    /// RFC 3339, executor clock.
    pub created_at: String,
    /// Sections.
    pub sections: Sections,
    /// Checkpoint stamp, when `kind == checkpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Checkpoint>,
    /// The executor's word that its final flush completed ([`FinalSeal`]): only on the sealing
    /// capture a complete final flush registers last. Absent otherwise, so a manifest without
    /// one encodes exactly as before, and a capture staged after it carries none (it unseals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_seal: Option<FinalSeal>,
}

/// `final_seal` (cross-repo decision 1): a completed final flush as a store-side fact, not only
/// an RPC reply. When a final flush of this executor completes — every writer stopped, both
/// classes snapped after that, everything staged registered — it registers one more capture,
/// the head's sections unchanged, `kind: final`, `n` = head + 1, carrying this; it reports
/// `complete` only once that register is acknowledged. The registrar records it on the chain
/// only when `complete` is true, `epoch` is the epoch the capture registers under and
/// `executor` is the executor the session token was issued for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalSeal {
    /// Always true: an incomplete final flush writes no seal.
    pub complete: bool,
    /// The lease epoch the sealing capture registers under.
    pub epoch: u64,
    /// The executor sealantd was planned as: `plan.get`'s `executor`, else
    /// `SEALANT_WORKSPACE_ID`.
    pub executor: String,
}

/// A manifest with its canonical bytes and capture id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedManifest {
    /// Parsed form.
    pub manifest: Manifest,
    /// Canonical bytes (what is PUT and registered).
    pub bytes: Vec<u8>,
    /// sha256 of `bytes`.
    pub capture_id: String,
}

impl Manifest {
    /// Canonical bytes and capture id.
    #[must_use]
    pub fn encode(self) -> EncodedManifest {
        // Serializing a struct cannot fail.
        let bytes = serde_json::to_vec(&self).unwrap_or_default();
        let capture_id = sha256_hex(&bytes);
        EncodedManifest {
            manifest: self,
            bytes,
            capture_id,
        }
    }

    /// Decode manifest bytes, keeping them as the identity.
    pub fn decode(bytes: &[u8]) -> Result<EncodedManifest, serde_json::Error> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        Ok(EncodedManifest {
            manifest,
            bytes: bytes.to_vec(),
            capture_id: sha256_hex(bytes),
        })
    }

    /// Every ref value plus `head` when it is a sha: the pack closure tips of this capture.
    #[must_use]
    pub fn git_tips(&self) -> Vec<String> {
        let mut tips: Vec<String> = self.sections.git.refs.values().cloned().collect();
        if !self.sections.git.head.starts_with("refs/") {
            tips.push(self.sections.git.head.clone());
        }
        tips.sort();
        tips.dedup();
        tips
    }
}

/// Current time as RFC 3339 UTC with second precision (`2026-09-12T10:11:12Z`).
#[must_use]
pub fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    rfc3339_from_unix(secs as i64)
}

/// Format a Unix timestamp as RFC 3339 UTC.
#[must_use]
pub fn rfc3339_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            worktree_id: "wt".into(),
            n: 2,
            parent: Some("p".into()),
            epoch: 1,
            seq: 42,
            kind: CaptureKind::Auto,
            created_at: "2026-09-12T00:00:00Z".into(),
            sections: Sections {
                git: GitSection {
                    packs: vec!["captures/wt/1/packs/a".into()],
                    refs: [("refs/heads/main".to_string(), "abc".to_string())]
                        .into_iter()
                        .collect(),
                    head: "refs/heads/main".into(),
                    fsck: FsckStatus::Verified,
                    symrefs: BTreeMap::new(),
                },
                workspace: WorkspaceSection::objects("captures/wt/1/trees/t", vec![]),
                bulk: BulkState::pending(),
                other_bulk: BTreeMap::new(),
            },
            checkpoint: None,
            final_seal: None,
        }
    }

    fn bulk(platform: &str, root: &str) -> BulkSection {
        BulkSection {
            root: root.into(),
            packs: vec![format!("captures/wt/1/packs/{root}")],
            platform: platform.into(),
            format: FORMAT_DIR_OBJECTS,
            dir_packs: vec![],
        }
    }

    /// Another platform's bulk section is never dropped: continuing a head whose section the
    /// registrar answered `"pending"` keeps it in `other_bulk`; this platform's own bulk section
    /// takes `bulk` and the other stays; a head answered with a section `other_bulk` holds
    /// restores that one. The field is absent from the bytes when empty.
    #[test]
    fn other_platforms_bulk_sections_are_carried() {
        let mut head = sample();
        head.sections.bulk = BulkState::Ready(bulk("linux-aarch64-gnu", "arm"));
        // The registrar answers pending to an x86 executor: nothing to restore, nothing lost.
        let here = head.sections.with_bulk_answer(&BulkState::pending());
        assert_eq!(here.bulk, BulkState::pending());
        assert_eq!(
            here.other_bulk.keys().collect::<Vec<_>>(),
            ["linux-aarch64-gnu"]
        );
        // The x86 executor's own bulk snap.
        let own = BulkState::Ready(bulk("linux-x86_64-gnu", "x86"));
        let next = Sections {
            other_bulk: Sections::other_bulk_after(&here, &own),
            bulk: own.clone(),
            ..here.clone()
        };
        assert_eq!(next.other_bulk["linux-aarch64-gnu"].root, "arm");
        assert!(!next.other_bulk.contains_key("linux-x86_64-gnu"));
        // Back on arm: the registrar answers the arm section out of `other_bulk`.
        let arm = next.with_bulk_answer(&BulkState::Ready(bulk("linux-aarch64-gnu", "arm")));
        assert_eq!(arm.bulk.section().unwrap().root, "arm");
        assert_eq!(arm.other_bulk["linux-x86_64-gnu"].root, "x86");
        // An answer the manifest does not hold restores nothing and keeps everything.
        let odd = next.with_bulk_answer(&BulkState::Ready(bulk("linux-aarch64-gnu", "forged")));
        assert_eq!(odd.bulk, BulkState::pending());
        assert_eq!(odd.other_bulk.len(), 2);

        let mut m = sample();
        m.sections = next;
        let e = m.clone().encode();
        let text = String::from_utf8(e.bytes.clone()).unwrap();
        assert!(
            text.contains(r#""other_bulk":{"linux-aarch64-gnu":{"root":"arm""#),
            "{text}"
        );
        assert_eq!(Manifest::decode(&e.bytes).unwrap().manifest, m);
        assert!(
            !String::from_utf8(sample().encode().bytes)
                .unwrap()
                .contains("other_bulk")
        );
    }

    #[test]
    fn encoding_is_deterministic_and_pending_is_a_string() {
        let a = sample().encode();
        let b = sample().encode();
        assert_eq!(a.capture_id, b.capture_id);
        let text = String::from_utf8(a.bytes.clone()).unwrap();
        assert!(text.contains("\"bulk\":\"pending\""));
        assert!(text.contains("\"fsck\":\"verified\""));
        assert!(text.contains("\"kind\":\"auto\""));
        assert!(!text.contains("checkpoint"));
        let back = Manifest::decode(&a.bytes).unwrap();
        assert_eq!(back.manifest, a.manifest);
        assert_eq!(back.capture_id, a.capture_id);
    }

    #[test]
    fn bulk_ready_round_trips() {
        let mut m = sample();
        m.sections.bulk = BulkState::Ready(BulkSection {
            root: "r".into(),
            packs: vec![],
            platform: "linux-x86_64-musl".into(),
            format: FORMAT_DIR_OBJECTS,
            dir_packs: vec![],
        });
        m.checkpoint = Some(Checkpoint {
            ordinal: 1,
            sha: "s".into(),
            ref_name: "refs/mend/checkpoints/1".into(),
        });
        let e = m.clone().encode();
        assert!(String::from_utf8_lossy(&e.bytes).contains("\"ref\":\"refs/mend/checkpoints/1\""));
        assert_eq!(Manifest::decode(&e.bytes).unwrap().manifest, m);
    }

    /// A format-1 section encodes as it did before dir packs (so its capture id is unchanged);
    /// a format-2 section names its format and dir packs, and both decode back.
    #[test]
    fn section_format_is_written_only_for_dir_packs() {
        let legacy = sample().encode();
        let text = String::from_utf8(legacy.bytes.clone()).unwrap();
        assert!(!text.contains("format"), "{text}");
        assert!(!text.contains("dir_packs"), "{text}");
        assert!(text.contains(r#""workspace":{"root":"captures/wt/1/trees/t","packs":[]}"#));
        let old_bytes = br#"{"worktree_id":"wt","n":0,"parent":null,"epoch":1,"seq":0,"kind":"auto","created_at":"x","sections":{"git":{"packs":[],"refs":{},"head":"refs/heads/main","fsck":"verified"},"workspace":{"root":"captures/wt/1/trees/t","packs":[]},"bulk":{"root":"captures/wt/1/trees/b","packs":[],"platform":"p"}}}"#;
        let old = Manifest::decode(old_bytes).unwrap();
        assert_eq!(old.manifest.sections.workspace.format, FORMAT_DIR_OBJECTS);
        assert_eq!(old.bytes, old_bytes.to_vec());

        let mut m = sample();
        m.sections.workspace = WorkspaceSection {
            root: "d".repeat(64),
            packs: vec![],
            format: FORMAT_DIR_PACKS,
            dir_packs: vec!["captures/wt/1/packs/p".into()],
            worktree_meta: None,
        };
        let e = m.clone().encode();
        let text = String::from_utf8(e.bytes.clone()).unwrap();
        assert!(
            text.contains(r#""format":2,"dir_packs":["captures/wt/1/packs/p"]"#),
            "{text}"
        );
        let back = Manifest::decode(&e.bytes).unwrap().manifest;
        assert_eq!(back, m);
        assert_eq!(back.sections.workspace.tree().dir_packs.len(), 1);
        assert_eq!(DirFormat::for_registrar(1), DirFormat::Objects);
        assert_eq!(DirFormat::for_registrar(2), DirFormat::Packs);
        assert_eq!(DirFormat::for_registrar(3), DirFormat::Packs);
    }

    /// The worktree metadata overlay is additive: absent, a workspace section encodes as it did
    /// before it (so the capture id of an older capture is unchanged); present, it follows the
    /// section's other fields and decodes back; a manifest without it decodes to `None`.
    #[test]
    fn worktree_meta_is_written_only_when_present() {
        let legacy = sample().encode();
        assert!(!String::from_utf8_lossy(&legacy.bytes).contains("worktree_meta"));
        let mut m = sample();
        m.sections.workspace.worktree_meta = Some(WorktreeMeta {
            format: WORKTREE_META_FORMAT,
            size: 3,
            sha256: "e".repeat(64),
            chunks: vec![ChunkId::of(b"abc")],
            packs: vec!["captures/wt/1/packs/p".into()],
        });
        let e = m.clone().encode();
        let text = String::from_utf8(e.bytes.clone()).unwrap();
        let chunk = ChunkId::of(b"abc").to_hex();
        let expected = format!(
            r#""workspace":{{"root":"captures/wt/1/trees/t","packs":[],"worktree_meta":{{"format":1,"size":3,"sha256":"{}","chunks":["{chunk}"],"packs":["captures/wt/1/packs/p"]}}}}"#,
            "e".repeat(64)
        );
        assert!(text.contains(&expected), "{text}");
        assert_eq!(Manifest::decode(&e.bytes).unwrap().manifest, m);
        assert_eq!(
            Manifest::decode(&legacy.bytes)
                .unwrap()
                .manifest
                .sections
                .workspace
                .worktree_meta,
            None
        );
    }

    /// `symrefs` is additive: absent when empty (an older manifest's bytes are unchanged),
    /// written after `fsck` when present, and decoded back.
    #[test]
    fn symrefs_are_written_only_when_present() {
        assert!(!String::from_utf8_lossy(&sample().encode().bytes).contains("symrefs"));
        let mut m = sample();
        m.sections.git.symrefs.insert(
            "refs/remotes/origin/HEAD".into(),
            "refs/remotes/origin/main".into(),
        );
        let e = m.clone().encode();
        let text = String::from_utf8(e.bytes.clone()).unwrap();
        assert!(
            text.contains(r#""fsck":"verified","symrefs":{"refs/remotes/origin/HEAD":"refs/remotes/origin/main"}}"#),
            "{text}"
        );
        assert_eq!(Manifest::decode(&e.bytes).unwrap().manifest, m);
    }

    #[test]
    fn rfc3339_formats_known_dates() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339_from_unix(1_788_998_400), "2026-09-10T00:00:00Z");
    }
}
