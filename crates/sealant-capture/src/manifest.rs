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

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chunk::sha256_hex;

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
    /// Ref name → sha, including the pseudo-refs.
    pub refs: BTreeMap<String, String>,
    /// `HEAD`: a ref name or a sha.
    pub head: String,
    /// fsck outcome.
    pub fsck: FsckStatus,
}

/// The workspace section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSection {
    /// Root dir object key.
    pub root: String,
    /// Every CDC pack key the section needs, across epochs.
    pub packs: Vec<String>,
}

/// The bulk section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkSection {
    /// Root dir object key.
    pub root: String,
    /// Every CDC pack key the section needs, across epochs.
    pub packs: Vec<String>,
    /// `<os>-<arch>-<libc>`.
    pub platform: String,
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
    /// Dependencies and build outputs.
    pub bulk: BulkState,
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
                },
                workspace: WorkspaceSection {
                    root: "captures/wt/1/trees/t".into(),
                    packs: vec![],
                },
                bulk: BulkState::pending(),
            },
            checkpoint: None,
        }
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

    #[test]
    fn rfc3339_formats_known_dates() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339_from_unix(1_788_998_400), "2026-09-10T00:00:00Z");
    }
}
