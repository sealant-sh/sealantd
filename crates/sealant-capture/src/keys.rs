//! Object keys (ADR-0015 *Keys*): every session-private object lives under
//! `captures/<worktree>/<epoch>/…`.

use std::fmt;

/// The epoch prefix a capture writes under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrefix {
    /// Worktree id.
    pub worktree_id: String,
    /// Lease epoch.
    pub epoch: u64,
}

impl KeyPrefix {
    /// `captures/<worktree>/<epoch>`.
    #[must_use]
    pub fn base(&self) -> String {
        format!("captures/{}/{}", self.worktree_id, self.epoch)
    }

    /// Key of a pack (git or CDC) by its sha256.
    #[must_use]
    pub fn pack(&self, sha256: &str) -> String {
        format!("{}/packs/{sha256}", self.base())
    }

    /// Key of a git pack's `.idx`.
    #[must_use]
    pub fn pack_idx(&self, sha256: &str) -> String {
        format!("{}/packs/{sha256}.idx", self.base())
    }

    /// Key of a dir object.
    #[must_use]
    pub fn tree(&self, sha256: &str) -> String {
        format!("{}/trees/{sha256}", self.base())
    }

    /// Key of a manifest by capture id.
    #[must_use]
    pub fn manifest(&self, capture_id: &str) -> String {
        format!("{}/manifests/{capture_id}", self.base())
    }
}

impl fmt::Display for KeyPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base())
    }
}

/// The content hash a key names (the last path segment, minus a `.idx` suffix), if it is a
/// content-addressed key.
#[must_use]
pub fn key_digest(key: &str) -> Option<&str> {
    let last = key.rsplit('/').next()?;
    let digest = last.strip_suffix(".idx").unwrap_or(last);
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digest)
}

/// Whether `key` names a git pack index.
#[must_use]
pub fn is_idx_key(key: &str) -> bool {
    key.ends_with(".idx")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_follow_the_adr_layout() {
        let p = KeyPrefix {
            worktree_id: "wt1".into(),
            epoch: 3,
        };
        assert_eq!(p.pack("ab"), "captures/wt1/3/packs/ab");
        assert_eq!(p.pack_idx("ab"), "captures/wt1/3/packs/ab.idx");
        assert_eq!(p.tree("cd"), "captures/wt1/3/trees/cd");
        assert_eq!(p.manifest("ef"), "captures/wt1/3/manifests/ef");
        let d = "a".repeat(64);
        assert_eq!(key_digest(&p.pack_idx(&d)), Some(d.as_str()));
        assert_eq!(key_digest("captures/wt1/3/packs/short"), None);
    }
}
