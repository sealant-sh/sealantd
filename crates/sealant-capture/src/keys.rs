//! Object keys (ADR-0015 *Keys*): every session-private object lives under
//! `captures/<worktree>/<epoch>/…`, and this build's under a key generation beneath that:
//! `captures/<worktree>/<epoch>/g<generation>/{packs,trees,manifests}/…`.
//!
//! The generation is how a key is never written again once a registrar refused a capture
//! naming it (cross-repo decision 6, *condemned objects are never revived*): retention may have
//! condemned that key, and a delete it paused would take the bytes back out from under any
//! capture that named the key again. Staging keeps the generation per worktree and epoch
//! ([`crate::ship::Staging::key_generation`]); every rebuild of a refused capture moves it on
//! first, so what the rebuild packs — even the very same bytes — goes up under keys nothing was
//! ever refused for. A key without the segment was written before generations and reads as
//! before; every key stays content-addressed in its last segment ([`key_digest`]).

use std::fmt;

/// The prefix a capture writes under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrefix {
    /// Worktree id.
    pub worktree_id: String,
    /// Lease epoch.
    pub epoch: u64,
    /// Key generation (`g<n>` under the epoch); `None` writes the keys as before generations.
    pub generation: Option<u64>,
}

impl KeyPrefix {
    /// `captures/<worktree>/<epoch>`: the epoch's own prefix, every generation under it.
    #[must_use]
    pub fn base(&self) -> String {
        format!("captures/{}/{}", self.worktree_id, self.epoch)
    }

    /// Where this prefix's objects go: `captures/<worktree>/<epoch>/g<generation>`, or the
    /// epoch's prefix itself without a generation.
    #[must_use]
    pub fn objects(&self) -> String {
        match self.generation {
            Some(generation) => format!("{}/g{generation}", self.base()),
            None => self.base(),
        }
    }

    /// Key of a pack (git or CDC) by its sha256.
    #[must_use]
    pub fn pack(&self, sha256: &str) -> String {
        format!("{}/packs/{sha256}", self.objects())
    }

    /// Key of a git pack's `.idx`.
    #[must_use]
    pub fn pack_idx(&self, sha256: &str) -> String {
        format!("{}/packs/{sha256}.idx", self.objects())
    }

    /// Key of a dir object.
    #[must_use]
    pub fn tree(&self, sha256: &str) -> String {
        format!("{}/trees/{sha256}", self.objects())
    }

    /// Key of a manifest by capture id.
    #[must_use]
    pub fn manifest(&self, capture_id: &str) -> String {
        format!("{}/manifests/{capture_id}", self.objects())
    }
}

impl fmt::Display for KeyPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.objects())
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

/// The key generation an object key was written under: the `g<n>` segment just above its
/// `packs`/`trees`/`manifests` directory; `None` for a key without one (written before
/// generations, or by the control plane).
#[must_use]
pub fn key_generation(key: &str) -> Option<u64> {
    let mut parts = key.rsplit('/');
    let _object = parts.next()?;
    let kind = parts.next()?;
    if !matches!(kind, "packs" | "trees" | "manifests") {
        return None;
    }
    let segment = parts.next()?;
    let digits = segment.strip_prefix('g')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
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
        let legacy = KeyPrefix {
            worktree_id: "wt1".into(),
            epoch: 3,
            generation: None,
        };
        assert_eq!(legacy.pack("ab"), "captures/wt1/3/packs/ab");
        assert_eq!(legacy.pack_idx("ab"), "captures/wt1/3/packs/ab.idx");
        assert_eq!(legacy.tree("cd"), "captures/wt1/3/trees/cd");
        assert_eq!(legacy.manifest("ef"), "captures/wt1/3/manifests/ef");
        let d = "a".repeat(64);
        assert_eq!(key_digest(&legacy.pack_idx(&d)), Some(d.as_str()));
        assert_eq!(key_digest("captures/wt1/3/packs/short"), None);
        assert_eq!(key_generation(&legacy.pack(&d)), None);
    }

    /// A generation sits between the epoch and the object kind; the digest is still the last
    /// segment, and the same bytes under two generations are two keys.
    #[test]
    fn a_generation_gives_the_same_bytes_a_new_key() {
        let d = "b".repeat(64);
        let g0 = KeyPrefix {
            worktree_id: "wt1".into(),
            epoch: 3,
            generation: Some(0),
        };
        let g1 = KeyPrefix {
            generation: Some(1),
            ..g0.clone()
        };
        assert_eq!(g0.pack(&d), format!("captures/wt1/3/g0/packs/{d}"));
        assert_eq!(g1.pack_idx(&d), format!("captures/wt1/3/g1/packs/{d}.idx"));
        assert_eq!(g1.tree(&d), format!("captures/wt1/3/g1/trees/{d}"));
        assert_eq!(g1.manifest(&d), format!("captures/wt1/3/g1/manifests/{d}"));
        assert_ne!(g0.pack(&d), g1.pack(&d));
        assert_eq!(g0.base(), g1.base());
        assert_eq!(key_digest(&g1.pack_idx(&d)), Some(d.as_str()));
        assert_eq!(key_generation(&g1.pack_idx(&d)), Some(1));
        assert_eq!(key_generation(&g0.manifest(&d)), Some(0));
        // A worktree id that looks like a generation is not one.
        assert_eq!(key_generation(&format!("captures/g7/3/packs/{d}")), None);
    }
}
