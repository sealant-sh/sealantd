//! `BlobSink`: where capture objects go. `LocalDir` is a directory (one machine and tests);
//! `PresignedHttp` PUTs and GETs per-key presigned URLs minted by a [`UrlMinter`], so the crate
//! never holds bucket credentials.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Bytes to store: in memory or a file on disk (streamed).
#[derive(Debug, Clone, Copy)]
pub enum BlobSource<'a> {
    /// In-memory bytes.
    Bytes(&'a [u8]),
    /// A file to stream.
    File(&'a Path),
}

impl BlobSource<'_> {
    /// Read the whole source.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        match self {
            Self::Bytes(b) => Ok(b.to_vec()),
            Self::File(p) => fs::read(p),
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> io::Result<u64> {
        match self {
            Self::Bytes(b) => Ok(b.len() as u64),
            Self::File(p) => Ok(fs::metadata(p)?.len()),
        }
    }

    /// Whether the source is empty.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Outcome of a put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// Bytes were written.
    Stored,
    /// The key already held bytes; nothing was written.
    AlreadyPresent,
}

/// Sink errors.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// The key holds nothing.
    #[error("key not found: {0}")]
    NotFound(String),
    /// The minter refused a URL (lease lost, quota, network).
    #[error("no url for {key}: {reason}")]
    NoUrl {
        /// Key.
        key: String,
        /// Why.
        reason: String,
    },
    /// The store answered with an unexpected status.
    #[error("{method} {key}: http {status}")]
    Http {
        /// Method.
        method: &'static str,
        /// Key.
        key: String,
        /// Status code.
        status: u16,
    },
    /// Transport failure.
    #[error("{method} {key}: {reason}")]
    Transport {
        /// Method.
        method: &'static str,
        /// Key.
        key: String,
        /// Why.
        reason: String,
    },
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl SinkError {
    /// Whether a retry can help.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } | Self::Io(_) => true,
            Self::Http { status, .. } => *status >= 500 || *status == 429 || *status == 408,
            Self::NoUrl { .. } | Self::NotFound(_) => false,
        }
    }
}

/// A key → bytes store.
pub trait BlobSink: Send + Sync {
    /// Store `source` at `key` unless the key already holds bytes.
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError>;
    /// Read the bytes at `key`.
    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError>;
    /// Whether `key` holds bytes.
    fn exists(&self, key: &str) -> Result<bool, SinkError>;
}

/// A directory: `key` → `<dir>/<key>`.
#[derive(Debug, Clone)]
pub struct LocalDir {
    dir: PathBuf,
}

impl LocalDir {
    /// Use (and create) `dir`.
    pub fn new(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let mut p = self.dir.clone();
        for seg in key.split('/').filter(|s| !s.is_empty() && *s != "..") {
            p.push(seg);
        }
        p
    }
}

impl BlobSink for LocalDir {
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        let path = self.path_for(key);
        if path.exists() {
            return Ok(PutOutcome::AlreadyPresent);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        match source {
            BlobSource::Bytes(b) => fs::write(&tmp, b)?,
            BlobSource::File(f) => {
                // A hardlink is free and immutable enough (staged files are never rewritten).
                if fs::hard_link(f, &tmp).is_err() {
                    fs::copy(f, &tmp)?;
                }
            }
        }
        fs::rename(&tmp, &path)?;
        Ok(PutOutcome::Stored)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        let path = self.path_for(key);
        match fs::read(&path) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(SinkError::NotFound(key.to_owned()))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        Ok(self.path_for(key).is_file())
    }
}

/// Mints presigned URLs for one key at a time (the Registrar's `upload.urls` / `plan.get` behind
/// a cache). The crate never sees credentials, only URLs.
pub trait UrlMinter: Send + Sync {
    /// A PUT URL for `key`.
    fn put_url(&self, key: &str) -> Result<String, String>;
    /// A GET URL for `key`.
    fn get_url(&self, key: &str) -> Result<String, String>;
}

/// Presigned-URL HTTP sink (S3, R2, Garage, or a test server).
pub struct PresignedHttp {
    agent: ureq::Agent,
    minter: Box<dyn UrlMinter>,
}

impl std::fmt::Debug for PresignedHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PresignedHttp")
    }
}

impl PresignedHttp {
    /// Build with a minter and a per-request timeout.
    #[must_use]
    pub fn new(minter: Box<dyn UrlMinter>, timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
            minter,
        }
    }

    fn url(&self, key: &str, put: bool) -> Result<String, SinkError> {
        let r = if put {
            self.minter.put_url(key)
        } else {
            self.minter.get_url(key)
        };
        r.map_err(|reason| SinkError::NoUrl {
            key: key.to_owned(),
            reason,
        })
    }
}

fn transport(method: &'static str, key: &str, e: ureq::Error) -> SinkError {
    SinkError::Transport {
        method,
        key: key.to_owned(),
        reason: e.to_string(),
    }
}

impl BlobSink for PresignedHttp {
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        let url = self.url(key, true)?;
        let len = source.len()?;
        let req = self
            .agent
            .put(&url)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", len.to_string())
            // Stores that honour conditional writes (S3, R2) refuse an overwrite with 412.
            .header("If-None-Match", "*");
        let resp = match source {
            BlobSource::Bytes(b) => req.send(b),
            BlobSource::File(p) => req.send(fs::File::open(p)?),
        }
        .map_err(|e| transport("PUT", key, e))?;
        match resp.status().as_u16() {
            200..=299 => Ok(PutOutcome::Stored),
            412 => Ok(PutOutcome::AlreadyPresent),
            status => Err(SinkError::Http {
                method: "PUT",
                key: key.to_owned(),
                status,
            }),
        }
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        let url = self.url(key, false)?;
        let mut resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| transport("GET", key, e))?;
        match resp.status().as_u16() {
            200..=299 => resp
                .body_mut()
                .with_config()
                .limit(u64::MAX)
                .read_to_vec()
                .map_err(|e| transport("GET", key, e)),
            404 => Err(SinkError::NotFound(key.to_owned())),
            status => Err(SinkError::Http {
                method: "GET",
                key: key.to_owned(),
                status,
            }),
        }
    }

    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        // A presigned GET URL signs the method, so probe with a one-byte ranged GET, not HEAD.
        let url = self.url(key, false)?;
        let resp = self
            .agent
            .get(&url)
            .header("Range", "bytes=0-0")
            .call()
            .map_err(|e| transport("GET", key, e))?;
        match resp.status().as_u16() {
            200..=299 => Ok(true),
            404 => Ok(false),
            status => Err(SinkError::Http {
                method: "GET",
                key: key.to_owned(),
                status,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_dir_put_get_exists() {
        let dir = tempfile::tempdir().unwrap();
        let s = LocalDir::new(&dir.path().join("store")).unwrap();
        let key = "captures/wt/1/packs/abc";
        assert!(!s.exists(key).unwrap());
        assert!(matches!(s.get(key), Err(SinkError::NotFound(_))));
        assert_eq!(
            s.put_if_absent(key, BlobSource::Bytes(b"one")).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(
            s.put_if_absent(key, BlobSource::Bytes(b"two")).unwrap(),
            PutOutcome::AlreadyPresent
        );
        assert_eq!(s.get(key).unwrap(), b"one");
        let f = dir.path().join("f");
        fs::write(&f, b"file").unwrap();
        assert_eq!(
            s.put_if_absent("k/f", BlobSource::File(&f)).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(s.get("k/f").unwrap(), b"file");
        // Path traversal in a key never escapes the directory.
        s.put_if_absent("../escape", BlobSource::Bytes(b"x"))
            .unwrap();
        assert!(!dir.path().join("escape").exists());
    }
}
