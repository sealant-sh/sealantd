//! `BlobSink`: where capture objects go. `LocalDir` is a directory (one machine and tests);
//! `PresignedHttp` PUTs and GETs per-key presigned URLs minted by a [`UrlMinter`], so the crate
//! never holds bucket credentials. Large objects go up as multipart uploads
//! ([`BlobSink::put_multipart`]): the minter hands out one presigned URL per part, the parts are
//! PUT with several in flight, and the registrar completes the upload server-side (write-once,
//! `If-None-Match: *`), so the executor still holds nothing but per-key URLs.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::cpu::thread_cpu;
use crate::registrar::{CompletedPart, MultipartUrls, opt};

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
    /// The registrar refused the bytes for the session's byte quota (413 at `upload.urls`, 409
    /// `byte-quota` at the register). Terminal: no retry, no other key, no later tick.
    #[error("refused ({reason}): limit {}, used {}, requested {}", opt(.limit), opt(.used), opt(.requested))]
    QuotaRefused {
        /// The registrar's reason code (`byte-quota`).
        reason: String,
        /// The session's budget in bytes, when the answer names it.
        limit: Option<u64>,
        /// Bytes priced against the session so far.
        used: Option<u64>,
        /// Bytes the refused call asked for.
        requested: Option<u64>,
    },
    /// A multipart upload could not be assembled: the registrar minted the wrong number of part
    /// URLs, a part answered without an ETag, the complete was refused, or the assembled object
    /// has the wrong size.
    #[error("multipart {key}: {reason}")]
    Multipart {
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
            Self::NoUrl { .. }
            | Self::NotFound(_)
            | Self::Multipart { .. }
            | Self::QuotaRefused { .. } => false,
        }
    }
}

/// Retry policy for one part (and the complete call) of a multipart upload. Exhausting it fails
/// the whole object; the shipper then retries the object with fresh URLs.
#[derive(Debug, Clone, Copy)]
pub struct PartRetry {
    /// Attempts per part.
    pub attempts: u32,
    /// First backoff; doubles per attempt.
    pub backoff: Duration,
    /// Backoff cap.
    pub max_backoff: Duration,
}

impl Default for PartRetry {
    fn default() -> Self {
        Self {
            attempts: 5,
            backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl PartRetry {
    fn delay(&self, attempt: u32) -> Duration {
        let mult = 1u32 << attempt.min(10);
        (self.backoff * mult).min(self.max_backoff)
    }
}

/// What completing a multipart upload reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completed {
    /// Stored, or the key already existed (the write-once complete was refused).
    pub outcome: PutOutcome,
    /// Size of the object at the key, when the registrar reports it.
    pub size: Option<u64>,
}

/// A key → bytes store.
pub trait BlobSink: Send + Sync {
    /// Store `source` at `key` unless the key already holds bytes.
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError>;
    /// Store `file` at `key` as a multipart upload: `part_size`-byte parts, up to
    /// `parts_in_flight` uploading at once, then one write-once complete. Same contract as
    /// [`BlobSink::put_if_absent`]: an existing key is left alone and reported. A sink whose
    /// store fixes the part size (the registrar's `part_size`) uses the store's, not
    /// `part_size`. The default is a single PUT.
    fn put_multipart(
        &self,
        key: &str,
        file: &Path,
        part_size: u64,
        parts_in_flight: usize,
    ) -> Result<PutOutcome, SinkError> {
        let _ = (part_size, parts_in_flight);
        self.put_if_absent(key, BlobSource::File(file))
    }
    /// Prepare to store `keys` (each `(key, bytes)`) with single PUTs: a presigned sink mints
    /// their URLs in one channel call instead of one per key, and the sizes let the registrar
    /// price the batch before it mints. Advisory — a PUT of a key that was not (or could not be)
    /// prepared mints on its own — except a [`SinkError::QuotaRefused`], which is terminal. The
    /// default does nothing.
    fn prefetch_put(&self, keys: &[(String, u64)]) -> Result<(), SinkError> {
        let _ = keys;
        Ok(())
    }
    /// Read the bytes at `key`.
    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError>;
    /// Whether `key` holds bytes.
    fn exists(&self, key: &str) -> Result<bool, SinkError>;
    /// CPU time spent so far in helper threads this sink spawned (part uploads), so a caller
    /// pacing itself by CPU can charge it; network waits are not CPU and never count.
    fn helper_cpu(&self) -> Duration {
        Duration::ZERO
    }
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

    /// A plain write: the parts are read in `part_size` pieces and concatenated.
    fn put_multipart(
        &self,
        key: &str,
        file: &Path,
        part_size: u64,
        _parts_in_flight: usize,
    ) -> Result<PutOutcome, SinkError> {
        let path = self.path_for(key);
        if path.exists() {
            return Ok(PutOutcome::AlreadyPresent);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut src = fs::File::open(file)?;
        let mut out = fs::File::create(&tmp)?;
        loop {
            let copied = io::copy(&mut (&mut src).take(part_size.max(1)), &mut out)?;
            if copied == 0 {
                break;
            }
        }
        out.sync_all()?;
        drop(out);
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
/// a cache) and completes multipart uploads through the registrar. The crate never sees
/// credentials, only URLs.
pub trait UrlMinter: Send + Sync {
    /// A PUT URL for `key`, whose object is `size` bytes. The size is not a hint: a registrar
    /// may bind the signature to that exact content length, so it is the length the PUT then
    /// sends, and never a guess or a zero stand-in.
    fn put_url(&self, key: &str, size: u64) -> Result<String, SinkError>;
    /// Mint PUT URLs for `keys` (each `(key, bytes)`) ahead of their [`UrlMinter::put_url`]
    /// calls, in one channel call carrying every size. The default mints nothing (every
    /// `put_url` then mints its own).
    fn prefetch_put(&self, keys: &[(String, u64)]) -> Result<(), SinkError> {
        let _ = keys;
        Ok(())
    }
    /// A GET URL for `key`.
    fn get_url(&self, key: &str) -> Result<String, SinkError>;
    /// Part URLs for a multipart upload of `key` (`size` bytes), or none when the store takes
    /// the key as a single PUT (below the registrar's threshold, or no multipart support).
    fn multipart_urls(&self, key: &str, size: u64) -> Result<Option<MultipartUrls>, SinkError> {
        let _ = (key, size);
        Ok(None)
    }
    /// Complete the multipart upload `upload_id` at `key` write-once: the registrar sends
    /// `If-None-Match: *` and reports an existing key as [`PutOutcome::AlreadyPresent`].
    fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<Completed, SinkError> {
        let _ = (upload_id, parts);
        Err(SinkError::Multipart {
            key: key.to_owned(),
            reason: "this minter cannot complete multipart uploads".to_owned(),
        })
    }
}

/// A shared minter is a minter: the daemon keeps the handle a re-plan resets while the sink
/// owns a clone.
impl<M: UrlMinter + ?Sized> UrlMinter for Arc<M> {
    fn put_url(&self, key: &str, size: u64) -> Result<String, SinkError> {
        (**self).put_url(key, size)
    }

    fn prefetch_put(&self, keys: &[(String, u64)]) -> Result<(), SinkError> {
        (**self).prefetch_put(keys)
    }

    fn get_url(&self, key: &str) -> Result<String, SinkError> {
        (**self).get_url(key)
    }

    fn multipart_urls(&self, key: &str, size: u64) -> Result<Option<MultipartUrls>, SinkError> {
        (**self).multipart_urls(key, size)
    }

    fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<Completed, SinkError> {
        (**self).complete_multipart(key, upload_id, parts)
    }
}

/// Presigned-URL HTTP sink (S3, R2, Garage, or a test server).
pub struct PresignedHttp {
    agent: ureq::Agent,
    minter: Box<dyn UrlMinter>,
    part_retry: PartRetry,
    /// CPU time (µs) burnt by finished part-upload threads.
    helper_cpu_micros: AtomicU64,
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
            part_retry: PartRetry::default(),
            helper_cpu_micros: AtomicU64::new(0),
        }
    }

    /// Retry policy per part.
    #[must_use]
    pub fn with_part_retry(mut self, retry: PartRetry) -> Self {
        self.part_retry = retry;
        self
    }

    fn url(&self, key: &str) -> Result<String, SinkError> {
        self.minter.get_url(key)
    }
}

fn transport(method: &'static str, key: &str, e: ureq::Error) -> SinkError {
    SinkError::Transport {
        method,
        key: key.to_owned(),
        reason: e.to_string(),
    }
}

fn multipart_err(key: &str, reason: impl Into<String>) -> SinkError {
    SinkError::Multipart {
        key: key.to_owned(),
        reason: reason.into(),
    }
}

/// Byte range of part `index` (0-based) in an object of `size` bytes cut at `part_size`.
fn part_range(index: usize, part_size: u64, size: u64) -> (u64, u64) {
    let offset = index as u64 * part_size;
    (offset, part_size.min(size.saturating_sub(offset)))
}

/// Total object size from a ranged GET's answer: `Content-Range: bytes 0-0/<total>` on a 206,
/// `Content-Length` on a 200 the store answered without honouring the range.
fn size_from_headers(status: u16, headers: &ureq::http::HeaderMap) -> Option<u64> {
    let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    match status {
        206 => text("content-range")?
            .rsplit('/')
            .next()?
            .trim()
            .parse()
            .ok(),
        200 => text("content-length")?.trim().parse().ok(),
        _ => None,
    }
}

impl PresignedHttp {
    /// PUT one part with retries; the ETag the store answered.
    fn upload_part(
        &self,
        key: &str,
        url: &str,
        file: &Path,
        part_number: u32,
        offset: u64,
        len: u64,
    ) -> Result<String, SinkError> {
        let mut last = None;
        for attempt in 0..self.part_retry.attempts.max(1) {
            if attempt > 0 {
                thread::sleep(self.part_retry.delay(attempt - 1));
            }
            let mut f = fs::File::open(file)?;
            f.seek(SeekFrom::Start(offset))?;
            let resp = self
                .agent
                .put(url)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", len.to_string())
                .send(ureq::SendBody::from_owned_reader(f.take(len)));
            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(key, part_number, attempt, error = %e, "part upload failed; retrying");
                    last = Some(transport("PUT", key, e));
                    continue;
                }
            };
            let status = resp.status().as_u16();
            match status {
                200..=299 => {
                    return resp
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                        .ok_or_else(|| multipart_err(key, format!("part {part_number}: no ETag")));
                }
                s if s >= 500 || s == 429 || s == 408 => {
                    tracing::warn!(
                        key,
                        part_number,
                        attempt,
                        status,
                        "part upload refused; retrying"
                    );
                    last = Some(SinkError::Http {
                        method: "PUT",
                        key: key.to_owned(),
                        status,
                    });
                }
                s => {
                    return Err(SinkError::Http {
                        method: "PUT",
                        key: key.to_owned(),
                        status: s,
                    });
                }
            }
        }
        Err(last.unwrap_or_else(|| multipart_err(key, "no attempts")))
    }

    /// Complete with retries on transport failures (a complete that reached the store and was
    /// lost on the way back answers `exists` the second time, which is the right answer).
    fn complete(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<Completed, SinkError> {
        let mut last = None;
        for attempt in 0..self.part_retry.attempts.max(1) {
            if attempt > 0 {
                thread::sleep(self.part_retry.delay(attempt - 1));
            }
            match self.minter.complete_multipart(key, upload_id, parts) {
                Ok(c) => return Ok(c),
                Err(e) if e.is_retryable() => {
                    tracing::warn!(key, attempt, error = %e, "multipart complete failed; retrying");
                    last = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| multipart_err(key, "no attempts")))
    }

    /// Size of the object at `key` by a one-byte ranged GET, when a GET URL exists for it.
    fn remote_size(&self, key: &str) -> Result<Option<u64>, SinkError> {
        let Ok(url) = self.minter.get_url(key) else {
            return Ok(None);
        };
        let resp = self
            .agent
            .get(&url)
            .header("Range", "bytes=0-0")
            .call()
            .map_err(|e| transport("GET", key, e))?;
        let status = resp.status().as_u16();
        match status {
            200 | 206 => Ok(size_from_headers(status, resp.headers())),
            404 => Err(SinkError::NotFound(key.to_owned())),
            s => Err(SinkError::Http {
                method: "GET",
                key: key.to_owned(),
                status: s,
            }),
        }
    }
}

impl BlobSink for PresignedHttp {
    fn prefetch_put(&self, keys: &[(String, u64)]) -> Result<(), SinkError> {
        if keys.is_empty() {
            return Ok(());
        }
        self.minter.prefetch_put(keys)
    }

    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        // The length before the URL: it is what the mint declares and what the PUT sends.
        let len = source.len()?;
        let url = self.minter.put_url(key, len)?;
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

    fn put_multipart(
        &self,
        key: &str,
        file: &Path,
        _part_size: u64,
        parts_in_flight: usize,
    ) -> Result<PutOutcome, SinkError> {
        let size = fs::metadata(file)?.len();
        let plan = if size == 0 {
            None
        } else {
            self.minter.multipart_urls(key, size)?
        };
        let Some(plan) = plan else {
            return self.put_if_absent(key, BlobSource::File(file));
        };
        if plan.part_size == 0 {
            return Err(multipart_err(key, "registrar minted part_size 0"));
        }
        let count = usize::try_from(size.div_ceil(plan.part_size))
            .map_err(|_| multipart_err(key, "too many parts"))?;
        if plan.part_urls.len() != count {
            return Err(multipart_err(
                key,
                format!(
                    "registrar minted {} part urls for {count} parts of {} bytes",
                    plan.part_urls.len(),
                    plan.part_size
                ),
            ));
        }
        let next = AtomicUsize::new(0);
        let etags: Mutex<Vec<Option<String>>> = Mutex::new(vec![None; count]);
        let failed: Mutex<Option<SinkError>> = Mutex::new(None);
        let workers = parts_in_flight.clamp(1, count);
        thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let stop = failed
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .is_some();
                        if index >= count || stop {
                            break;
                        }
                        let (offset, len) = part_range(index, plan.part_size, size);
                        let part_number = index as u32 + 1;
                        match self.upload_part(
                            key,
                            &plan.part_urls[index],
                            file,
                            part_number,
                            offset,
                            len,
                        ) {
                            Ok(etag) => {
                                etags
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)[index] =
                                    Some(etag);
                            }
                            Err(e) => {
                                failed
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .get_or_insert(e);
                                break;
                            }
                        }
                    }
                    // A fresh thread's CPU time is exactly what it burnt here.
                    let micros = u64::try_from(thread_cpu().as_micros()).unwrap_or(u64::MAX);
                    self.helper_cpu_micros.fetch_add(micros, Ordering::Relaxed);
                });
            }
        });
        if let Some(e) = failed
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return Err(e);
        }
        let parts: Vec<CompletedPart> = etags
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .into_iter()
            .enumerate()
            .map(|(i, etag)| {
                etag.map(|etag| CompletedPart {
                    part_number: i as u32 + 1,
                    etag,
                })
                .ok_or_else(|| multipart_err(key, format!("part {} never uploaded", i + 1)))
            })
            .collect::<Result<_, _>>()?;
        let completed = self.complete(key, &plan.upload_id, &parts)?;
        if completed.outcome == PutOutcome::Stored {
            let reported = match completed.size {
                Some(n) => Some(n),
                None => self.remote_size(key)?,
            };
            if let Some(n) = reported
                && n != size
            {
                return Err(multipart_err(
                    key,
                    format!("assembled object is {n} bytes, expected {size}"),
                ));
            }
        }
        Ok(completed.outcome)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        let url = self.url(key)?;
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
        let url = self.url(key)?;
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

    fn helper_cpu(&self) -> Duration {
        Duration::from_micros(self.helper_cpu_micros.load(Ordering::Relaxed))
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

    #[test]
    fn local_dir_multipart_is_a_plain_write() {
        let dir = tempfile::tempdir().unwrap();
        let s = LocalDir::new(&dir.path().join("store")).unwrap();
        let f = dir.path().join("big");
        let big: Vec<u8> = (0..100_003u32).map(|i| (i % 253) as u8).collect();
        fs::write(&f, &big).unwrap();
        let key = "captures/wt/1/packs/big";
        assert_eq!(
            s.put_multipart(key, &f, 4096, 4).unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(s.get(key).unwrap(), big);
        assert_eq!(
            s.put_multipart(key, &f, 4096, 4).unwrap(),
            PutOutcome::AlreadyPresent
        );
        assert_eq!(s.helper_cpu(), Duration::ZERO);
    }

    #[test]
    fn part_ranges_and_sizes() {
        assert_eq!(part_range(0, 10, 25), (0, 10));
        assert_eq!(part_range(2, 10, 25), (20, 5));
        let mut h = ureq::http::HeaderMap::new();
        h.insert("content-range", "bytes 0-0/12345".parse().unwrap());
        assert_eq!(size_from_headers(206, &h), Some(12345));
        let mut h = ureq::http::HeaderMap::new();
        h.insert("content-length", "77".parse().unwrap());
        assert_eq!(size_from_headers(200, &h), Some(77));
        assert_eq!(size_from_headers(404, &h), None);
    }
}
