//! I/O errors that name what was done and where. A snap that failed with `No space left on
//! device (os error 28)` said neither which file nor which step; the same error now reads
//! `write /…/.sealantd/capture/objects/manifest-…: No space left on device (os error 28)`.
//! The error keeps its [`io::ErrorKind`], so callers that match on the kind are unchanged.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// An I/O error on a path: what was done (`write`, `rename into`, `mkdir -p`, …), where, and
/// what the filesystem said.
#[derive(Debug)]
pub struct PathIoError {
    /// What was done.
    pub op: &'static str,
    /// Where.
    pub path: PathBuf,
    /// What the filesystem said.
    pub source: io::Error,
}

impl fmt::Display for PathIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.path.display(), self.source)
    }
}

impl std::error::Error for PathIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// `error`, naming `op` and `path` (an error that already names a path is kept as it is).
#[must_use]
pub fn with_path(error: io::Error, op: &'static str, path: &Path) -> io::Error {
    if error
        .get_ref()
        .is_some_and(|inner| inner.is::<PathIoError>())
    {
        return error;
    }
    io::Error::new(
        error.kind(),
        PathIoError {
            op,
            path: path.to_path_buf(),
            source: error,
        },
    )
}

/// [`with_path`] on a result.
pub trait IoAt<T> {
    /// Name `op` and `path` in the error, if any.
    ///
    /// # Errors
    /// The error, naming `op` and `path`.
    fn at(self, op: &'static str, path: &Path) -> io::Result<T>;
}

impl<T> IoAt<T> for io::Result<T> {
    fn at(self, op: &'static str, path: &Path) -> io::Result<T> {
        self.map_err(|error| with_path(error, op, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_operation_and_the_path_and_keeps_the_kind() {
        let error = Err::<(), _>(io::Error::from_raw_os_error(28))
            .at("write", Path::new("/staging/objects/x"))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert!(
            error
                .to_string()
                .starts_with("write /staging/objects/x: No space left on device"),
            "{error}"
        );
        let again = with_path(error, "rename into", Path::new("/elsewhere"));
        assert!(again.to_string().starts_with("write /staging/objects/x"));
    }
}
