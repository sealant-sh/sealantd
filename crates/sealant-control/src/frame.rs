//! Length-prefixed frame I/O.
//!
//! Each frame is a big-endian `u32` length prefix followed by exactly that many bytes of JSON. The
//! declared length is checked against the configured maximum *before* the body buffer is allocated,
//! so a hostile peer cannot force a large allocation.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Errors reading or writing a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The declared (or actual) frame length exceeded the configured maximum.
    #[error("frame length {len} exceeds maximum {max}")]
    TooLarge {
        /// Declared frame length.
        len: u32,
        /// Configured maximum.
        max: u32,
    },
    /// An underlying I/O error.
    #[error(transparent)]
    Io(std::io::Error),
}

/// Read one frame body. Returns `Ok(None)` on a clean end-of-stream at a frame boundary.
///
/// # Errors
/// Returns [`FrameError::TooLarge`] if the declared length exceeds `max_frame_bytes` (before any
/// body allocation), or [`FrameError::Io`] on a transport error or a truncated frame.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame_bytes: u32,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > max_frame_bytes {
        return Err(FrameError::TooLarge {
            len,
            max: max_frame_bytes,
        });
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await.map_err(FrameError::Io)?;
    Ok(Some(body))
}

/// Write one frame body, prefixed with its big-endian `u32` length, then flush.
///
/// # Errors
/// Returns [`FrameError::TooLarge`] if `body` exceeds `max_frame_bytes`, or [`FrameError::Io`] on a
/// transport error.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
    max_frame_bytes: u32,
) -> Result<(), FrameError> {
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        len: u32::MAX,
        max: max_frame_bytes,
    })?;
    if len > max_frame_bytes {
        return Err(FrameError::TooLarge {
            len,
            max: max_frame_bytes,
        });
    }
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(FrameError::Io)?;
    writer.write_all(body).await.map_err(FrameError::Io)?;
    writer.flush().await.map_err(FrameError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_a_frame() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let payload = b"hello frame";
        write_frame(&mut a, payload, 1024).await.expect("write");
        let body = read_frame(&mut b, 1024).await.expect("read").expect("some");
        assert_eq!(body, payload);
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        let got = read_frame(&mut b, 64).await.expect("read");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn oversized_declared_length_is_rejected_before_alloc() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Declare a 4 GiB body without sending it.
        a.write_all(&u32::MAX.to_be_bytes()).await.expect("len");
        a.flush().await.expect("flush");
        let err = read_frame(&mut b, 1024).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { max: 1024, .. }));
    }

    #[tokio::test]
    async fn writing_oversized_body_is_rejected() {
        let (mut a, _b) = tokio::io::duplex(64);
        let big = vec![0u8; 2048];
        let err = write_frame(&mut a, &big, 1024).await.unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge {
                len: 2048,
                max: 1024
            }
        ));
    }
}
