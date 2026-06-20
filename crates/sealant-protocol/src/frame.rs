//! Wire framing constants.
//!
//! Every protocol message is a single frame: a big-endian `u32` length prefix followed by exactly
//! that many bytes of UTF-8 JSON. The maximum frame size is validated *before* allocation so a
//! hostile or buggy peer cannot force a large allocation. One `read()` never equals one message;
//! the codec in `sealant-control` reassembles frames from the byte stream.

/// Number of bytes in the big-endian `u32` length prefix that precedes every frame body.
pub const LENGTH_PREFIX_BYTES: usize = 4;

/// Default maximum frame body size (8 MiB) when not overridden by configuration.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;

/// Lower bound for a configured maximum frame size; smaller requests are clamped up to this.
pub const MIN_MAX_FRAME_BYTES: u32 = 1024;

/// Clamp a requested maximum-frame size into the supported range.
#[must_use]
pub fn clamp_max_frame_bytes(requested: u32) -> u32 {
    requested.max(MIN_MAX_FRAME_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_small_values_up() {
        assert_eq!(clamp_max_frame_bytes(0), MIN_MAX_FRAME_BYTES);
        assert_eq!(clamp_max_frame_bytes(512), MIN_MAX_FRAME_BYTES);
        assert_eq!(
            clamp_max_frame_bytes(DEFAULT_MAX_FRAME_BYTES),
            DEFAULT_MAX_FRAME_BYTES
        );
    }
}
