//! `sealant-vmm-v1`: the framed binary protocol and HTTP control contracts shared by
//! `sealant-vm-runner` (inside Docker), `sealant-vmd` (macOS launcher), and `sealant-vz-worker`
//! (macOS `Virtualization.framework` per-VM worker).
//!
//! Frame layout over the upgraded TCP socket (9-byte big-endian header):
//! `[u8 kind][u32_be stream_id][u32_be payload_len][payload...]`
//!
//! Stream IDs are partitioned so neither side can ever collide:
//! - Runner-initiated streams (host -> guest `vsock:1024`): odd IDs (`1, 3, 5, ...`).
//! - Worker-initiated streams (guest -> host `vsock:1025`, `1026`, `1027`): even IDs (`2, 4, 6, ...`).
//! - `stream_id = 0` is reserved for `Control` and `EthFrame`.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Wire protocol version negotiated on `POST /v1/vms`.
pub const PROTOCOL_VERSION: u32 = 1;
/// HTTP `Upgrade` token for the runner <-> worker multiplexed transport.
pub const UPGRADE_PROTOCOL: &str = "sealant-vmm-v1";
/// Fixed frame header size in bytes: `kind (1) + stream_id (4) + payload_len (4)`.
pub const FRAME_HEADER_LEN: usize = 9;
/// Maximum raw Ethernet frame length (65520 MTU + 14-byte Ethernet header + headroom).
pub const MAX_ETH_FRAME_BYTES: usize = 65_600;
/// Maximum payload in a single `VsockData` frame.
pub const MAX_VSOCK_DATA_BYTES: usize = 256 * 1024;
/// Maximum payload in a single JSON `Control` frame.
pub const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
/// Maximum payload in a `VsockOpenErr` message.
pub const MAX_ERROR_FRAME_BYTES: usize = 4 * 1024;

/// Discriminator byte at offset 0 of every `sealant-vmm-v1` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Control = 0x01,
    EthFrame = 0x02,
    VsockOpen = 0x03,
    VsockOpenOk = 0x04,
    VsockOpenErr = 0x05,
    VsockData = 0x06,
    VsockFin = 0x07,
    VsockRst = 0x08,
}

impl FrameKind {
    pub fn from_u8(byte: u8) -> Result<Self, ProtoError> {
        match byte {
            0x01 => Ok(Self::Control),
            0x02 => Ok(Self::EthFrame),
            0x03 => Ok(Self::VsockOpen),
            0x04 => Ok(Self::VsockOpenOk),
            0x05 => Ok(Self::VsockOpenErr),
            0x06 => Ok(Self::VsockData),
            0x07 => Ok(Self::VsockFin),
            0x08 => Ok(Self::VsockRst),
            other => Err(ProtoError::UnknownFrameKind(other)),
        }
    }

    pub fn max_payload_len(self) -> usize {
        match self {
            Self::Control => MAX_CONTROL_FRAME_BYTES,
            Self::EthFrame => MAX_ETH_FRAME_BYTES,
            Self::VsockOpen => 4,
            Self::VsockOpenOk | Self::VsockFin | Self::VsockRst => 0,
            Self::VsockOpenErr => MAX_ERROR_FRAME_BYTES,
            Self::VsockData => MAX_VSOCK_DATA_BYTES,
        }
    }
}

/// One framed message on the `sealant-vmm-v1` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn control_json<T: Serialize>(msg: &T) -> Result<Self, ProtoError> {
        let payload = serde_json::to_vec(msg)?;
        if payload.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(ProtoError::FrameTooLarge {
                kind: FrameKind::Control,
                len: payload.len(),
                max: MAX_CONTROL_FRAME_BYTES,
            });
        }
        Ok(Self {
            kind: FrameKind::Control,
            stream_id: 0,
            payload,
        })
    }

    pub fn eth(frame: Vec<u8>) -> Result<Self, ProtoError> {
        if frame.is_empty() || frame.len() > MAX_ETH_FRAME_BYTES {
            return Err(ProtoError::FrameTooLarge {
                kind: FrameKind::EthFrame,
                len: frame.len(),
                max: MAX_ETH_FRAME_BYTES,
            });
        }
        Ok(Self {
            kind: FrameKind::EthFrame,
            stream_id: 0,
            payload: frame,
        })
    }

    pub fn vsock_open(stream_id: u32, port: u32) -> Self {
        Self {
            kind: FrameKind::VsockOpen,
            stream_id,
            payload: port.to_be_bytes().to_vec(),
        }
    }

    pub fn vsock_open_ok(stream_id: u32) -> Self {
        Self {
            kind: FrameKind::VsockOpenOk,
            stream_id,
            payload: Vec::new(),
        }
    }

    pub fn vsock_open_err(stream_id: u32, reason: impl Into<String>) -> Self {
        let mut bytes = reason.into().into_bytes();
        bytes.truncate(MAX_ERROR_FRAME_BYTES);
        Self {
            kind: FrameKind::VsockOpenErr,
            stream_id,
            payload: bytes,
        }
    }

    pub fn vsock_data(stream_id: u32, payload: Vec<u8>) -> Result<Self, ProtoError> {
        if payload.len() > MAX_VSOCK_DATA_BYTES {
            return Err(ProtoError::FrameTooLarge {
                kind: FrameKind::VsockData,
                len: payload.len(),
                max: MAX_VSOCK_DATA_BYTES,
            });
        }
        Ok(Self {
            kind: FrameKind::VsockData,
            stream_id,
            payload,
        })
    }

    pub fn vsock_fin(stream_id: u32) -> Self {
        Self {
            kind: FrameKind::VsockFin,
            stream_id,
            payload: Vec::new(),
        }
    }

    pub fn vsock_rst(stream_id: u32) -> Self {
        Self {
            kind: FrameKind::VsockRst,
            stream_id,
            payload: Vec::new(),
        }
    }

    /// Extracts the 4-byte big-endian vsock port from a [`FrameKind::VsockOpen`] frame.
    pub fn vsock_port(&self) -> Result<u32, ProtoError> {
        if self.kind != FrameKind::VsockOpen || self.payload.len() != 4 {
            return Err(ProtoError::MalformedPayload(
                "VsockOpen requires a 4-byte port",
            ));
        }
        let bytes: [u8; 4] = self
            .payload
            .as_slice()
            .try_into()
            .map_err(|_| ProtoError::MalformedPayload("VsockOpen requires a 4-byte port"))?;
        Ok(u32::from_be_bytes(bytes))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown frame kind 0x{0:02x}")]
    UnknownFrameKind(u8),
    #[error("{kind:?} frame length {len} exceeds maximum {max}")]
    FrameTooLarge {
        kind: FrameKind,
        len: usize,
        max: usize,
    },
    #[error("malformed frame payload: {0}")]
    MalformedPayload(&'static str),
}

/// Reads one frame from an async stream. Returns `Ok(None)` on clean EOF at a frame boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>, ProtoError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    let first = reader.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let kind = FrameKind::from_u8(header[0])?;
    let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let max = kind.max_payload_len();
    if len > max {
        return Err(ProtoError::FrameTooLarge { kind, len, max });
    }
    if kind == FrameKind::VsockOpen && len != 4 {
        return Err(ProtoError::MalformedPayload("VsockOpen length must be 4"));
    }
    if kind == FrameKind::EthFrame && len == 0 {
        return Err(ProtoError::MalformedPayload("EthFrame must not be empty"));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok(Some(Frame {
        kind,
        stream_id,
        payload,
    }))
}

/// Writes one frame to an async stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), ProtoError> {
    let max = frame.kind.max_payload_len();
    if frame.payload.len() > max {
        return Err(ProtoError::FrameTooLarge {
            kind: frame.kind,
            len: frame.payload.len(),
            max,
        });
    }
    let len = u32::try_from(frame.payload.len()).map_err(|_| ProtoError::FrameTooLarge {
        kind: frame.kind,
        len: frame.payload.len(),
        max,
    })?;
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = frame.kind as u8;
    header[1..5].copy_from_slice(&frame.stream_id.to_be_bytes());
    header[5..9].copy_from_slice(&len.to_be_bytes());
    writer.write_all(&header).await?;
    if !frame.payload.is_empty() {
        writer.write_all(&frame.payload).await?;
    }
    Ok(())
}

/// Boot mode shared across HTTP launch requests and worker specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmMode {
    Normal,
    Recover,
}

impl VmMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Recover => "recover",
        }
    }
}

/// macOS memory pressure level reported by `sealant-vmd` and `sealant-vz-worker`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryPressureLevel {
    Normal,
    Warning,
    Critical,
}

/// Control messages sent from `sealant-vm-runner` to `sealant-vz-worker`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RunnerControl {
    RequestStop,
    ForceKill,
    SetBalloonTarget { bytes: u64 },
    Ping,
}

/// Control messages sent from `sealant-vz-worker` to `sealant-vm-runner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WorkerControl {
    #[serde(rename_all = "camelCase")]
    VmStarted {
        boot_time_utc_ms: u64,
        negotiated_mtu: u32,
    },
    #[serde(rename_all = "camelCase")]
    HostWake {
        utc_epoch_ns: u64,
    },
    #[serde(rename_all = "camelCase")]
    MemoryPressure {
        level: MemoryPressureLevel,
    },
    #[serde(rename_all = "camelCase")]
    Console {
        data: String,
    },
    #[serde(rename_all = "camelCase")]
    VmExited {
        clean: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Pong,
}

/// JSON body sent by `sealant-vm-runner` on `POST /v1/vms` (`Upgrade: sealant-vmm-v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchVmRequest {
    pub protocol_version: u32,
    pub vm_name: String,
    pub mode: VmMode,
    pub base_image_key: String,
    pub vcpus: u32,
    pub memory_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub mtu: u32,
}

/// Validated launch specification written to `sealant-vz-worker`'s `stdin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerLaunchSpec {
    pub protocol_version: u32,
    pub vm_name: String,
    pub mode: VmMode,
    pub vm_root: String,
    pub kernel_path: String,
    pub base_image_path: String,
    pub data_image_path: String,
    pub cmdline: String,
    pub vcpus: u32,
    pub memory_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub mtu: u32,
    pub transport_fd: i32,
}

/// Non-loopback host interface addresses reported by `sealant-vmd` so `<name>-proxy` blocks
/// guest egress to the Mac's own IPv4 and IPv6 addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostIps {
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
}

/// JSON response from `GET /v1/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub protocol_version: u32,
    pub version: String,
    pub instance_nonce: String,
    pub kernel_sha256: String,
    pub arch: String,
    pub macos_version: String,
    pub host_ips: HostIps,
    pub memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub memory_pressure: MemoryPressureLevel,
    pub disk_available_important_bytes: u64,
    pub workers_running: u32,
}

/// One check inside `GET /v1/self-test`, matching `sealant-vm-runner --self-test`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestCheck {
    pub name: String,
    pub ok: bool,
    pub observed: String,
    #[serde(flatten)]
    pub facts: serde_json::Map<String, serde_json::Value>,
}

/// JSON report from `GET /v1/self-test` and `sealant-vmd --self-test`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestReport {
    pub version: u32,
    pub ok: bool,
    pub checks: Vec<SelfTestCheck>,
}

/// Constant-time comparison for `Authorization: Bearer <token>` (compares SHA-256 digests so
/// neither contents nor length leak via timing).
#[must_use]
pub fn verify_bearer_token(header_value: &str, expected_token: &str) -> bool {
    let Some(presented) = header_value.strip_prefix("Bearer ") else {
        return false;
    };
    if expected_token.is_empty() {
        return false;
    }
    let a = Sha256::digest(presented.as_bytes());
    let b = Sha256::digest(expected_token.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Validates the HTTP `Host` header against loopback and `host.docker.internal` for `port`,
/// blocking DNS-rebinding attacks from local browser tabs.
#[must_use]
pub fn validate_host_header(host: &str, port: u16) -> bool {
    let expected = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("host.docker.internal:{port}"),
        format!("[::1]:{port}"),
    ];
    expected
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

/// Validates a base image key (`<key>.img` under `images/`): single path segment, no `..` or
/// leading dot.
pub fn validate_base_image_key(key: &str) -> Result<(), &'static str> {
    if key.is_empty() || key.len() > 128 {
        return Err("baseImageKey must be 1..=128 bytes");
    }
    if key.starts_with('.') || key.contains("..") {
        return Err("baseImageKey must not start with '.' or contain '..'");
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err("baseImageKey contains invalid characters");
    }
    Ok(())
}

/// Validates a workspace VM name (`data/<vmName>/data.img`): single safe segment matching Docker
/// container names (`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}`), no `..`.
pub fn validate_vm_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 128 {
        return Err("vmName must be 1..=128 bytes");
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("vmName must not be empty");
    };
    if !first.is_ascii_alphanumeric() {
        return Err("vmName must start with an ASCII alphanumeric character");
    }
    if name.contains("..") {
        return Err("vmName must not contain '..'");
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err("vmName contains invalid characters");
    }
    Ok(())
}

/// Validates a unicast MAC address (`aa:bb:cc:dd:ee:ff`).
pub fn validate_mac(mac: &str) -> Result<String, &'static str> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err("MAC must have 6 colon-separated octets");
    }
    let mut bytes = [0u8; 6];
    for (slot, part) in bytes.iter_mut().zip(&parts) {
        if part.len() != 2 {
            return Err("MAC octet must be 2 hex digits");
        }
        *slot = u8::from_str_radix(part, 16).map_err(|_| "MAC octet must be hex")?;
    }
    if bytes[0] & 0x01 != 0 {
        return Err("MAC must be unicast");
    }
    Ok(bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Builds the exact Linux microVM guest kernel command line for `console` (`hvc0` on Apple VZ).
#[must_use]
pub fn kernel_cmdline(console: &str, mode: VmMode) -> String {
    format!(
        "console={console} root=/dev/vda ro init=/usr/local/bin/sealantd sealantd.mode={} -- --vm",
        mode.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_enforce_bounds() {
        let frames = vec![
            Frame::control_json(&RunnerControl::SetBalloonTarget {
                bytes: 2 * 1024 * 1024 * 1024,
            })
            .unwrap(),
            Frame::control_json(&WorkerControl::HostWake {
                utc_epoch_ns: 1_795_800_000_000_000_000,
            })
            .unwrap(),
            Frame::eth(vec![0xaa; 1514]).unwrap(),
            Frame::vsock_open(1, 1024),
            Frame::vsock_open_ok(1),
            Frame::vsock_open_err(2, "refused"),
            Frame::vsock_data(1, b"hello".to_vec()).unwrap(),
            Frame::vsock_fin(1),
            Frame::vsock_rst(2),
        ];

        let mut wire = Vec::new();
        for f in &frames {
            write_frame(&mut wire, f).await.unwrap();
        }
        let mut cursor = wire.as_slice();
        for expected in &frames {
            let got = read_frame(&mut cursor).await.unwrap().unwrap();
            assert_eq!(&got, expected);
        }
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_or_unknown_frames_are_rejected() {
        // Unknown kind 0x99
        let bad_kind = [0x99u8, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            read_frame(&mut bad_kind.as_slice()).await,
            Err(ProtoError::UnknownFrameKind(0x99))
        ));
        // Oversized EthFrame
        let mut too_big = [0u8; 9];
        too_big[0] = FrameKind::EthFrame as u8;
        too_big[5..9].copy_from_slice(&((MAX_ETH_FRAME_BYTES as u32) + 1).to_be_bytes());
        assert!(matches!(
            read_frame(&mut too_big.as_slice()).await,
            Err(ProtoError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn validators_reject_traversal_and_dns_rebinding() {
        assert!(validate_base_image_key("sha256-0123456789abcdef").is_ok());
        assert!(validate_base_image_key("../etc/passwd").is_err());
        assert!(validate_base_image_key(".hidden").is_err());
        assert!(validate_base_image_key("a/b").is_err());

        assert!(validate_vm_name("mend-ws-abc123").is_ok());
        assert!(validate_vm_name("../escape").is_err());
        assert!(validate_vm_name("-dash").is_err());
        assert!(validate_vm_name("a/b").is_err());

        assert!(validate_host_header("127.0.0.1:49152", 49152));
        assert!(validate_host_header("host.docker.internal:49152", 49152));
        assert!(!validate_host_header("evil.example:49152", 49152));
        assert!(!validate_host_header("127.0.0.1:9999", 49152));

        assert!(verify_bearer_token("Bearer secret123", "secret123"));
        assert!(!verify_bearer_token("Bearer secret124", "secret123"));
        assert!(!verify_bearer_token("Basic secret123", "secret123"));
        assert!(!verify_bearer_token("Bearer ", ""));

        assert_eq!(
            kernel_cmdline("hvc0", VmMode::Normal),
            "console=hvc0 root=/dev/vda ro init=/usr/local/bin/sealantd sealantd.mode=normal -- --vm"
        );
    }
}
