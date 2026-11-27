//! Remote macOS `Virtualization.framework` VMM backend (`--vmm-backend mac-vmd`).
//!
//! Connects to `sealant-vmd` over `host.docker.internal:<port>`, upgrades the connection to
//! `sealant-vmm-v1` (which `sealant-vmd` hands straight to `sealant-vz-worker` via FD 3), and
//! multiplexes raw `tap0` frames, `vsock` 1024–1027 streams, `HostWake` → `runtime.syncClock`
//! RPCs, memory-pressure balloon targets, and graceful stop over that single TCP link.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sealant_protocol::{
    ClientMessage, Command, ControlRequest, RequestId, SCHEMA_VERSION, encode_client,
};
use sealant_vmm_proto::{
    Frame, FrameKind, LaunchVmRequest, MAX_ETH_FRAME_BYTES, MAX_VSOCK_DATA_BYTES,
    MemoryPressureLevel, PROTOCOL_VERSION, RunnerControl, UPGRADE_PROTOCOL, VmMode, WorkerControl,
    read_frame, write_frame,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc, oneshot, watch};

use crate::exit::{ExitRecorder, VmmExit};
use crate::protocol::{self, BootMode, GuestExitStatus};
use crate::retry::after_accept_error;
use crate::tap::Tap;
use crate::vsock;

/// Default MTU negotiated over `VZFileHandleNetworkDeviceAttachment` on macOS (Gate 0 proved
/// 2,423–4,270 MB/s on OrbStack and 249–329 MB/s on Docker Desktop with zero drops at 65520).
pub const DEFAULT_MAC_MTU: u32 = 65_520;
const PERIODIC_CLOCK_SYNC_INTERVAL: Duration = Duration::from_secs(60);
const MIN_BALLOON_TARGET_BYTES: u64 = 512 * 1024 * 1024;
const VSOCK_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP_HEAD: usize = 8 * 1024;
const MAX_BOOT_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct MacVmdConfig {
    pub host: String,
    pub host_ip: IpAddr,
    pub port: u16,
    pub bearer_token: String,
    pub vm_name: String,
    pub mode: BootMode,
    pub base_image_key: String,
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub mac: Option<String>,
    pub mtu: u32,
    pub sealant_run_dir: PathBuf,
    pub shutdown_grace: Duration,
}

enum StreamEvent {
    Data(Vec<u8>),
    Fin,
    Rst,
}

#[derive(Default)]
struct MuxState {
    pending_opens: HashMap<u32, oneshot::Sender<Result<(), String>>>,
    streams: HashMap<u32, mpsc::Sender<StreamEvent>>,
}

struct RemoteMux {
    out_tx: mpsc::Sender<Frame>,
    state: Arc<Mutex<MuxState>>,
    next_odd_id: AtomicU32,
}

impl RemoteMux {
    fn new(out_tx: mpsc::Sender<Frame>, state: Arc<Mutex<MuxState>>) -> Arc<Self> {
        Arc::new(Self {
            out_tx,
            state,
            next_odd_id: AtomicU32::new(1),
        })
    }

    fn alloc_odd_id(&self) -> u32 {
        let mut id = self.next_odd_id.fetch_add(2, Ordering::Relaxed);
        if id == 0 || id.is_multiple_of(2) {
            id = 1;
        }
        id
    }

    async fn open_guest_port(&self, port: u32) -> io::Result<(u32, mpsc::Receiver<StreamEvent>)> {
        let stream_id = self.alloc_odd_id();
        let (open_tx, open_rx) = oneshot::channel();
        let (ev_tx, ev_rx) = mpsc::channel(64);
        {
            let mut guard = self.state.lock().await;
            guard.pending_opens.insert(stream_id, open_tx);
            guard.streams.insert(stream_id, ev_tx);
        }
        if self
            .out_tx
            .send(Frame::vsock_open(stream_id, port))
            .await
            .is_err()
        {
            let mut guard = self.state.lock().await;
            guard.pending_opens.remove(&stream_id);
            guard.streams.remove(&stream_id);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mac-vmd transport closed",
            ));
        }
        match tokio::time::timeout(VSOCK_OPEN_TIMEOUT, open_rx).await {
            Ok(Ok(Ok(()))) => Ok((stream_id, ev_rx)),
            Ok(Ok(Err(reason))) => {
                self.state.lock().await.streams.remove(&stream_id);
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, reason))
            }
            Ok(Err(_)) | Err(_) => {
                let mut guard = self.state.lock().await;
                guard.pending_opens.remove(&stream_id);
                guard.streams.remove(&stream_id);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("vsock:{port} open timed out"),
                ))
            }
        }
    }

    async fn send_control(&self, msg: &RunnerControl) {
        if let Ok(frame) = Frame::control_json(msg) {
            let _ = self.out_tx.send(frame).await;
        }
    }
}

/// Runs one microVM lifecycle against `sealant-vmd` → `sealant-vz-worker` and returns how the
/// remote VMM exited (clean exit `Code(0)` vs error `Code(1)`), while populating `exits`.
pub async fn run_vm(
    cfg: &MacVmdConfig,
    tap: Option<Tap>,
    boot_frame: String,
    exits: ExitRecorder,
) -> io::Result<VmmExit> {
    let tcp = connect_and_upgrade(cfg).await?;
    let _ = tcp.set_nodelay(true);
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(512);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if write_frame(&mut tcp_write, &frame).await.is_err() {
                break;
            }
            // Drain any already-queued frames before flushing to keep batching overhead low.
            while let Ok(next) = out_rx.try_recv() {
                if write_frame(&mut tcp_write, &next).await.is_err() {
                    return;
                }
            }
            if tcp_write.flush().await.is_err() {
                break;
            }
        }
    });

    let mux_state = Arc::new(Mutex::new(MuxState::default()));
    let mux = RemoteMux::new(out_tx.clone(), Arc::clone(&mux_state));

    // Bind /run/sealant/control.sock and forward every client to guest vsock:1024.
    let control_listener = vsock::bind_unix(&cfg.sealant_run_dir.join("control.sock"), 0o660)?;
    let control_mux = Arc::clone(&mux);
    let control_task = tokio::spawn(async move {
        serve_control_listener(control_listener, control_mux).await;
    });

    // Optional raw tap0 pump (normal mode only).
    let (tap_in_tx, mut tap_in_rx) = mpsc::channel::<Vec<u8>>(256);
    let tap_tasks = if let Some(tap) = tap {
        let owned: OwnedFd = tap.into_owned_fd();
        let async_fd = Arc::new(AsyncFd::new(owned)?);
        let reader_fd = Arc::clone(&async_fd);
        let reader_out = out_tx.clone();
        let t_read = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_ETH_FRAME_BYTES];
            loop {
                let Ok(mut guard) = reader_fd.readable().await else {
                    break;
                };
                match guard.try_io(|inner| nix_read(inner.get_ref(), &mut buf)) {
                    Ok(Ok(n)) if n > 0 => {
                        if let Ok(frame) = Frame::eth(buf[..n].to_vec())
                            && reader_out.send(frame).await.is_err()
                        {
                            break;
                        }
                    }
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(Err(_)) => break,
                    Err(_would_block) => continue,
                }
            }
        });
        let writer_fd = Arc::clone(&async_fd);
        let t_write = tokio::spawn(async move {
            while let Some(pkt) = tap_in_rx.recv().await {
                let Ok(mut guard) = writer_fd.writable().await else {
                    break;
                };
                let _ = guard.try_io(|inner| nix_write(inner.get_ref(), &pkt));
            }
        });
        Some((t_read, t_write))
    } else {
        None
    };

    // Periodic 60s clock-sync fallback while awake (supplements immediate HostWake sync).
    let clock_mux = Arc::clone(&mux);
    let clock_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(PERIODIC_CLOCK_SYNC_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let ns = dur.as_nanos().min(u128::from(u64::MAX)) as u64;
                sync_guest_clock(&clock_mux, ns).await;
            }
        }
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (exited_tx, mut exited_rx) = oneshot::channel::<VmmExit>();

    let reader_cfg = cfg.clone();
    let reader_mux = Arc::clone(&mux);
    let reader_state = Arc::clone(&mux_state);
    let reader_out = out_tx.clone();
    let reader_exits = exits.clone();
    let reader_task = tokio::spawn(async move {
        let mut exited_tx = Some(exited_tx);
        let mut boot_accepted = false;
        while let Ok(Some(frame)) = read_frame(&mut tcp_read).await {
            match frame.kind {
                FrameKind::Control => {
                    let Ok(msg) = serde_json::from_slice::<WorkerControl>(&frame.payload) else {
                        tracing::warn!("ignoring malformed worker control frame");
                        continue;
                    };
                    match msg {
                        WorkerControl::VmStarted {
                            boot_time_utc_ms,
                            negotiated_mtu,
                        } => {
                            tracing::info!(
                                boot_time_utc_ms,
                                negotiated_mtu,
                                "macOS VZ microVM started"
                            );
                        }
                        WorkerControl::HostWake { utc_epoch_ns } => {
                            tracing::info!(
                                utc_epoch_ns,
                                "macOS host wake observed; syncing guest clock"
                            );
                            let m = Arc::clone(&reader_mux);
                            tokio::spawn(async move {
                                sync_guest_clock(&m, utc_epoch_ns).await;
                            });
                        }
                        WorkerControl::MemoryPressure { level } => {
                            let target =
                                balloon_target_for_pressure(reader_cfg.memory_bytes, level);
                            tracing::info!(
                                ?level,
                                target_bytes = target,
                                "adjusting VZ balloon target"
                            );
                            reader_mux
                                .send_control(&RunnerControl::SetBalloonTarget { bytes: target })
                                .await;
                        }
                        WorkerControl::Console { data } => {
                            for line in data.lines() {
                                if !line.trim().is_empty() {
                                    tracing::debug!(guest_console = line);
                                }
                            }
                        }
                        WorkerControl::VmExited { clean, error } => {
                            if let Some(err) = &error {
                                tracing::warn!(clean, error = %err, "sealant-vz-worker reported VM exit");
                            }
                            if let Some(tx) = exited_tx.take() {
                                let code = if clean {
                                    VmmExit::Code(0)
                                } else {
                                    VmmExit::Code(1)
                                };
                                let _ = tx.send(code);
                            }
                            break;
                        }
                        WorkerControl::Pong => {}
                    }
                }
                FrameKind::EthFrame => {
                    let _ = tap_in_tx.try_send(frame.payload);
                }
                FrameKind::VsockOpen => {
                    let Ok(port) = frame.vsock_port() else {
                        let _ = reader_out
                            .send(Frame::vsock_open_err(frame.stream_id, "bad port"))
                            .await;
                        continue;
                    };
                    match port {
                        vsock::BOOT_PORT => {
                            if boot_accepted {
                                let _ = reader_out
                                    .send(Frame::vsock_open_err(
                                        frame.stream_id,
                                        "boot channel already used",
                                    ))
                                    .await;
                                continue;
                            }
                            boot_accepted = true;
                            let (ev_tx, ev_rx) = mpsc::channel(64);
                            reader_state
                                .lock()
                                .await
                                .streams
                                .insert(frame.stream_id, ev_tx);
                            let _ = reader_out.send(Frame::vsock_open_ok(frame.stream_id)).await;
                            tokio::spawn(drive_remote_boot(
                                frame.stream_id,
                                ev_rx,
                                reader_out.clone(),
                                Arc::clone(&reader_state),
                                boot_frame.clone(),
                                reader_exits.clone(),
                                shutdown_rx.clone(),
                            ));
                        }
                        vsock::CAPTURE_PORT => {
                            let target = reader_cfg.sealant_run_dir.join("capture.sock");
                            spawn_guest_to_unix(
                                frame.stream_id,
                                target,
                                reader_out.clone(),
                                Arc::clone(&reader_state),
                            )
                            .await;
                        }
                        vsock::SESSION_PORT if reader_cfg.mode == BootMode::Normal => {
                            let target = reader_cfg.sealant_run_dir.join("session.sock");
                            spawn_guest_to_unix(
                                frame.stream_id,
                                target,
                                reader_out.clone(),
                                Arc::clone(&reader_state),
                            )
                            .await;
                        }
                        _ => {
                            let _ = reader_out
                                .send(Frame::vsock_open_err(
                                    frame.stream_id,
                                    format!("unsupported guest vsock port {port}"),
                                ))
                                .await;
                        }
                    }
                }
                FrameKind::VsockOpenOk => {
                    if let Some(tx) = reader_state
                        .lock()
                        .await
                        .pending_opens
                        .remove(&frame.stream_id)
                    {
                        let _ = tx.send(Ok(()));
                    }
                }
                FrameKind::VsockOpenErr => {
                    let msg = String::from_utf8_lossy(&frame.payload).into_owned();
                    let mut guard = reader_state.lock().await;
                    guard.streams.remove(&frame.stream_id);
                    if let Some(tx) = guard.pending_opens.remove(&frame.stream_id) {
                        let _ = tx.send(Err(msg));
                    }
                }
                FrameKind::VsockData => {
                    let tx = reader_state
                        .lock()
                        .await
                        .streams
                        .get(&frame.stream_id)
                        .cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(StreamEvent::Data(frame.payload)).await;
                    }
                }
                FrameKind::VsockFin => {
                    let tx = reader_state
                        .lock()
                        .await
                        .streams
                        .get(&frame.stream_id)
                        .cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(StreamEvent::Fin).await;
                    }
                }
                FrameKind::VsockRst => {
                    if let Some(tx) = reader_state.lock().await.streams.remove(&frame.stream_id) {
                        let _ = tx.send(StreamEvent::Rst).await;
                    }
                }
            }
        }
        // Transport EOF without an explicit clean VmExited is an unclean VMM exit (never 76!).
        if let Some(tx) = exited_tx.take() {
            let _ = tx.send(VmmExit::Code(1));
        }
    });

    // Wait for VM exit OR SIGTERM/SIGINT graceful shutdown.
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let vmm_exit = tokio::select! {
        res = &mut exited_rx => res.unwrap_or(VmmExit::Code(1)),
        _ = term.recv() => {
            tracing::info!("SIGTERM: asking macOS VZ guest to shut down");
            graceful_stop(&mux, &shutdown_tx, &mut exited_rx, cfg.shutdown_grace, &mut term, &mut int).await
        }
        _ = int.recv() => {
            tracing::info!("SIGINT: asking macOS VZ guest to shut down");
            graceful_stop(&mux, &shutdown_tx, &mut exited_rx, cfg.shutdown_grace, &mut term, &mut int).await
        }
    };

    control_task.abort();
    clock_task.abort();
    if let Some((t1, t2)) = tap_tasks {
        t1.abort();
        t2.abort();
    }
    reader_task.abort();
    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), writer_task).await;

    Ok(vmm_exit)
}

async fn graceful_stop(
    mux: &RemoteMux,
    shutdown_tx: &watch::Sender<bool>,
    exited_rx: &mut oneshot::Receiver<VmmExit>,
    grace: Duration,
    term: &mut tokio::signal::unix::Signal,
    int: &mut tokio::signal::unix::Signal,
) -> VmmExit {
    shutdown_tx.send_replace(true);
    mux.send_control(&RunnerControl::RequestStop).await;
    tokio::select! {
        res = &mut *exited_rx => return res.unwrap_or(VmmExit::Code(1)),
        _ = tokio::time::sleep(grace) => {
            tracing::warn!(?grace, "guest did not power off in time; sending ForceKill");
        }
        _ = term.recv() => tracing::warn!("second SIGTERM: sending ForceKill"),
        _ = int.recv() => tracing::warn!("second SIGINT: sending ForceKill"),
    }
    mux.send_control(&RunnerControl::ForceKill).await;
    match tokio::time::timeout(Duration::from_secs(5), exited_rx).await {
        Ok(Ok(exit)) => exit,
        _ => VmmExit::Code(1),
    }
}

/// Computes the target VZ balloon memory size for a macOS memory-pressure notification.
#[must_use]
pub fn balloon_target_for_pressure(max_memory_bytes: u64, level: MemoryPressureLevel) -> u64 {
    match level {
        MemoryPressureLevel::Normal => max_memory_bytes,
        MemoryPressureLevel::Warning => (max_memory_bytes / 2)
            .max(MIN_BALLOON_TARGET_BYTES)
            .min(max_memory_bytes),
        MemoryPressureLevel::Critical => MIN_BALLOON_TARGET_BYTES.min(max_memory_bytes),
    }
}

async fn connect_and_upgrade(cfg: &MacVmdConfig) -> io::Result<TcpStream> {
    let addr = SocketAddr::new(cfg.host_ip, cfg.port);
    let mut stream = TcpStream::connect(addr).await.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("connecting to sealant-vmd at {addr}: {e}"),
        )
    })?;
    let launch_req = LaunchVmRequest {
        protocol_version: PROTOCOL_VERSION,
        vm_name: cfg.vm_name.clone(),
        mode: match cfg.mode {
            BootMode::Normal => VmMode::Normal,
            BootMode::Recover => VmMode::Recover,
        },
        base_image_key: cfg.base_image_key.clone(),
        vcpus: cfg.vcpus,
        memory_bytes: cfg.memory_bytes,
        mac: cfg.mac.clone(),
        mtu: cfg.mtu,
    };
    let body = serde_json::to_vec(&launch_req).map_err(io::Error::other)?;
    let req_head = format!(
        "POST /v1/vms HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Bearer {}\r\nConnection: Upgrade\r\nUpgrade: {UPGRADE_PROTOCOL}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        cfg.host,
        cfg.port,
        cfg.bearer_token,
        body.len()
    );
    stream.write_all(req_head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    // Read HTTP response header byte-by-byte so we never over-read into sealant-vmm-v1 frames!
    let mut head = Vec::with_capacity(256);
    while head.len() < MAX_HTTP_HEAD {
        let byte = stream.read_u8().await?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let status_line = head_str.lines().next().unwrap_or("");
    if !status_line.starts_with("HTTP/1.1 101 ") {
        return Err(io::Error::other(format!(
            "sealant-vmd refused launch upgrade: {status_line:?}"
        )));
    }
    Ok(stream)
}

async fn serve_control_listener(listener: tokio::net::UnixListener, mux: Arc<RemoteMux>) {
    loop {
        let client = match listener.accept().await {
            Ok((c, _)) => c,
            Err(e) => {
                after_accept_error("mac-vmd control bridge", &e).await;
                continue;
            }
        };
        let mux = Arc::clone(&mux);
        tokio::spawn(async move {
            match mux.open_guest_port(vsock::CONTROL_PORT).await {
                Ok((stream_id, ev_rx)) => {
                    pump_unix_and_mux(
                        stream_id,
                        client,
                        ev_rx,
                        mux.out_tx.clone(),
                        Arc::clone(&mux.state),
                    )
                    .await;
                }
                Err(e) => tracing::warn!("guest vsock:1024 unreachable: {e}"),
            }
        });
    }
}

async fn spawn_guest_to_unix(
    stream_id: u32,
    target: PathBuf,
    out_tx: mpsc::Sender<Frame>,
    state: Arc<Mutex<MuxState>>,
) {
    let (ev_tx, ev_rx) = mpsc::channel(64);
    state.lock().await.streams.insert(stream_id, ev_tx);
    tokio::spawn(async move {
        match UnixStream::connect(&target).await {
            Ok(unix) => {
                let _ = out_tx.send(Frame::vsock_open_ok(stream_id)).await;
                pump_unix_and_mux(stream_id, unix, ev_rx, out_tx, state).await;
            }
            Err(e) => {
                state.lock().await.streams.remove(&stream_id);
                let _ = out_tx
                    .send(Frame::vsock_open_err(stream_id, e.to_string()))
                    .await;
            }
        }
    });
}

async fn pump_unix_and_mux(
    stream_id: u32,
    unix: UnixStream,
    mut ev_rx: mpsc::Receiver<StreamEvent>,
    out_tx: mpsc::Sender<Frame>,
    state: Arc<Mutex<MuxState>>,
) {
    let (mut u_read, mut u_write) = unix.into_split();
    let tx_out = out_tx.clone();
    let to_mux = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match u_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = tx_out.send(Frame::vsock_fin(stream_id)).await;
                    break;
                }
                Ok(n) => {
                    let chunk = buf[..n].to_vec();
                    if let Ok(frame) = Frame::vsock_data(stream_id, chunk)
                        && tx_out.send(frame).await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let _ = tx_out.send(Frame::vsock_rst(stream_id)).await;
                    break;
                }
            }
        }
    });

    while let Some(ev) = ev_rx.recv().await {
        match ev {
            StreamEvent::Data(bytes) => {
                if u_write.write_all(&bytes).await.is_err() {
                    let _ = out_tx.send(Frame::vsock_rst(stream_id)).await;
                    break;
                }
            }
            StreamEvent::Fin => {
                let _ = u_write.shutdown().await;
                break;
            }
            StreamEvent::Rst => break,
        }
    }
    let _ = to_mux.await;
    state.lock().await.streams.remove(&stream_id);
}

async fn drive_remote_boot(
    stream_id: u32,
    mut ev_rx: mpsc::Receiver<StreamEvent>,
    out_tx: mpsc::Sender<Frame>,
    state: Arc<Mutex<MuxState>>,
    boot_frame: String,
    exits: ExitRecorder,
    mut shutdown: watch::Receiver<bool>,
) {
    if let Ok(f) = Frame::vsock_data(stream_id, boot_frame.into_bytes())
        && out_tx.send(f).await.is_err()
    {
        state.lock().await.streams.remove(&stream_id);
        return;
    }

    let mut line_buf = Vec::<u8>::new();
    let mut shutdown_pending = true;
    loop {
        tokio::select! {
            ev = ev_rx.recv() => {
                match ev {
                    Some(StreamEvent::Data(bytes)) => {
                        line_buf.extend_from_slice(&bytes);
                        if line_buf.len() > MAX_BOOT_FRAME_BYTES {
                            tracing::warn!("remote boot channel frame too long");
                            break;
                        }
                        while let Some(nl) = line_buf.iter().position(|&b| b == b'\n') {
                            let line_bytes: Vec<u8> = line_buf.drain(..=nl).collect();
                            let line = String::from_utf8_lossy(&line_bytes);
                            if line.trim().is_empty() {
                                continue;
                            }
                            match GuestExitStatus::parse_frame(&line) {
                                Ok(status) => {
                                    tracing::info!(
                                        exit_code = status.exit_code,
                                        synced = status.synced,
                                        reason = status.reason.as_deref().unwrap_or(""),
                                        "guest exit status (mac-vmd)"
                                    );
                                    exits.record(status);
                                    if let Ok(ack) = Frame::vsock_data(
                                        stream_id,
                                        protocol::exit_ack_line().into_bytes(),
                                    ) {
                                        let _ = out_tx.send(ack).await;
                                    }
                                }
                                Err(e) => tracing::warn!("ignoring boot frame: {e}"),
                            }
                        }
                    }
                    Some(StreamEvent::Fin | StreamEvent::Rst) | None => break,
                }
            }
            changed = shutdown.changed(), if shutdown_pending => {
                match changed {
                    Ok(()) if *shutdown.borrow() => {
                        shutdown_pending = false;
                        if let Ok(f) = Frame::vsock_data(
                            stream_id,
                            protocol::shutdown_line().into_bytes(),
                        ) {
                            let _ = out_tx.send(f).await;
                        }
                    }
                    Ok(()) => {}
                    Err(_) => shutdown_pending = false,
                }
            }
        }
    }
    state.lock().await.streams.remove(&stream_id);
}

/// Sends one `runtime.syncClock` Protobuf control frame over an internal `vsock:1024` stream.
async fn sync_guest_clock(mux: &RemoteMux, unix_epoch_ns: u64) {
    let Ok((stream_id, mut ev_rx)) = mux.open_guest_port(vsock::CONTROL_PORT).await else {
        return;
    };
    let req = ClientMessage::Request(ControlRequest {
        schema_version: SCHEMA_VERSION,
        request_id: RequestId::new("vm-runner-sync-clock"),
        command: Command::RuntimeSyncClock { unix_epoch_ns },
        trace: None,
    });
    let payload = encode_client(&req);
    let Ok(len) = u32::try_from(payload.len()) else {
        return;
    };
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&payload);
    if framed.len() <= MAX_VSOCK_DATA_BYTES
        && let Ok(frame) = Frame::vsock_data(stream_id, framed)
    {
        let _ = mux.out_tx.send(frame).await;
        let _ = mux.out_tx.send(Frame::vsock_fin(stream_id)).await;
    }
    // Wait briefly for the guest's reply (or ignore if guest is shutting down / predates command).
    let _ = tokio::time::timeout(Duration::from_secs(2), ev_rx.recv()).await;
    let _ = mux.out_tx.send(Frame::vsock_rst(stream_id)).await;
    mux.state.lock().await.streams.remove(&stream_id);
}

fn nix_read(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    nix::unistd::read(fd, buf).map_err(io::Error::from)
}

fn nix_write(fd: &OwnedFd, buf: &[u8]) -> io::Result<usize> {
    nix::unistd::write(fd, buf).map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn balloon_targets_scale_safely_with_pressure() {
        let max = 4 * 1024 * 1024 * 1024;
        assert_eq!(
            balloon_target_for_pressure(max, MemoryPressureLevel::Normal),
            max
        );
        assert_eq!(
            balloon_target_for_pressure(max, MemoryPressureLevel::Warning),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(
            balloon_target_for_pressure(max, MemoryPressureLevel::Critical),
            MIN_BALLOON_TARGET_BYTES
        );
    }

    #[tokio::test]
    async fn end_to_end_mac_vmd_boot_vsock_clock_sync_and_exit_76() {
        let tmp = tempfile::tempdir().unwrap();
        let vm_root = tmp.path().join("vm");
        let run_dir = tmp.path().join("run");
        std::fs::create_dir_all(vm_root.join("images")).unwrap();
        std::fs::create_dir_all(vm_root.join("data/ws-e2e")).unwrap();
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(vm_root.join("images/sha256-abc.img"), b"base").unwrap();
        std::fs::write(vm_root.join("data/ws-e2e/data.img"), b"data").unwrap();
        let kernel = tmp.path().join("Image");
        std::fs::write(&kernel, b"fake-kernel").unwrap();

        let worker = tmp.path().join("fake-vz-worker.py");
        std::fs::write(
            &worker,
            r#"#!/usr/bin/env python3
import json, os, struct, sys

spec = json.loads(sys.stdin.read())
fd = spec["transportFd"]

def send(kind, sid, payload=b""):
    os.write(fd, struct.pack(">BII", kind, sid, len(payload)) + payload)

def read_exact(n):
    buf = bytearray()
    while len(buf) < n:
        c = os.read(fd, n - len(buf))
        if not c:
            raise EOFError()
        buf.extend(c)
    return bytes(buf)

def recv():
    k, sid, ln = struct.unpack(">BII", read_exact(9))
    return k, sid, read_exact(ln)

# 1. Announce VmStarted
send(1, 0, json.dumps({"type": "vmStarted", "bootTimeUtcMs": 999, "negotiatedMtu": spec["mtu"]}).encode())
# 2. Open single-use vsock:1026 (even stream_id=2)
send(3, 2, struct.pack(">I", 1026))
k, sid, _ = recv()
assert (k, sid) == (4, 2), (k, sid)
# Receive boot config frame on stream 2
k, sid, boot_data = recv()
assert k == 6 and sid == 2 and b'"version":1' in boot_data

# 3. Emit HostWake and verify runner opens vsock:1024 and sends a length-prefixed protobuf frame!
send(1, 0, json.dumps({"type": "hostWake", "utcEpochNs": 1795800000000000000}).encode())
k, clock_sid, port_bytes = recv()
assert k == 3 and (clock_sid % 2 == 1) and struct.unpack(">I", port_bytes)[0] == 1024
send(4, clock_sid)
k, sid, sync_frame = recv()
assert k == 6 and sid == clock_sid and len(sync_frame) > 4
send(7, clock_sid)  # Fin

# 4. Send synced exit 76 on vsock:1026 and receive exitAck
send(6, 2, b'{"version":1,"type":"exit","exitCode":76,"synced":true}\n')
while True:
    k, sid, payload = recv()
    if k == 6 and sid == 2 and b'"exitAck"' in payload:
        break
send(7, 2)
# 5. Report clean VmExited
send(1, 0, json.dumps({"type": "vmExited", "clean": True}).encode())
"#,
        )
        .unwrap();
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o755)).unwrap();

        let (listener, state) = sealant_vmd::server::bind(sealant_vmd::server::Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bearer_token: "test-token-0123456789abcdef0123456789".to_owned(),
            vm_root,
            kernel_path: kernel,
            worker_path: worker,
        })
        .await
        .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop_tx, stop_rx) = watch::channel(false);
        let srv = tokio::spawn(sealant_vmd::server::serve(listener, state, stop_rx));

        let exits = ExitRecorder::default();
        let vmm_exit = run_vm(
            &MacVmdConfig {
                host: "127.0.0.1".to_owned(),
                host_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
                bearer_token: "test-token-0123456789abcdef0123456789".to_owned(),
                vm_name: "ws-e2e".to_owned(),
                mode: BootMode::Normal,
                base_image_key: "sha256-abc".to_owned(),
                vcpus: 2,
                memory_bytes: 1024 * 1024 * 1024,
                mac: Some("02:aa:bb:cc:dd:ee".to_owned()),
                mtu: DEFAULT_MAC_MTU,
                sealant_run_dir: run_dir,
                shutdown_grace: Duration::from_secs(5),
            },
            None,
            "{\"version\":1,\"mode\":\"normal\"}\n".to_owned(),
            exits.clone(),
        )
        .await
        .unwrap();

        let _ = stop_tx.send(true);
        srv.await.unwrap().unwrap();

        assert_eq!(vmm_exit, VmmExit::Code(0));
        assert_eq!(
            exit::runner_exit_code(vmm_exit, exits.latest().as_ref()),
            76
        );
    }
}
