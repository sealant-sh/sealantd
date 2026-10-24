use std::sync::Arc;
use std::time::Duration;

use sealant_control::{handle_connection, read_frame, write_frame};
use sealant_protocol::{
    AttachMode, AttachSessionArgs, ClientMessage, Command, CommandResult, ControlError,
    ControlErrorCode, ControlRequest, ControlResponse, EnvVar, ExecArgs, ExecutionId,
    ForwardOpened, ForwardProtocol, OpenForwardArgs, OpenSessionArgs, RequestId, ResponseOutcome,
    ServerMessage, SessionId, SessionMode, SessionOpened, SessionState, StreamFrame, StreamPayload,
    WriteStdinArgs,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::Runtime;
use sealantd::shutdown::ShutdownSignal;
use tokio::io::DuplexStream;
use tokio::sync::watch;

const MAX: u32 = 8 * 1024 * 1024;

const SERVER: &str = r#"
import os, socket, sys, threading, time
port, mode = int(sys.argv[1]), sys.argv[2]
threading.Timer(60, os._exit, (0,)).start()
if mode in ("setsid", "flood"):
    if os.fork() > 0:
        if mode == "flood":
            sys.stdin.readline()
            def flood():
                block = b"x" * 65536
                while True:
                    os.write(1, block)
            threading.Thread(target=flood, daemon=True).start()
            time.sleep(2)
            os._exit(0)
        threading.Event().wait()
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    threading.Timer(60, os._exit, (0,)).start()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen()
def echo(c):
    while True:
        data = c.recv(65536)
        if not data:
            break
        if data == b"release":
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            break
        c.sendall(data)
    c.close()
while True:
    try:
        c, _ = s.accept()
    except OSError:
        threading.Event().wait()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
"#;

fn python() -> String {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join("python3"))
        .find(|candidate| candidate.is_file())
        .expect("python3 on PATH")
        .to_string_lossy()
        .into_owned()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port()
}

async fn wait_listening(port: u16) {
    let ready = async {
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), ready)
        .await
        .expect("the server listens");
}

struct Client {
    runtime: Arc<Runtime>,
    stream: DuplexStream,
    frames: Vec<StreamFrame>,
    next: u32,
}

impl Client {
    fn new() -> Self {
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = std::env::temp_dir();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
        runtime.mark_healthy();
        Self::on(runtime)
    }

    /// Another connection to the same runtime.
    fn on(runtime: Arc<Runtime>) -> Self {
        let (sd_tx, sd_rx) = watch::channel(false);
        std::mem::forget(sd_tx);
        let (stream, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        tokio::spawn(handle_connection(
            runtime.clone(),
            server_read,
            server_write,
            sd_rx,
        ));
        Self {
            runtime,
            stream,
            frames: Vec::new(),
            next: 0,
        }
    }

    async fn recv(&mut self) -> ServerMessage {
        let body = read_frame(&mut self.stream, MAX)
            .await
            .expect("read frame")
            .expect("frame present");
        sealant_protocol::decode_server(&body).expect("decode")
    }

    async fn request(&mut self, command: Command) -> ControlResponse {
        self.next += 1;
        let id = RequestId::new(format!("r{}", self.next));
        let body = sealant_protocol::encode_client(&ClientMessage::Request(ControlRequest::new(
            id.clone(),
            command,
        )));
        write_frame(&mut self.stream, &body, MAX)
            .await
            .expect("write");
        let answer = async {
            loop {
                match self.recv().await {
                    ServerMessage::Response(r) if r.request_id == id => return r,
                    ServerMessage::Stream(frame) => self.frames.push(frame),
                    _ => {}
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(15), answer)
            .await
            .expect("answered")
    }

    async fn open_server(&mut self, port: u16, mode: &str) -> SessionId {
        let args = vec!["-c".into(), SERVER.into(), port.to_string(), mode.into()];
        self.open_leader(python(), args, port).await.session_id
    }

    async fn open_leader(&mut self, shell: String, args: Vec<String>, port: u16) -> SessionOpened {
        let response = self
            .request(Command::OpenSession(OpenSessionArgs {
                user: None,
                execution_id: None,
                shell: Some(shell),
                args,
                cwd: None,
                env: vec![],
                cols: 80,
                rows: 24,
                term: None,
                mode: SessionMode::Pipe,
            }))
            .await;
        let ResponseOutcome::Ok {
            result: Some(CommandResult::SessionOpened(opened)),
        } = response.outcome
        else {
            panic!("session opened: {response:?}");
        };
        wait_listening(port).await;
        opened
    }

    async fn close_and_wait(&mut self, session: &SessionId) {
        let response = self
            .request(Command::CloseSession {
                session_id: session.clone(),
            })
            .await;
        assert!(response.is_ok(), "closed: {response:?}");
        for _ in 0..200 {
            let response = self.request(Command::ListSessions).await;
            if let ResponseOutcome::Ok {
                result: Some(CommandResult::SessionList(list)),
            } = response.outcome
                && list
                    .sessions
                    .iter()
                    .any(|s| &s.session_id == session && s.state == SessionState::Exited)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("session {session} never exited");
    }

    async fn forward(
        &mut self,
        port: u16,
        owner: Option<&SessionId>,
    ) -> Result<ForwardOpened, ControlError> {
        let response = self
            .request(Command::OpenForward(OpenForwardArgs {
                host: "127.0.0.1".to_owned(),
                port,
                execution_id: None,
                protocol: ForwardProtocol::Tcp,
                dedicated: false,
                owner_session_id: owner.cloned(),
            }))
            .await;
        match response.outcome {
            ResponseOutcome::Ok {
                result: Some(CommandResult::ForwardOpened(opened)),
            } => Ok(opened),
            ResponseOutcome::Error { error } => Err(error),
            other => panic!("unexpected answer: {other:?}"),
        }
    }

    async fn echo(&mut self, opened: &ForwardOpened, bytes: &[u8]) -> Vec<u8> {
        let body = sealant_protocol::encode_client(&ClientMessage::Stream(StreamFrame::data(
            opened.channel_id.clone(),
            0,
            bytes.to_vec(),
        )));
        write_frame(&mut self.stream, &body, MAX)
            .await
            .expect("write");
        let mut got = Vec::new();
        let read = async {
            while got.len() < bytes.len() {
                if let ServerMessage::Stream(frame) = self.recv().await
                    && frame.channel_id == opened.channel_id
                    && let StreamPayload::Data { data } = frame.payload
                {
                    got.extend_from_slice(data.as_slice());
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .expect("echoed");
        got
    }

    async fn end_error(&mut self, opened: &ForwardOpened) -> Option<String> {
        let seen = self.frames.iter().find_map(|frame| match &frame.payload {
            StreamPayload::End(end) if frame.channel_id == opened.channel_id => {
                Some(end.error.clone())
            }
            _ => None,
        });
        if let Some(error) = seen {
            return error;
        }
        let read = async {
            loop {
                if let ServerMessage::Stream(frame) = self.recv().await
                    && frame.channel_id == opened.channel_id
                    && let StreamPayload::End(end) = frame.payload
                {
                    return end.error;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .expect("the forward ends")
    }
}

fn reason(error: &ControlError) -> Option<&str> {
    error.detail.as_ref()?.get("reason")?.as_str()
}

#[tokio::test]
async fn a_forward_bound_to_the_session_that_serves_opens_and_echoes_it() {
    let mut client = Client::new();
    let port = free_port();
    let a = client.open_server(port, "serve").await;

    let opened = client.forward(port, Some(&a)).await.expect("bound to A");
    assert_eq!(opened.bound_session_id.as_ref(), Some(&a));
    assert_eq!(client.echo(&opened, b"bound").await, b"bound");
    client.close_and_wait(&a).await;
}

#[tokio::test]
async fn a_session_that_exited_binds_nothing_even_when_another_holds_its_port() {
    let mut client = Client::new();
    let port = free_port();
    let a = client.open_server(port, "serve").await;
    client.close_and_wait(&a).await;
    let b = client.open_server(port, "serve").await;

    let error = client
        .forward(port, Some(&a))
        .await
        .expect_err("A has exited");
    assert_eq!(error.code, ControlErrorCode::SessionNotFound);
    assert_eq!(reason(&error), Some("owner-exited"));

    let error = client
        .forward(port, Some(&SessionId::new("sess_unknown")))
        .await
        .expect_err("no such session");
    assert_eq!(reason(&error), Some("owner-exited"));
    client.close_and_wait(&b).await;
}

#[tokio::test]
async fn a_listener_outside_the_session_is_a_peer_mismatch() {
    let mut client = Client::new();
    let idle = client.open_server(free_port(), "serve").await;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });

    let error = client
        .forward(port, Some(&idle))
        .await
        .expect_err("this process is not in the session");
    assert_eq!(error.code, ControlErrorCode::PolicyDenied);
    assert_eq!(reason(&error), Some("peer-mismatch"));
    client.close_and_wait(&idle).await;
}

#[tokio::test]
async fn a_server_that_left_the_linux_session_with_the_marker_is_the_sessions_own() {
    let mut client = Client::new();
    let port = free_port();
    let d = client.open_server(port, "setsid").await;

    let opened = client
        .forward(port, Some(&d))
        .await
        .expect("the double-forked server carries SEALANT_SESSION_MARKER");
    assert_eq!(opened.bound_session_id.as_ref(), Some(&d));
    assert_eq!(client.echo(&opened, b"setsid").await, b"setsid");

    client.close_and_wait(&d).await;
    assert_eq!(
        client.end_error(&opened).await.as_deref(),
        Some("owner-exited")
    );
    wait_listening(port).await;
}

#[tokio::test]
async fn a_target_that_never_accepts_is_unverifiable() {
    let mut client = Client::new();
    let idle = client.open_server(free_port(), "serve").await;
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket.bind(([127, 0, 0, 1], 0).into()).expect("bind");
    let port = socket.local_addr().expect("addr").port();
    let _listener = socket.listen(8).expect("listen");

    let error = client
        .forward(port, Some(&idle))
        .await
        .expect_err("nothing accepts the connection");
    assert_eq!(reason(&error), Some("binding-unverifiable"));
    client.close_and_wait(&idle).await;
}

#[tokio::test]
async fn a_bound_forward_reaches_tcp_on_loopback_only() {
    let mut client = Client::new();
    let idle = client.open_server(free_port(), "serve").await;
    let unknown = SessionId::new("sess_unknown");
    for (host, protocol, owner) in [
        ("192.0.2.1", ForwardProtocol::Tcp, &idle),
        ("127.0.0.1", ForwardProtocol::Udp, &idle),
        ("127.0.0.1", ForwardProtocol::Udp, &unknown),
    ] {
        let response = client
            .request(Command::OpenForward(OpenForwardArgs {
                host: host.to_owned(),
                port: 9,
                execution_id: None,
                protocol,
                dedicated: false,
                owner_session_id: Some(owner.clone()),
            }))
            .await;
        let ResponseOutcome::Error { error } = response.outcome else {
            panic!("{host} {protocol:?} refused: {response:?}");
        };
        assert_eq!(
            error.code,
            ControlErrorCode::InvalidArgument,
            "{host} {protocol:?} {owner}"
        );
    }
    client.close_and_wait(&idle).await;
}

#[tokio::test]
async fn a_forward_with_only_an_execution_id_opens_unbound() {
    let mut client = Client::new();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    let response = client
        .request(Command::OpenForward(OpenForwardArgs {
            host: "127.0.0.1".to_owned(),
            port,
            execution_id: Some(ExecutionId::new("exe_gateway")),
            protocol: ForwardProtocol::Tcp,
            dedicated: false,
            owner_session_id: None,
        }))
        .await;
    let ResponseOutcome::Ok {
        result: Some(CommandResult::ForwardOpened(opened)),
    } = response.outcome
    else {
        panic!("opened: {response:?}");
    };
    assert_eq!(opened.bound_session_id, None);
}

/// The first `SEALANT_SESSION_MARKER` value in a process's environment.
fn marker_of(pid: i32) -> Option<String> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).expect("environ");
    environ.split(|&b| b == 0).find_map(|entry| {
        let value = entry.strip_prefix(b"SEALANT_SESSION_MARKER=")?;
        Some(String::from_utf8_lossy(value).into_owned())
    })
}

impl Client {
    /// Run `sh -c 'printf %s "${SEALANT_SESSION_MARKER-unset}"'` naming `session`, and read what it
    /// printed.
    async fn exec_marker(&mut self, session: SessionId, env: Vec<EnvVar>) -> String {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("marker");
        let response = self
            .request(Command::Exec(ExecArgs {
                user: None,
                execution_id: None,
                session_id: Some(session),
                executable: "/bin/sh".to_owned(),
                args: vec![
                    "-c".to_owned(),
                    format!(
                        "printf %s \"${{SEALANT_SESSION_MARKER-unset}}\" > {}.tmp && mv {0}.tmp {0}",
                        out.display()
                    ),
                ],
                cwd: None,
                env,
                stdin: false,
                attach: false,
                timeout_millis: None,
                background: false,
                capture: None,
                graceful_signal: None,
            }))
            .await;
        assert!(response.is_ok(), "exec accepted: {response:?}");
        let written = async {
            loop {
                if let Ok(text) = std::fs::read_to_string(&out) {
                    return text;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), written)
            .await
            .expect("the exec wrote its marker")
    }
}

#[tokio::test]
async fn an_exec_carries_the_marker_of_a_running_session_it_names_and_no_other() {
    let mut client = Client::new();
    let port = free_port();
    let args = vec!["-c".into(), SERVER.into(), port.to_string(), "serve".into()];
    let leader = client.open_leader(python(), args, port).await;
    let marker = marker_of(leader.pid).expect("the leader carries a marker");
    assert_ne!(
        marker,
        leader.session_id.as_str(),
        "the marker is not the public id"
    );
    assert_eq!(marker.len(), 32, "{marker}");

    let named = client.exec_marker(leader.session_id.clone(), vec![]).await;
    assert_eq!(named, marker);

    let forged = EnvVar {
        key: "SEALANT_SESSION_MARKER".to_owned(),
        value: marker.clone(),
    };
    let unknown = client
        .exec_marker(SessionId::new("sess_unknown"), vec![forged])
        .await;
    assert_eq!(
        unknown, "unset",
        "no marker for a session that is not running"
    );
    client.close_and_wait(&leader.session_id).await;
    let exited = client.exec_marker(leader.session_id.clone(), vec![]).await;
    assert_eq!(exited, "unset", "no marker for a session that exited");
}

#[tokio::test]
async fn a_leader_without_its_marker_still_owns_through_its_linux_session() {
    let mut client = Client::new();
    let port = free_port();
    let args = vec![
        "-u".into(),
        "SEALANT_SESSION_MARKER".into(),
        python(),
        "-c".into(),
        SERVER.into(),
        port.to_string(),
        "serve".into(),
    ];
    let leader = client.open_leader("/usr/bin/env".into(), args, port).await;
    assert_eq!(marker_of(leader.pid), None, "the leader dropped its marker");
    let opened = client
        .forward(port, Some(&leader.session_id))
        .await
        .expect("the leader's Linux session proves it");
    assert_eq!(client.echo(&opened, b"sid").await, b"sid");
    client.close_and_wait(&leader.session_id).await;
}

#[tokio::test]
async fn another_session_on_the_port_of_a_session_still_running_is_a_peer_mismatch() {
    let mut client = Client::new();
    let port = free_port();
    let a = client.open_server(port, "serve").await;
    let mut release = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to A");
    tokio::io::AsyncWriteExt::write_all(&mut release, b"release")
        .await
        .expect("release");
    let freed = async {
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), freed)
        .await
        .expect("A stops listening and keeps running");
    let b = client.open_server(port, "serve").await;

    let error = client
        .forward(port, Some(&a))
        .await
        .expect_err("B holds A's port");
    assert_eq!(reason(&error), Some("peer-mismatch"));
    let opened = client.forward(port, Some(&b)).await.expect("bound to B");
    assert_eq!(client.echo(&opened, b"b").await, b"b");
    client.close_and_wait(&a).await;
    client.close_and_wait(&b).await;
}

impl Client {
    async fn send(&mut self, opened: &ForwardOpened, bytes: &[u8]) {
        let body = sealant_protocol::encode_client(&ClientMessage::Stream(StreamFrame::data(
            opened.channel_id.clone(),
            0,
            bytes.to_vec(),
        )));
        write_frame(&mut self.stream, &body, MAX)
            .await
            .expect("write");
    }

    /// Every `End` the forward got, the ones already read included, waiting `quiet` for more.
    async fn ends(&mut self, opened: &ForwardOpened, quiet: Duration) -> Vec<Option<String>> {
        let is_end = |frame: &StreamFrame| match &frame.payload {
            StreamPayload::End(end) if frame.channel_id == opened.channel_id => {
                Some(end.error.clone())
            }
            _ => None,
        };
        let mut ends: Vec<_> = self.frames.iter().filter_map(is_end).collect();
        while let Ok(message) = tokio::time::timeout(quiet, self.recv()).await {
            if let ServerMessage::Stream(frame) = message
                && let Some(end) = is_end(&frame)
            {
                ends.push(end);
            }
        }
        ends
    }
}

#[tokio::test]
async fn a_bound_forward_that_ended_sends_no_second_end_when_its_leader_exits() {
    let mut client = Client::new();
    let port = free_port();
    let a = client.open_server(port, "serve").await;
    let opened = client.forward(port, Some(&a)).await.expect("bound to A");
    client.send(&opened, b"release").await;
    assert_eq!(
        client.ends(&opened, Duration::from_millis(500)).await,
        vec![None]
    );
    client.frames.clear();

    client.close_and_wait(&a).await;
    assert_eq!(
        client.ends(&opened, Duration::from_millis(500)).await,
        Vec::<Option<String>>::new(),
        "the forward already ended"
    );
}

#[tokio::test]
async fn a_bound_forward_ends_when_its_leader_exits_though_an_attached_client_stopped_reading() {
    let mut client = Client::new();
    let port = free_port();
    let session = client.open_server(port, "flood").await;
    let mut stalled = Client::on(client.runtime.clone());
    let attached = stalled
        .request(Command::AttachSession(AttachSessionArgs {
            session_id: session.clone(),
            mode: AttachMode::Interactive,
            from_sequence: None,
        }))
        .await;
    assert!(attached.is_ok(), "attached: {attached:?}");

    let opened = client
        .forward(port, Some(&session))
        .await
        .expect("the setsid server carries the marker");
    let go = client
        .request(Command::WriteStdin(WriteStdinArgs {
            process_id: None,
            session_id: Some(session.clone()),
            data: b"go\n".to_vec().into(),
        }))
        .await;
    assert!(go.is_ok(), "{go:?}");
    assert_eq!(
        client.end_error(&opened).await.as_deref(),
        Some("owner-exited"),
        "the leader's output sits unread on the attached connection"
    );
    drop(stalled);
}
