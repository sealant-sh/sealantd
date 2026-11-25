//! A stand-in for Sentry: an HTTP/1.1 server on loopback that keeps every request it is sent (the
//! OTLP exports and the Sentry envelopes alike) and answers 200.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// One request as it reached the collector.
#[derive(Clone, Debug)]
pub(crate) struct Received {
    pub(crate) path: String,
    /// Lower-case names.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Received {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone)]
pub(crate) struct Collector {
    pub(crate) port: u16,
    received: Arc<Mutex<Vec<Received>>>,
}

impl Collector {
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let keep = received.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let keep = keep.clone();
                std::thread::spawn(move || serve(stream, &keep));
            }
        });
        Self { port, received }
    }

    /// A DSN for project 10 on this collector.
    pub(crate) fn dsn(&self) -> String {
        format!(
            "http://5e5c0de5e5c0de5e5c0de5e5c0de5e5c@127.0.0.1:{}/10",
            self.port
        )
    }

    pub(crate) fn received(&self) -> Vec<Received> {
        self.received.lock().expect("lock").clone()
    }
}

fn serve(stream: TcpStream, keep: &Mutex<Vec<Received>>) {
    let mut writer = stream.try_clone().expect("clone");
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let mut headers = Vec::new();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((k, v)) = header.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
            }
        }
        let length: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        assert!(
            !headers.iter().any(|(k, _)| k == "transfer-encoding"),
            "a chunked body: the collector reads Content-Length bodies only"
        );
        let mut body = vec![0; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        keep.lock().expect("lock").push(Received {
            path,
            headers,
            body,
        });
        let answer = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        if writer.write_all(answer).is_err() {
            return;
        }
    }
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
