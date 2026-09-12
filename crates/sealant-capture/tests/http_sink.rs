//! `PresignedHttp` against a tiny in-process HTTP/1.1 object server.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sealant_capture::sink::{
    BlobSink, BlobSource, PresignedHttp, PutOutcome, SinkError, UrlMinter,
};

struct Server {
    base: String,
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

fn serve() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let objects: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let store = objects.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let store = store.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts
                        .next()
                        .unwrap_or("")
                        .trim_start_matches('/')
                        .split('?')
                        .next()
                        .unwrap_or("")
                        .to_owned();
                    let mut len = 0usize;
                    let mut if_none_match = false;
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        let lower = h.to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap();
                        }
                        if lower.starts_with("if-none-match:") {
                            if_none_match = true;
                        }
                    }
                    let mut body = vec![0u8; len];
                    reader.read_exact(&mut body).unwrap();
                    let (status, out): (&str, Vec<u8>) = match method.as_str() {
                        "PUT" => {
                            let mut s = store.lock().unwrap();
                            if if_none_match && s.contains_key(&path) {
                                ("412 Precondition Failed", Vec::new())
                            } else {
                                s.insert(path.clone(), body);
                                ("200 OK", Vec::new())
                            }
                        }
                        "GET" => match store.lock().unwrap().get(&path) {
                            Some(b) => ("200 OK", b.clone()),
                            None => ("404 Not Found", Vec::new()),
                        },
                        _ => ("405 Method Not Allowed", Vec::new()),
                    };
                    let mut w = stream.try_clone().unwrap();
                    write!(
                        w,
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n",
                        out.len()
                    )
                    .unwrap();
                    w.write_all(&out).unwrap();
                    w.flush().unwrap();
                }
            });
        }
    });
    Server { base, objects }
}

struct Minter(String);

impl UrlMinter for Minter {
    fn put_url(&self, key: &str) -> Result<String, String> {
        Ok(format!("{}/{key}?sig=put", self.0))
    }
    fn get_url(&self, key: &str) -> Result<String, String> {
        Ok(format!("{}/{key}?sig=get", self.0))
    }
}

#[test]
fn presigned_http_put_get_exists() {
    let server = serve();
    let sink = PresignedHttp::new(
        Box::new(Minter(server.base.clone())),
        Duration::from_secs(5),
    );
    let key = "captures/wt/1/packs/abc";
    assert!(!sink.exists(key).unwrap());
    assert!(matches!(sink.get(key), Err(SinkError::NotFound(_))));
    assert_eq!(
        sink.put_if_absent(key, BlobSource::Bytes(b"hello"))
            .unwrap(),
        PutOutcome::Stored
    );
    assert_eq!(
        sink.put_if_absent(key, BlobSource::Bytes(b"other"))
            .unwrap(),
        PutOutcome::AlreadyPresent
    );
    assert!(sink.exists(key).unwrap());
    assert_eq!(sink.get(key).unwrap(), b"hello");
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("big");
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&f, &big).unwrap();
    assert_eq!(
        sink.put_if_absent("k/big", BlobSource::File(&f)).unwrap(),
        PutOutcome::Stored
    );
    assert_eq!(sink.get("k/big").unwrap(), big);
    assert_eq!(server.objects.lock().unwrap().len(), 2);
}
