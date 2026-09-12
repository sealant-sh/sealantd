//! A tiny in-process HTTP/1.1 object server: presigned-style PUT/GET on `/<key>`, S3-style part
//! PUTs on `/<key>?partNumber=N&uploadId=ID` answered with an ETag, ranged GETs, and counters
//! for what the client did (part PUTs in flight at once, single PUTs, retries served).
#![allow(dead_code, unreachable_pub)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sealant_capture::registrar::{CompleteRefusal, CompletedPart, MultipartCompleter};
use sha2::{Digest, Sha256};

/// Parts of open multipart uploads: upload id → part number → (etag, bytes).
pub type Parts = HashMap<String, HashMap<u32, (String, Vec<u8>)>>;

#[derive(Default)]
pub struct Counters {
    /// Part PUTs that reached the server.
    pub part_puts: AtomicU64,
    /// Single PUTs.
    pub single_puts: AtomicU64,
    /// Part PUTs being served right now.
    pub in_flight: AtomicUsize,
    /// The most part PUTs ever served at once.
    pub max_in_flight: AtomicUsize,
    /// Fail the next part PUT of this part number with 503, once.
    pub fail_part_once: AtomicU64,
    /// Whether that failure was served.
    pub failed_once: AtomicBool,
}

pub struct Server {
    pub base: String,
    pub objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pub parts: Arc<Mutex<Parts>>,
    pub counters: Arc<Counters>,
    /// Held before answering a part PUT, so parts overlap visibly.
    pub part_delay: Duration,
}

/// The ETag the server answers for a body: a quoted sha256 prefix.
pub fn etag(body: &[u8]) -> String {
    let d = Sha256::digest(body);
    format!("\"{}\"", hex::encode(&d[..8]))
}

pub fn serve() -> Server {
    serve_with(Duration::from_millis(60))
}

pub fn serve_with(part_delay: Duration) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let objects: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let parts: Arc<Mutex<Parts>> = Arc::new(Mutex::new(HashMap::new()));
    let counters = Arc::new(Counters::default());
    let (store, parts2, counters2) = (objects.clone(), parts.clone(), counters.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let (store, parts, counters) = (store.clone(), parts2.clone(), counters2.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut head = line.split_whitespace();
                    let method = head.next().unwrap_or("").to_owned();
                    let target = head.next().unwrap_or("").trim_start_matches('/').to_owned();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let (path, query) = (path.to_owned(), query.to_owned());
                    let mut len = 0usize;
                    let mut if_none_match = false;
                    let mut range = false;
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
                        if lower.starts_with("range: bytes=0-0") {
                            range = true;
                        }
                    }
                    let mut body = vec![0u8; len];
                    reader.read_exact(&mut body).unwrap();
                    let part = query_param(&query, "partNumber")
                        .zip(query_param(&query, "uploadId"))
                        .and_then(|(n, id)| n.parse::<u32>().ok().map(|n| (n, id)));
                    let mut extra = String::new();
                    let (status, out): (&str, Vec<u8>) = match (method.as_str(), part) {
                        ("PUT", Some((n, upload_id))) => {
                            counters.part_puts.fetch_add(1, Ordering::SeqCst);
                            let now = counters.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                            counters.max_in_flight.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(part_delay);
                            counters.in_flight.fetch_sub(1, Ordering::SeqCst);
                            let fail = counters.fail_part_once.load(Ordering::SeqCst);
                            if fail == u64::from(n)
                                && !counters.failed_once.swap(true, Ordering::SeqCst)
                            {
                                ("503 Service Unavailable", Vec::new())
                            } else {
                                let tag = etag(&body);
                                parts
                                    .lock()
                                    .unwrap()
                                    .entry(upload_id)
                                    .or_default()
                                    .insert(n, (tag.clone(), body));
                                extra = format!("ETag: {tag}\r\n");
                                ("200 OK", Vec::new())
                            }
                        }
                        ("PUT", None) => {
                            counters.single_puts.fetch_add(1, Ordering::SeqCst);
                            let mut s = store.lock().unwrap();
                            if if_none_match && s.contains_key(&path) {
                                ("412 Precondition Failed", Vec::new())
                            } else {
                                s.insert(path.clone(), body);
                                ("200 OK", Vec::new())
                            }
                        }
                        ("GET", _) => match store.lock().unwrap().get(&path) {
                            Some(b) if range => {
                                extra = format!("Content-Range: bytes 0-0/{}\r\n", b.len());
                                ("206 Partial Content", b[..b.len().min(1)].to_vec())
                            }
                            Some(b) => ("200 OK", b.clone()),
                            None => ("404 Not Found", Vec::new()),
                        },
                        _ => ("405 Method Not Allowed", Vec::new()),
                    };
                    let mut w = stream.try_clone().unwrap();
                    write!(
                        w,
                        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\n\r\n",
                        out.len()
                    )
                    .unwrap();
                    w.write_all(&out).unwrap();
                    w.flush().unwrap();
                }
            });
        }
    });
    Server {
        base,
        objects,
        parts,
        counters,
        part_delay,
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

/// The server's stand-in for `CompleteMultipartUpload` with `If-None-Match: *`: assembles the
/// uploaded parts in order at the key, refuses an existing key, checks every ETag.
pub struct Completer {
    pub objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pub parts: Arc<Mutex<Parts>>,
    /// Every `(key, upload_id, parts)` the completer was asked to assemble.
    pub calls: Mutex<Vec<(String, String, Vec<CompletedPart>)>>,
}

impl Server {
    pub fn completer(&self) -> Arc<Completer> {
        Arc::new(Completer {
            objects: self.objects.clone(),
            parts: self.parts.clone(),
            calls: Mutex::new(Vec::new()),
        })
    }
}

impl MultipartCompleter for Completer {
    fn complete(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<Option<u64>, CompleteRefusal> {
        self.calls
            .lock()
            .unwrap()
            .push((key.to_owned(), upload_id.to_owned(), parts.to_vec()));
        let mut objects = self.objects.lock().unwrap();
        if objects.contains_key(key) {
            return Err(CompleteRefusal::Exists);
        }
        let mut uploaded = self.parts.lock().unwrap();
        let Some(stored) = uploaded.remove(upload_id) else {
            return Err(CompleteRefusal::BadParts(format!("no upload {upload_id}")));
        };
        let mut body = Vec::new();
        for p in parts {
            match stored.get(&p.part_number) {
                Some((tag, bytes)) if *tag == p.etag => body.extend_from_slice(bytes),
                Some(_) => {
                    return Err(CompleteRefusal::BadParts(format!(
                        "part {} etag mismatch",
                        p.part_number
                    )));
                }
                None => {
                    return Err(CompleteRefusal::BadParts(format!(
                        "part {} never uploaded",
                        p.part_number
                    )));
                }
            }
        }
        let size = body.len() as u64;
        objects.insert(key.to_owned(), body);
        Ok(Some(size))
    }
}
