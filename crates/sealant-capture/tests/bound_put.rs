//! Bytes-bound PUT URLs (`registrar` module docs, # Bytes-bound PUT URLs): a PUT whose URL signs
//! `x-amz-checksum-sha256` sends the SHA-256 of its bytes in that header, and a pack index —
//! whose name does not say it — has it declared to the minter before its URL is minted. The
//! server here refuses a body that does not match the header, as Garage does (`InvalidDigest`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sealant_capture::sink::{
    BlobSink, BlobSource, PresignedHttp, PutOutcome, SinkError, UrlMinter,
};
use sha2::{Digest, Sha256};

/// What one PUT carried: its path and its `x-amz-checksum-sha256`, if any.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                char::from(A[((n >> (18 - 6 * i)) & 63) as usize])
            } else {
                '='
            });
        }
    }
    out
}

/// An object server that checks a body against its `x-amz-checksum-sha256` when the URL signs it.
fn serve() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut out = stream;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let target = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let mut headers = HashMap::new();
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
                        }
                    }
                    let len: usize = headers
                        .get("content-length")
                        .map_or(0, |v| v.parse().unwrap());
                    let mut body = vec![0u8; len];
                    reader.read_exact(&mut body).unwrap();
                    let checksum = headers.get("x-amz-checksum-sha256").cloned();
                    log.lock()
                        .unwrap()
                        .push((path.trim_start_matches('/').to_owned(), checksum.clone()));
                    let signs = query.to_ascii_lowercase().contains("x-amz-checksum-sha256");
                    let status = match (signs, checksum) {
                        (true, None) => "400 Bad Request",
                        (true, Some(c)) if c != base64(&Sha256::digest(&body)) => "400 Bad Request",
                        _ => "200 OK",
                    };
                    write!(out, "HTTP/1.1 {status}\r\ncontent-length: 0\r\n\r\n").unwrap();
                }
            });
        }
    });
    (base, seen)
}

/// Mints URLs that sign the checksum, and records what was declared to it before each mint.
struct Minter {
    base: String,
    bound: bool,
    declared: Mutex<Vec<(String, String)>>,
    declared_at_mint: Mutex<Vec<(String, Option<String>)>>,
}

impl UrlMinter for Minter {
    fn put_url(&self, key: &str, _size: u64) -> Result<String, SinkError> {
        let declared = self
            .declared
            .lock()
            .unwrap()
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, d)| d.clone());
        self.declared_at_mint
            .lock()
            .unwrap()
            .push((key.to_owned(), declared));
        let signed = if self.bound {
            "host%3Bif-none-match%3Bx-amz-checksum-sha256"
        } else {
            "host%3Bif-none-match"
        };
        Ok(format!(
            "{}/{key}?X-Amz-SignedHeaders={signed}&X-Amz-Signature=x",
            self.base
        ))
    }
    fn declare_sha256(&self, digests: &[(String, String)]) {
        self.declared
            .lock()
            .unwrap()
            .extend(digests.iter().cloned());
    }
    fn get_url(&self, key: &str) -> Result<String, SinkError> {
        Ok(format!("{}/{key}", self.base))
    }
}

fn sink(base: &str, bound: bool) -> (PresignedHttp, Arc<Minter>) {
    let minter = Arc::new(Minter {
        base: base.to_owned(),
        bound,
        declared: Mutex::new(Vec::new()),
        declared_at_mint: Mutex::new(Vec::new()),
    });
    (
        PresignedHttp::new(Box::new(Arc::clone(&minter)), Duration::from_secs(5)),
        minter,
    )
}

#[test]
fn a_bound_put_names_its_bytes_and_an_index_is_declared_before_its_mint() {
    let (base, seen) = serve();
    let (sink, minter) = sink(&base, true);
    let pack = b"pack bytes";
    let pack_key = format!("captures/wt/1/packs/{}", sha256_hex(pack));
    assert_eq!(
        sink.put_if_absent(&pack_key, BlobSource::Bytes(pack))
            .unwrap(),
        PutOutcome::Stored
    );
    let index = b"index bytes, named after the pack";
    let index_key = format!("{pack_key}.idx");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("index");
    std::fs::write(&file, index).unwrap();
    assert_eq!(
        sink.put_if_absent(&index_key, BlobSource::File(&file))
            .unwrap(),
        PutOutcome::Stored
    );

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            (pack_key.clone(), Some(base64(&Sha256::digest(pack)))),
            (index_key.clone(), Some(base64(&Sha256::digest(index)))),
        ]
    );
    // The pack's name says its SHA-256: nothing to declare. The index's was declared first.
    assert_eq!(
        *minter.declared_at_mint.lock().unwrap(),
        vec![(pack_key, None), (index_key, Some(sha256_hex(index)))]
    );
}

#[test]
fn a_put_whose_url_does_not_sign_the_checksum_sends_none() {
    let (base, seen) = serve();
    let (sink, _) = sink(&base, false);
    let pack = b"pack bytes";
    let pack_key = format!("captures/wt/1/packs/{}", sha256_hex(pack));
    assert_eq!(
        sink.put_if_absent(&pack_key, BlobSource::Bytes(pack))
            .unwrap(),
        PutOutcome::Stored
    );
    assert_eq!(*seen.lock().unwrap(), vec![(pack_key, None)]);
}

/// Against a real store: `MEND_TEST_BOUND_URLS` names a JSON file of PUT URLs Mend presigned
/// bound to their bytes (`{"urls":{key:url},"bytes":{key:base64}}`), on Garage. The sink's PUTs
/// go up; the same URLs then refuse other bytes. Skipped without it.
#[test]
fn a_real_store_takes_the_bound_bytes_and_refuses_others() {
    let Ok(path) = std::env::var("MEND_TEST_BOUND_URLS") else {
        return;
    };
    let file: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let urls: HashMap<String, String> = serde_json::from_value(file["urls"].clone()).unwrap();
    let bytes: HashMap<String, String> = serde_json::from_value(file["bytes"].clone()).unwrap();

    struct Fixed(HashMap<String, String>);
    impl UrlMinter for Fixed {
        fn put_url(&self, key: &str, _size: u64) -> Result<String, SinkError> {
            Ok(self.0[key].clone())
        }
        fn get_url(&self, key: &str) -> Result<String, SinkError> {
            Err(SinkError::NotFound(key.to_owned()))
        }
    }
    let sink = PresignedHttp::new(Box::new(Fixed(urls.clone())), Duration::from_secs(10));
    let decode = |b64: &str| -> Vec<u8> {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for c in b64.bytes().filter(|c| *c != b'=') {
            buf = (buf << 6) | A.iter().position(|a| *a == c).unwrap() as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    };
    for (key, b64) in &bytes {
        let body = decode(b64);
        assert_eq!(
            sink.put_if_absent(key, BlobSource::Bytes(&body)).unwrap(),
            PutOutcome::Stored,
            "{key}"
        );
        // The same URL, other bytes of the same length: refused by the store — 400 when the
        // header names the bound digest (a key whose name says it), 403 when it names the other
        // bytes' (a pack index, hashed from what is sent): no longer what was signed.
        let mut other = body.clone();
        other[0] ^= 0xff;
        let refused = sink.put_if_absent(key, BlobSource::Bytes(&other));
        assert!(
            matches!(
                refused,
                Err(SinkError::Http {
                    status: 400 | 403,
                    ..
                })
            ),
            "{key}: {refused:?}"
        );
    }
}
