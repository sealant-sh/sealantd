//! `PresignedHttp` against a tiny in-process HTTP/1.1 object server.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sealant_capture::sink::{
    BlobSink, BlobSource, PresignedHttp, PutOutcome, SinkError, UrlMinter,
};

use common::serve;

/// Records the length each PUT URL was minted for, the way a registrar that binds the
/// signature to the content length sees it.
struct Minter {
    base: String,
    sized: Mutex<Vec<(String, u64)>>,
}

impl Minter {
    fn new(base: String) -> Self {
        Self {
            base,
            sized: Mutex::new(Vec::new()),
        }
    }
}

impl UrlMinter for Minter {
    fn put_url(&self, key: &str, size: u64) -> Result<String, SinkError> {
        self.sized.lock().unwrap().push((key.to_owned(), size));
        Ok(format!("{}/{key}?sig=put", self.base))
    }
    fn get_url(&self, key: &str) -> Result<String, SinkError> {
        Ok(format!("{}/{key}?sig=get", self.base))
    }
}

#[test]
fn presigned_http_put_get_exists() {
    let server = serve();
    let minter = Arc::new(Minter::new(server.base.clone()));
    let sink = PresignedHttp::new(Box::new(Arc::clone(&minter)), Duration::from_secs(5));
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
    // Every PUT URL was minted for the exact byte count the PUT then sent.
    assert_eq!(
        *minter.sized.lock().unwrap(),
        vec![
            (key.to_owned(), 5),
            (key.to_owned(), 5),
            ("k/big".to_owned(), 3_000_000),
        ]
    );
}
