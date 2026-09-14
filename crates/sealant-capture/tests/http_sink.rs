//! `PresignedHttp` against a tiny in-process HTTP/1.1 object server.

mod common;

use std::time::Duration;

use sealant_capture::sink::{
    BlobSink, BlobSource, PresignedHttp, PutOutcome, SinkError, UrlMinter,
};

use common::serve;

struct Minter(String);

impl UrlMinter for Minter {
    fn put_url(&self, key: &str) -> Result<String, SinkError> {
        Ok(format!("{}/{key}?sig=put", self.0))
    }
    fn get_url(&self, key: &str) -> Result<String, SinkError> {
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
