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

/// One span from an OTLP export, its attribute values as text.
#[derive(Clone, Debug)]
pub(crate) struct Exported {
    pub(crate) name: String,
    pub(crate) trace_id: Vec<u8>,
    pub(crate) span_id: Vec<u8>,
    pub(crate) parent_span_id: Vec<u8>,
    pub(crate) attributes: Vec<(String, String)>,
    /// Whether OpenTelemetry's status says the span failed.
    pub(crate) failed: bool,
}

impl Exported {
    pub(crate) fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Every span in the OTLP trace exports among `received`.
pub(crate) fn exported_spans(received: &[Received]) -> Vec<Exported> {
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value;
    use prost::Message as _;
    received
        .iter()
        .filter(|r| r.path.ends_with("/otlp/v1/traces"))
        .flat_map(|r| {
            ExportTraceServiceRequest::decode(r.body.as_slice())
                .expect("an OTLP protobuf export")
                .resource_spans
        })
        .flat_map(|resource| resource.scope_spans)
        .flat_map(|scope| scope.spans)
        .map(|span| Exported {
            name: span.name,
            trace_id: span.trace_id,
            span_id: span.span_id,
            parent_span_id: span.parent_span_id,
            // `STATUS_CODE_ERROR`.
            failed: span.status.is_some_and(|status| status.code == 2),
            attributes: span
                .attributes
                .into_iter()
                .map(|kv| {
                    let value = match kv.value.and_then(|v| v.value) {
                        Some(Value::StringValue(s)) => s,
                        Some(Value::BoolValue(b)) => b.to_string(),
                        Some(Value::IntValue(i)) => i.to_string(),
                        Some(Value::DoubleValue(d)) => d.to_string(),
                        other => format!("{other:?}"),
                    };
                    (kv.key, value)
                })
                .collect(),
        })
        .collect()
}

/// Fail unless every span reads in Sentry as what it is: an op other than `default` and a
/// description that is not blank.
pub(crate) fn assert_sentry_shows(spans: &[Exported]) {
    assert!(!spans.is_empty(), "no spans");
    for span in spans {
        let op = span.attribute("sentry.op").unwrap_or_default();
        let description = span.attribute("sentry.description").unwrap_or_default();
        assert!(
            !op.is_empty() && op != "default" && !description.trim().is_empty(),
            "{} would show in Sentry as op {op:?}, description {description:?}",
            span.name
        );
    }
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
