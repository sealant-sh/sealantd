//! The OTLP exporter's HTTP client: ureq on rustls with public roots, the stack the capture code
//! already ships. The batch processor calls it on its own thread, so a blocking call is fine; the
//! timeout bounds it.
//!
//! It sends only the headers it was built with and `content-type`. The exporter also merges in
//! `OTEL_EXPORTER_OTLP_HEADERS` from the process environment, which in a workspace is the image's:
//! a user's collector key must never be sent to ours.

use std::time::Duration;

use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};

/// How long one export may take, connect to last byte.
const TIMEOUT: Duration = Duration::from_secs(5);
/// A collector's answer is a small protobuf; anything bigger is not one.
const MAX_RESPONSE: u64 = 64 * 1024;

#[derive(Debug)]
pub(crate) struct UreqClient {
    agent: ureq::Agent,
    /// Lower-case names of the headers a request may carry.
    allowed: Vec<String>,
}

impl UreqClient {
    pub(crate) fn new(headers: &[(String, String)]) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            // An exporter never follows a collector elsewhere.
            .max_redirects(0)
            .build();
        let mut allowed: Vec<String> = headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        allowed.push("content-type".to_owned());
        Self {
            agent: ureq::Agent::new_with_config(config),
            allowed,
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for UreqClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (mut parts, body) = request.into_parts();
        let mut headers = std::mem::take(&mut parts.headers);
        for (name, value) in headers
            .drain()
            .filter_map(|(name, value)| Some((name?, value)))
        {
            if self.allowed.iter().any(|a| a == name.as_str()) {
                parts.headers.insert(name, value);
            }
        }
        let request = Request::from_parts(parts, body.to_vec());
        let response = self.agent.run(request)?;
        let (parts, mut body) = response.into_parts();
        let bytes = body.with_config().limit(MAX_RESPONSE).read_to_vec()?;
        Ok(Response::from_parts(parts, Bytes::from(bytes)))
    }
}
