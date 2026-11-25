//! What a process exports, read from its environment (or the boot config's, in a microVM guest).
//!
//! `SENTRY_DSN` turns everything on: Sentry errors to that project, and traces to the same
//! project's OTLP endpoint. `OTEL_EXPORTER_OTLP_ENDPOINT` (with `OTEL_EXPORTER_OTLP_HEADERS`)
//! sends traces to another collector instead, with or without a DSN. Neither set: nothing is
//! exported and no exporter or transport is ever built.

use std::fmt;
use std::str::FromStr;

/// Turns telemetry on: the Sentry project errors go to, whose OTLP endpoint traces go to.
pub const SENTRY_DSN: &str = "SENTRY_DSN";
/// The Sentry environment (`development` when unset).
pub const SENTRY_ENVIRONMENT: &str = "SENTRY_ENVIRONMENT";
/// The release, `<sentry-project>@<version>`; the build's own when unset.
pub const SENTRY_RELEASE: &str = "SENTRY_RELEASE";
/// The share of new traces recorded, 0 to 1 (1 when unset). A caller's sampled flag still wins.
pub const SENTRY_TRACES_SAMPLE_RATE: &str = "SENTRY_TRACES_SAMPLE_RATE";
/// A collector's base URL, in place of the DSN's (`/v1/traces` is added).
pub const OTEL_EXPORTER_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
/// `key=value,key=value` headers for that collector.
pub const OTEL_EXPORTER_OTLP_HEADERS: &str = "OTEL_EXPORTER_OTLP_HEADERS";

/// Every variable [`Config::from_lookup`] reads, for a launcher that forwards them.
pub const VARIABLES: [&str; 6] = [
    SENTRY_DSN,
    SENTRY_ENVIRONMENT,
    SENTRY_RELEASE,
    SENTRY_TRACES_SAMPLE_RATE,
    OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_EXPORTER_OTLP_HEADERS,
];

/// Where traces go: an OTLP/HTTP traces URL and the headers it needs.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TracesTarget {
    pub(crate) url: String,
    pub(crate) headers: Vec<(String, String)>,
}

/// Header names only: a header's value is usually a key.
impl fmt::Debug for TracesTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracesTarget")
            .field("url", &self.url)
            .field(
                "headers",
                &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// What one process exports.
#[derive(Clone, Debug)]
pub struct Config {
    pub(crate) traces: Option<TracesTarget>,
    pub(crate) sentry: Option<sentry::types::Dsn>,
    pub(crate) environment: String,
    pub(crate) release: Option<String>,
    pub(crate) sample_rate: f64,
}

impl Config {
    /// Nothing exported.
    #[must_use]
    pub fn off() -> Self {
        Self {
            traces: None,
            sentry: None,
            environment: "development".to_owned(),
            release: None,
            sample_rate: 1.0,
        }
    }

    /// From this process's environment.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// From this process's environment, each of the [`VARIABLES`] under `prefix`: the daemon reads
    /// `SEALANT_SENTRY_DSN` and so on, because a workspace image's own `SENTRY_DSN` is the
    /// user's, not ours.
    #[must_use]
    pub fn from_prefixed_env(prefix: &str) -> Self {
        Self::from_lookup(|key| std::env::var(format!("{prefix}{key}")).ok())
    }

    /// From any source of the [`VARIABLES`]: a guest reads them out of its boot config.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let get = |key: &str| {
            get(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let sentry = get(SENTRY_DSN).and_then(|dsn| match sentry::types::Dsn::from_str(&dsn) {
            Ok(dsn) => Some(dsn),
            Err(error) => {
                // The DSN itself is not secret, but it is not ours to print either.
                tracing::warn!(%error, "SENTRY_DSN is not a DSN: nothing goes to Sentry");
                None
            }
        });
        let traces = match get(OTEL_EXPORTER_OTLP_ENDPOINT) {
            Some(base) => Some(TracesTarget {
                url: format!("{}/v1/traces", base.trim_end_matches('/')),
                headers: get(OTEL_EXPORTER_OTLP_HEADERS)
                    .map(|h| parse_headers(&h))
                    .unwrap_or_default(),
            }),
            None => sentry.as_ref().map(sentry_traces_target),
        };
        let sample_rate = get(SENTRY_TRACES_SAMPLE_RATE)
            .and_then(|r| r.parse::<f64>().ok())
            .filter(|r| r.is_finite())
            .map_or(1.0, |r| r.clamp(0.0, 1.0));
        Self {
            traces,
            sentry,
            environment: get(SENTRY_ENVIRONMENT).unwrap_or_else(|| "development".to_owned()),
            release: get(SENTRY_RELEASE),
            sample_rate,
        }
    }

    /// The release to report when `SENTRY_RELEASE` is unset: the build's own.
    #[must_use]
    pub fn with_default_release(mut self, release: Option<&str>) -> Self {
        if self.release.is_none() {
            self.release = release.filter(|r| !r.is_empty()).map(str::to_owned);
        }
        self
    }

    /// Whether anything is exported at all.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.traces.is_some() || self.sentry.is_some()
    }

    /// Whether errors go to Sentry.
    #[must_use]
    pub fn sends_errors(&self) -> bool {
        self.sentry.is_some()
    }

    /// Whether traces are exported.
    #[must_use]
    pub fn sends_traces(&self) -> bool {
        self.traces.is_some()
    }
}

/// The project's OTLP traces endpoint, beside its envelope endpoint, with its public key.
fn sentry_traces_target(dsn: &sentry::types::Dsn) -> TracesTarget {
    let envelope = dsn.envelope_api_url().to_string();
    let base = envelope
        .strip_suffix("envelope/")
        .unwrap_or(envelope.as_str());
    TracesTarget {
        url: format!("{base}integration/otlp/v1/traces"),
        headers: vec![(
            "x-sentry-auth".to_owned(),
            format!("sentry sentry_key={}", dsn.public_key()),
        )],
    }
}

/// `OTEL_EXPORTER_OTLP_HEADERS`: `key=value` pairs split on commas, values percent-decoded.
fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), percent_decode(v.trim())))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(&h), Some(&l)) if hex(h).is_some() && hex(l).is_some() => {
                let (h, l) = (hex(h).unwrap_or(0), hex(l).unwrap_or(0));
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Config {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|k| vars.get(k).cloned())
    }

    #[test]
    fn nothing_set_exports_nothing() {
        let config = config(&[]);
        assert!(!config.is_enabled());
        let blank = self::config(&[(SENTRY_DSN, "  "), (OTEL_EXPORTER_OTLP_ENDPOINT, "")]);
        assert!(!blank.is_enabled());
    }

    #[test]
    fn a_dsn_sends_traces_to_its_projects_otlp_endpoint() {
        let config = config(&[(
            SENTRY_DSN,
            "https://08f5480a962eb7ad02168e555f6df82c@sentry.example.com/10",
        )]);
        assert!(config.sends_errors());
        let traces = config.traces.expect("traces");
        assert_eq!(
            traces.url,
            "https://sentry.example.com/api/10/integration/otlp/v1/traces"
        );
        assert_eq!(
            traces.headers,
            vec![(
                "x-sentry-auth".to_owned(),
                "sentry sentry_key=08f5480a962eb7ad02168e555f6df82c".to_owned()
            )]
        );
        assert_eq!(config.environment, "development");
        assert_eq!(config.sample_rate, 1.0);
    }

    #[test]
    fn a_dsn_on_a_port_keeps_it() {
        let config = config(&[(SENTRY_DSN, "http://key@127.0.0.1:4318/3")]);
        assert_eq!(
            config.traces.expect("traces").url,
            "http://127.0.0.1:4318/api/3/integration/otlp/v1/traces"
        );
    }

    #[test]
    fn an_otlp_endpoint_overrides_the_dsns() {
        let config = config(&[
            (SENTRY_DSN, "https://key@sentry.example.com/10"),
            (OTEL_EXPORTER_OTLP_ENDPOINT, "http://localhost:4318/"),
            (OTEL_EXPORTER_OTLP_HEADERS, "a=1, b=x%3Dy ,=skipped,novalue"),
        ]);
        assert!(config.sends_errors());
        let traces = config.traces.expect("traces");
        assert_eq!(traces.url, "http://localhost:4318/v1/traces");
        assert_eq!(
            traces.headers,
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "x=y".to_owned())
            ]
        );
        assert!(!format!("{traces:?}").contains("x=y"));
    }

    #[test]
    fn a_bad_dsn_or_rate_falls_back() {
        let config = config(&[
            (SENTRY_DSN, "not a dsn"),
            (SENTRY_TRACES_SAMPLE_RATE, "lots"),
        ]);
        assert!(!config.is_enabled());
        assert_eq!(config.sample_rate, 1.0);
        let clamped = self::config(&[(SENTRY_TRACES_SAMPLE_RATE, "7")]);
        assert_eq!(clamped.sample_rate, 1.0);
        let half = self::config(&[(SENTRY_TRACES_SAMPLE_RATE, "0.5")]);
        assert_eq!(half.sample_rate, 0.5);
    }

    #[test]
    fn the_release_is_the_environments_then_the_builds() {
        let set = config(&[(SENTRY_RELEASE, "sealantd@1.2.3")])
            .with_default_release(Some("sealantd@0.0.1"));
        assert_eq!(set.release.as_deref(), Some("sealantd@1.2.3"));
        let unset = config(&[]).with_default_release(Some("sealantd@0.0.1"));
        assert_eq!(unset.release.as_deref(), Some("sealantd@0.0.1"));
        assert_eq!(config(&[]).with_default_release(Some("")).release, None);
    }
}
