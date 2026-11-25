//! What may leave the process in a Sentry event.
//!
//! Spans carry only the fields their code names (ids and enums, never arguments, environment or
//! output), so they need no scrubbing. A Sentry event is different: an `error!` message, an error's
//! `Display` or a panic message can quote whatever the failing code held. Every string an event
//! carries is therefore masked with the daemon's own redactor (its configured secrets and the
//! token shapes it masks in recorded output), then stripped of URL credentials and query strings,
//! and the event loses its breadcrumbs, request, user and host name.

use std::sync::{Arc, PoisonError, RwLock};

use sealant_runtime_core::redact::{FinishReason, REDACTED, Redactor};
use sentry::protocol::{Context, Event, Map, Value};

static REDACTOR: RwLock<Option<Arc<Redactor>>> = RwLock::new(None);

/// Mask `redactor`'s secrets, as well as the built-in token shapes, in everything sent to Sentry
/// from now on. The daemon passes the redactor it masks recorded output with.
pub fn set_redactor(redactor: Arc<Redactor>) {
    *REDACTOR.write().unwrap_or_else(PoisonError::into_inner) = Some(redactor);
}

fn redactor() -> Arc<Redactor> {
    REDACTOR
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .unwrap_or_default()
}

/// `text` as it may be sent: secrets masked, URL credentials and queries removed.
#[must_use]
pub fn scrub_text(text: &str) -> String {
    let redactor = redactor();
    let mut stream = redactor.stream();
    let mut masked = stream.push(text.as_bytes()).recorded().to_vec();
    masked.extend_from_slice(stream.finish(FinishReason::Eof).recorded());
    strip_urls(&String::from_utf8_lossy(&masked))
}

const MASK: &str = match std::str::from_utf8(REDACTED) {
    Ok(mask) => mask,
    Err(_) => "***REDACTED***",
};

/// Each `scheme://user:pass@host/path?query` loses its user info and its query.
fn strip_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`'))
            .unwrap_or(tail.len());
        let (url, after) = tail.split_at(end);
        let authority_end = url.find(['/', '?', '#']).unwrap_or(url.len());
        let (authority, path) = url.split_at(authority_end);
        match authority.rfind('@') {
            Some(at) => {
                out.push_str(MASK);
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        match path.find('?') {
            Some(q) => {
                out.push_str(&path[..=q]);
                out.push_str(MASK);
            }
            None => out.push_str(path),
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn scrub_value(value: &mut Value) {
    match value {
        Value::String(s) => *s = scrub_text(s),
        Value::Array(items) => items.iter_mut().for_each(scrub_value),
        Value::Object(map) => map.values_mut().for_each(scrub_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn scrub_map(map: &mut Map<String, Value>) {
    map.values_mut().for_each(scrub_value);
}

fn scrub_opt(text: &mut Option<String>) {
    if let Some(t) = text {
        *t = scrub_text(t);
    }
}

/// The event as it may be sent (`before_send`).
#[must_use]
pub fn scrub_event(mut event: Event<'static>) -> Event<'static> {
    scrub_opt(&mut event.message);
    scrub_opt(&mut event.culprit);
    scrub_opt(&mut event.transaction);
    if let Some(entry) = &mut event.logentry {
        entry.message = scrub_text(&entry.message);
        entry.params.iter_mut().for_each(scrub_value);
    }
    for exception in &mut event.exception.values {
        scrub_opt(&mut exception.value);
        if let Some(mechanism) = &mut exception.mechanism {
            scrub_opt(&mut mechanism.description);
            scrub_map(&mut mechanism.data);
        }
    }
    for value in event.tags.values_mut() {
        *value = scrub_text(value);
    }
    scrub_map(&mut event.extra);
    for context in event.contexts.values_mut() {
        match context {
            Context::Other(map) => scrub_map(map),
            // The host's name can be a workspace's.
            Context::Device(device) => device.name = None,
            _ => {}
        }
    }
    event.breadcrumbs.values.clear();
    event.request = None;
    event.user = None;
    event.server_name = None;
    event.modules.clear();
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_lose_credentials_and_queries() {
        assert_eq!(
            strip_urls("clone https://bob:hunter22@git.example.com/a/b.git?token=abc failed"),
            "clone https://***REDACTED***@git.example.com/a/b.git?***REDACTED*** failed"
        );
        assert_eq!(
            strip_urls("\"http://h:1/p\" and s3://bucket/key?X-Amz-Signature=zz"),
            "\"http://h:1/p\" and s3://bucket/key?***REDACTED***"
        );
        assert_eq!(strip_urls("no url here"), "no url here");
        assert_eq!(strip_urls("dangling ://"), "dangling ://");
    }

    #[test]
    fn known_secrets_and_token_shapes_are_masked() {
        set_redactor(Arc::new(Redactor::new(vec![
            "launch-secret-0042".to_owned(),
        ])));
        let text = scrub_text("failed with launch-secret-0042 and ghp_abcdefghijklmnopqrstuvwx");
        assert!(!text.contains("launch-secret-0042"), "{text}");
        assert!(!text.contains("ghp_abcdefghijklmnopqrstuvwx"), "{text}");
        assert!(text.contains(MASK), "{text}");
    }

    #[test]
    fn an_event_keeps_no_breadcrumbs_request_user_or_host() {
        let mut event = Event {
            message: Some("x https://u:p@h/?q=1".to_owned()),
            server_name: Some("workspace-7".into()),
            ..Event::default()
        };
        event.extra.insert(
            "path".to_owned(),
            Value::String("https://u:p@h/".to_owned()),
        );
        event.breadcrumbs.values.push(sentry::Breadcrumb::default());
        let event = scrub_event(event);
        assert_eq!(
            event.message.as_deref(),
            Some("x https://***REDACTED***@h/?***REDACTED***")
        );
        assert_eq!(
            event.extra["path"],
            Value::String("https://***REDACTED***@h/".to_owned())
        );
        assert!(event.breadcrumbs.values.is_empty());
        assert!(event.server_name.is_none());
    }
}
