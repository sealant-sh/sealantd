//! Secret env for one process (`process.secret-env.v1`): variables an `exec` or `openSession`
//! addresses to the process it starts, and to no other, their values masked in everything
//! recorded of it. One parser serves both spawn paths. A refusal names an entry by its index and
//! the rule it broke, never its name or value.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use sealant_protocol::{ControlError, EnvVar, SecretEnvVar};
use sealant_runtime_core::{PROXY_ENV_KEYS, REDACTED, Redactor};

use crate::identity::IDENTITY_KEYS;

/// At most this many entries.
pub const MAX_ENTRIES: usize = 128;
/// A name is at most this many bytes.
pub const MAX_NAME_BYTES: usize = 128;
/// A value is at least this many bytes: a shorter one would mask ordinary text.
pub const MIN_VALUE_BYTES: usize = 6;
/// A value is at most this many bytes.
pub const MAX_VALUE_BYTES: usize = 4096;
/// Names and values together are at most this many bytes.
pub const MAX_TOTAL_BYTES: usize = 32 * 1024;

/// Set by the daemon besides a person's identity ([`crate::identity::IDENTITY_KEYS`]): the
/// boot's `PATH` and a PTY's `TERM`.
const RUNTIME_SET_NAMES: &[&str] = &["PATH", "TERM"];

/// `[A-Za-z_][A-Za-z0-9_]*`, at most [`MAX_NAME_BYTES`]: the names the daemon accepts for an
/// environment it is handed, here and in the boot's secret environment.
#[must_use]
pub fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
        && name.len() <= MAX_NAME_BYTES
}

/// A name in the daemon's own `SEALANT_` namespace, in any case.
#[must_use]
pub fn is_platform_name(name: &str) -> bool {
    name.as_bytes()
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"SEALANT_"))
}

/// Whether masked output could still show `value`: the marker holds it, or it starts with the
/// marker's end or ends with its start, so a span masked next to it would complete it.
fn meets_marker(value: &[u8]) -> bool {
    REDACTED.windows(value.len()).any(|w| w == value)
        || (1..=REDACTED.len()).any(|n| {
            value.starts_with(&REDACTED[REDACTED.len() - n..]) || value.ends_with(&REDACTED[..n])
        })
}

/// The rule a refused entry broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// More than [`MAX_ENTRIES`] entries.
    EntryCount,
    /// More than [`MAX_TOTAL_BYTES`] across names and values.
    TotalSize,
    /// A name longer than [`MAX_NAME_BYTES`].
    NameLength,
    /// A name outside `[A-Za-z_][A-Za-z0-9_]*`.
    NameGrammar,
    /// A name given twice.
    NameDuplicate,
    /// A name also in the request's `env`.
    NameInEnv,
    /// A `SEALANT_` name.
    NamePlatform,
    /// A name the process's identity sets, or the runtime's `PATH` or `TERM`.
    NameIdentity,
    /// A name the egress proxy sets, in any case.
    NameProxy,
    /// A value holding NUL.
    ValueNul,
    /// A value under [`MIN_VALUE_BYTES`].
    ValueShort,
    /// A value over [`MAX_VALUE_BYTES`].
    ValueLong,
    /// A value the mask's own marker holds, or that starts with its end or ends with its start,
    /// so masked output could still show it.
    ValueInMarker,
}

impl Rule {
    /// The rule's stable name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EntryCount => "entry-count",
            Self::TotalSize => "total-size",
            Self::NameLength => "name-length",
            Self::NameGrammar => "name-grammar",
            Self::NameDuplicate => "name-duplicate",
            Self::NameInEnv => "name-in-env",
            Self::NamePlatform => "name-platform",
            Self::NameIdentity => "name-identity",
            Self::NameProxy => "name-proxy",
            Self::ValueNul => "value-nul",
            Self::ValueShort => "value-short",
            Self::ValueLong => "value-long",
            Self::ValueInMarker => "value-in-marker",
        }
    }
}

/// Why a secret env was refused: the entry (none for a rule over the whole set) and the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The refused entry's position in the request.
    pub index: Option<usize>,
    /// The rule it broke.
    pub rule: Rule,
}

impl From<Refusal> for ControlError {
    fn from(refusal: Refusal) -> Self {
        let rule = refusal.rule.as_str();
        ControlError::invalid_argument(match refusal.index {
            Some(index) => format!("secretEnv entry {index} refused: {rule}"),
            None => format!("secretEnv refused: {rule}"),
        })
    }
}

/// An accepted secret env. Its `Debug` holds neither names nor values, and it has no
/// serialization: it lives only until the process is spawned.
pub struct SecretEnv(Vec<SecretEnvVar>);

impl fmt::Debug for SecretEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretEnv").finish_non_exhaustive()
    }
}

impl SecretEnv {
    /// Accept `entries` for a process whose request `env` is `env`.
    ///
    /// # Errors
    /// The first entry that breaks a rule, by index and rule.
    pub fn parse(entries: Vec<SecretEnvVar>, env: &[EnvVar]) -> Result<Self, Refusal> {
        if entries.len() > MAX_ENTRIES {
            return Err(Refusal {
                index: None,
                rule: Rule::EntryCount,
            });
        }
        let mut seen = HashSet::new();
        let mut total = 0;
        for (index, entry) in entries.iter().enumerate() {
            let refuse = |rule| Refusal {
                index: Some(index),
                rule,
            };
            let (name, value) = (entry.key.as_str(), entry.value.as_bytes());
            let rule = if !is_env_name(name) {
                Some(if name.len() > MAX_NAME_BYTES {
                    Rule::NameLength
                } else {
                    Rule::NameGrammar
                })
            } else if !seen.insert(name) {
                Some(Rule::NameDuplicate)
            } else if env.iter().any(|var| var.key == name) {
                Some(Rule::NameInEnv)
            } else if is_platform_name(name) {
                Some(Rule::NamePlatform)
            } else if IDENTITY_KEYS.contains(&name) || RUNTIME_SET_NAMES.contains(&name) {
                Some(Rule::NameIdentity)
            } else if PROXY_ENV_KEYS
                .iter()
                .any(|key| key.eq_ignore_ascii_case(name))
            {
                Some(Rule::NameProxy)
            } else if value.contains(&0) {
                Some(Rule::ValueNul)
            } else if value.len() < MIN_VALUE_BYTES {
                Some(Rule::ValueShort)
            } else if value.len() > MAX_VALUE_BYTES {
                Some(Rule::ValueLong)
            } else if meets_marker(value) {
                Some(Rule::ValueInMarker)
            } else {
                None
            };
            if let Some(rule) = rule {
                return Err(refuse(rule));
            }
            total += name.len() + value.len();
        }
        if total > MAX_TOTAL_BYTES {
            return Err(Refusal {
                index: None,
                rule: Rule::TotalSize,
            });
        }
        Ok(Self(entries))
    }

    /// The variables, to set over the request's `env`.
    pub fn vars(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|v| (v.key.as_str(), v.value.as_str()))
    }

    /// The process's own patterns: `base`'s and these values. `base` itself is never extended.
    #[must_use]
    pub fn mask(&self, base: &Arc<Redactor>) -> Arc<Redactor> {
        if self.0.is_empty() {
            return base.clone();
        }
        Arc::new(base.with_literals(self.0.iter().map(|v| v.value.as_str())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "fake-pg-password-5d1e";

    fn var(key: &str, value: &str) -> SecretEnvVar {
        SecretEnvVar {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    fn refusal(entries: Vec<SecretEnvVar>, env: &[EnvVar]) -> Option<Refusal> {
        SecretEnv::parse(entries, env).err()
    }

    /// The rules both spawn paths apply, and Core's process admission mirrors: each case is
    /// refused at its index by its rule, and none of the diagnostics carries a name or value.
    #[test]
    fn each_rule_refuses_its_entry_without_its_name_or_value() {
        let ok = var("PGPASSWORD", VALUE);
        let long_name = "N".repeat(MAX_NAME_BYTES + 1);
        let max_name = "N".repeat(MAX_NAME_BYTES);
        let cases: Vec<(Vec<SecretEnvVar>, Option<usize>, Rule)> = vec![
            (vec![ok.clone(); MAX_ENTRIES + 1], None, Rule::EntryCount),
            (
                (0..9)
                    .map(|i| var(&format!("BIG_{i}"), &"v".repeat(MAX_VALUE_BYTES)))
                    .collect(),
                None,
                Rule::TotalSize,
            ),
            (
                vec![ok.clone(), var(&long_name, VALUE)],
                Some(1),
                Rule::NameLength,
            ),
            (vec![var("", VALUE)], Some(0), Rule::NameGrammar),
            (vec![var("1PW", VALUE)], Some(0), Rule::NameGrammar),
            (vec![var("PG-PW", VALUE)], Some(0), Rule::NameGrammar),
            (vec![var("PGPASSWÖRD", VALUE)], Some(0), Rule::NameGrammar),
            (vec![ok.clone(), ok.clone()], Some(1), Rule::NameDuplicate),
            (vec![var("PGUSER", VALUE)], Some(0), Rule::NameInEnv),
            (
                vec![var("SEALANT_SESSION_MARKER", VALUE)],
                Some(0),
                Rule::NamePlatform,
            ),
            (
                vec![var("SEALANT_CAPTURE_TOKEN", VALUE)],
                Some(0),
                Rule::NamePlatform,
            ),
            (
                vec![var("sealant_anything", VALUE)],
                Some(0),
                Rule::NamePlatform,
            ),
            (vec![var("HOME", VALUE)], Some(0), Rule::NameIdentity),
            (vec![var("TMPDIR", VALUE)], Some(0), Rule::NameIdentity),
            (
                vec![var("XDG_RUNTIME_DIR", VALUE)],
                Some(0),
                Rule::NameIdentity,
            ),
            (vec![var("PATH", VALUE)], Some(0), Rule::NameIdentity),
            (vec![var("TERM", VALUE)], Some(0), Rule::NameIdentity),
            (vec![var("https_proxy", VALUE)], Some(0), Rule::NameProxy),
            (vec![var("Http_Proxy", VALUE)], Some(0), Rule::NameProxy),
            (
                vec![var("PGPASSWORD", "fake\0secret")],
                Some(0),
                Rule::ValueNul,
            ),
            (vec![var("PGPASSWORD", "five5")], Some(0), Rule::ValueShort),
            (vec![var("PGPASSWORD", "")], Some(0), Rule::ValueShort),
            (
                vec![var("PGPASSWORD", &"v".repeat(MAX_VALUE_BYTES + 1))],
                Some(0),
                Rule::ValueLong,
            ),
            (
                vec![var("PGPASSWORD", "REDACTED")],
                Some(0),
                Rule::ValueInMarker,
            ),
            (
                vec![var("PGPASSWORD", "TED***")],
                Some(0),
                Rule::ValueInMarker,
            ),
            // Recorded right after a masked span, or right before one, these would still show.
            (
                vec![var("PGPASSWORD", "***abc1")],
                Some(0),
                Rule::ValueInMarker,
            ),
            (
                vec![var("PGPASSWORD", "pw-D***")],
                Some(0),
                Rule::ValueInMarker,
            ),
            (
                vec![var("PGPASSWORD", "fake-pg-pw*")],
                Some(0),
                Rule::ValueInMarker,
            ),
        ];
        let env = [EnvVar {
            key: "PGUSER".to_owned(),
            value: "developer".to_owned(),
        }];
        for (entries, index, rule) in cases {
            let names: Vec<String> = entries.iter().map(|e| e.key.clone()).collect();
            let values: Vec<String> = entries.iter().map(|e| e.value.clone()).collect();
            let got = refusal(entries, &env);
            assert_eq!(got, Some(Refusal { index, rule }), "{names:?}");
            let message = ControlError::from(got.unwrap()).message;
            assert!(message.contains(rule.as_str()), "{message}");
            for text in names.iter().chain(&values).filter(|t| t.len() > 1) {
                assert!(!message.contains(text.as_str()), "{message}");
            }
        }

        let accepted = [
            vec![ok.clone()],
            vec![var(
                "DATABASE_URL",
                "postgres://developer:fake-pg-pw@db/worktree",
            )],
            vec![var("pgpassword", "sixsix")],
            vec![var(&max_name, &"v".repeat(MAX_VALUE_BYTES))],
            vec![
                var("GITHUB_TOKEN", VALUE),
                var("_UNDERSCORE", "multi\nline"),
            ],
            (0..MAX_ENTRIES)
                .map(|i| var(&format!("PW_{i}"), VALUE))
                .collect(),
            vec![],
        ];
        for entries in accepted {
            assert_eq!(refusal(entries, &env), None);
        }
    }

    #[test]
    fn a_name_with_a_multi_byte_character_is_no_platform_name() {
        assert!(!is_platform_name("abcdefgÖ"));
        assert!(!is_platform_name("SEALANTÖ"));
        assert!(is_platform_name("sealant_x"));
        assert!(!is_platform_name("SEALANT"));
    }

    /// Every name a person's identity sets on their process is refused, so no secret replaces
    /// it; the rule reads the same list the identity is checked against.
    #[test]
    fn every_name_a_person_s_identity_sets_is_refused() {
        let person = crate::identity::RunAs {
            name: "fake-person".to_owned(),
            uid: 40_001,
            gid: 40_000,
            groups: vec![40_000],
            home: "/home/fake-person".into(),
            shell: "/bin/sh".into(),
        };
        let mut set: Vec<String> = person.env().into_iter().map(|(key, _)| key).collect();
        let mut listed: Vec<String> = IDENTITY_KEYS.iter().map(|k| (*k).to_owned()).collect();
        set.sort();
        listed.sort();
        assert_eq!(set, listed, "RunAs::env sets exactly IDENTITY_KEYS");
        for key in set {
            assert_eq!(
                refusal(vec![var(&key, VALUE)], &[]).map(|r| r.rule),
                Some(Rule::NameIdentity),
                "{key}"
            );
        }
    }

    #[test]
    fn a_process_mask_adds_its_values_to_the_base_and_leaves_the_base_alone() {
        let base = Arc::new(Redactor::new(vec!["fake-boot-secret-1".to_owned()]));
        let accepted = SecretEnv::parse(vec![var("PGPASSWORD", VALUE)], &[]).unwrap();
        let mask = |redactor: &Arc<Redactor>, raw: &[u8]| {
            let mut stream = redactor.stream();
            let mut out = stream.push(raw).recorded().to_vec();
            out.extend_from_slice(
                stream
                    .finish(sealant_runtime_core::FinishReason::Eof)
                    .recorded(),
            );
            String::from_utf8(out).unwrap()
        };
        let line = format!("{VALUE} fake-boot-secret-1");
        assert_eq!(
            mask(&accepted.mask(&base), line.as_bytes()),
            "***REDACTED*** ***REDACTED***"
        );
        assert_eq!(
            mask(&base, line.as_bytes()),
            format!("{VALUE} ***REDACTED***")
        );
        assert!(!format!("{accepted:?}").contains(VALUE));
        let none = SecretEnv::parse(vec![], &[]).unwrap();
        assert!(Arc::ptr_eq(&none.mask(&base), &base));
    }
}
