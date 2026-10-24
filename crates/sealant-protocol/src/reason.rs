//! The machine reasons a refused forward carries in `ControlError.detail.reason`, and the
//! environment entry that marks a session's processes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The environment entry that marks a session's processes for a forward bound to the session.
/// Its value is a secret sealantd mints per session, never the session id: every leader gets it,
/// and so does an `exec` that names a running session it runs as the same user as. A process the
/// session starts inherits it, which covers a server that left the session's Linux session
/// (`setsid`, a double fork). Only the first entry counts, as for `getenv`.
pub const SESSION_ENV: &str = "SEALANT_SESSION_MARKER";

/// Why a TCP forward's connect failed, in the terms a caller branches on. A failure outside these
/// kinds carries no reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardConnectReason {
    /// The target answered with a reset: nothing listens on that address and port.
    ConnectionRefused,
    /// The host name did not resolve, or not before the connect deadline.
    NameUnresolved,
    /// No route to the host or its network.
    NetworkUnreachable,
    /// No answer before the connect deadline.
    DialTimeout,
}

/// Why a forward bound to a session was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardBindingRefusal {
    /// The session is not running, or its leader exited before the forward was confirmed.
    OwnerExited,
    /// A process outside the session holds the connection's far end.
    PeerMismatch,
    /// No holder could be found and checked before the connect deadline: a server that has
    /// not accepted yet, one whose `/proc` entries sealantd cannot read, or a target outside
    /// sealantd's view.
    #[serde(rename = "binding-unverifiable")]
    Unverifiable,
}

impl ForwardBindingRefusal {
    pub const ALL: [Self; 3] = [Self::OwnerExited, Self::PeerMismatch, Self::Unverifiable];

    /// The `ControlError.detail` that carries this refusal.
    #[must_use]
    pub fn detail(self) -> serde_json::Value {
        serde_json::json!({ "reason": self })
    }

    /// The reason string itself, which a bound forward's `End.error` carries when its owner
    /// exits.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::OwnerExited => "owner-exited",
            Self::PeerMismatch => "peer-mismatch",
            Self::Unverifiable => "binding-unverifiable",
        }
    }
}

impl ForwardConnectReason {
    pub const ALL: [Self; 4] = [
        Self::ConnectionRefused,
        Self::NameUnresolved,
        Self::NetworkUnreachable,
        Self::DialTimeout,
    ];

    /// The `ControlError.detail` that carries this reason.
    #[must_use]
    pub fn detail(self) -> serde_json::Value {
        serde_json::json!({ "reason": self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The quoted strings of the `as const` array `name` in a TypeScript source.
    fn ts_list(source: &str, name: &str) -> Vec<String> {
        let start = source
            .find(&format!("export const {name} = ["))
            .unwrap_or_else(|| panic!("{name} is exported"));
        let body = &source[start..];
        let body = &body[body.find('[').expect("[") + 1..body.find("] as const").expect("]")];
        body.split(',')
            .map(|item| item.trim().trim_matches('"').to_owned())
            .filter(|item| !item.is_empty())
            .collect()
    }

    #[test]
    fn the_typescript_package_names_the_same_connect_reasons() {
        let source = include_str!("../../../packages/runtime-protocol/src/reason.ts");
        let rust: Vec<String> = ForwardConnectReason::ALL
            .iter()
            .map(|reason| serde_json::to_value(reason).expect("serialize"))
            .map(|value| value.as_str().expect("a string").to_owned())
            .collect();
        assert_eq!(ts_list(source, "FORWARD_CONNECT_REASONS"), rust);
    }

    #[test]
    fn the_typescript_package_names_the_same_binding_refusals() {
        let source = include_str!("../../../packages/runtime-protocol/src/reason.ts");
        let rust: Vec<String> = ForwardBindingRefusal::ALL
            .iter()
            .map(|refusal| serde_json::to_value(refusal).expect("serialize"))
            .map(|value| value.as_str().expect("a string").to_owned())
            .collect();
        assert_eq!(ts_list(source, "FORWARD_BINDING_REFUSALS"), rust);
        for refusal in ForwardBindingRefusal::ALL {
            assert_eq!(
                serde_json::to_value(refusal).expect("serialize"),
                refusal.reason()
            );
        }
    }

    #[test]
    fn a_reason_travels_as_detail_reason() {
        assert_eq!(
            ForwardConnectReason::ConnectionRefused.detail(),
            serde_json::json!({ "reason": "connection-refused" })
        );
    }
}
