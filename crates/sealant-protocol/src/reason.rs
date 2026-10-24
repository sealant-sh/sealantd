//! The machine reasons a refused forward carries in `ControlError.detail.reason`.
//!
//! `@sealant/runtime-protocol` exports the same strings (`packages/runtime-protocol/src/reason.ts`),
//! so a caller imports them rather than retyping them; a test here keeps the two lists equal.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

impl ForwardConnectReason {
    /// Every reason, in the order `@sealant/runtime-protocol` lists them.
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
    fn a_reason_travels_as_detail_reason() {
        assert_eq!(
            ForwardConnectReason::ConnectionRefused.detail(),
            serde_json::json!({ "reason": "connection-refused" })
        );
    }
}
