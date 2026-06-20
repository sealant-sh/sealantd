//! Top-level wire messages: framed requests, responses, and the server message multiplexer.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandResult};
use crate::error::ControlError;
use crate::event::EventEnvelope;
use crate::ids::RequestId;

/// A request from a control client to the daemon.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ControlRequest {
    /// Wire schema version.
    pub schema_version: u32,
    /// Correlation / duplicate-detection key.
    pub request_id: RequestId,
    /// The command to execute.
    pub command: Command,
}

impl ControlRequest {
    /// Build a request at the current [`crate::SCHEMA_VERSION`].
    pub fn new(request_id: RequestId, command: Command) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            request_id,
            command,
        }
    }
}

/// Outcome of a control request: exactly one ack or one typed error (plan §8.6).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum ResponseOutcome {
    /// The request succeeded, optionally carrying a typed result.
    Ok {
        /// Result payload, when the command returns data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<CommandResult>,
    },
    /// The request failed with a deterministic error.
    Error {
        /// The error.
        error: ControlError,
    },
}

/// A response to exactly one [`ControlRequest`].
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ControlResponse {
    /// Wire schema version.
    pub schema_version: u32,
    /// The request this answers.
    pub request_id: RequestId,
    /// The outcome.
    pub outcome: ResponseOutcome,
}

impl ControlResponse {
    /// A success response with an optional result.
    pub fn ok(request_id: RequestId, result: Option<CommandResult>) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            request_id,
            outcome: ResponseOutcome::Ok { result },
        }
    }

    /// A success response carrying a typed result.
    pub fn ok_with(request_id: RequestId, result: CommandResult) -> Self {
        Self::ok(request_id, Some(result))
    }

    /// A generic success acknowledgement with no data.
    pub fn accepted(request_id: RequestId) -> Self {
        Self::ok(request_id, Some(CommandResult::Accepted))
    }

    /// An error response.
    pub fn error(request_id: RequestId, error: ControlError) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            request_id,
            outcome: ResponseOutcome::Error { error },
        }
    }

    /// Whether this response is a success.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self.outcome, ResponseOutcome::Ok { .. })
    }
}

/// A message sent by a control client. Tagged by `kind` for forward compatibility.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ClientMessage {
    /// A control request.
    Request(ControlRequest),
}

impl From<ControlRequest> for ClientMessage {
    fn from(request: ControlRequest) -> Self {
        Self::Request(request)
    }
}

/// A message sent by the daemon: either a response or an asynchronous telemetry event.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ServerMessage {
    /// A response to a request.
    Response(ControlResponse),
    /// An asynchronous telemetry event.
    Event(EventEnvelope),
}

impl From<ControlResponse> for ServerMessage {
    fn from(response: ControlResponse) -> Self {
        Self::Response(response)
    }
}

impl From<EventEnvelope> for ServerMessage {
    fn from(event: EventEnvelope) -> Self {
        Self::Event(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ExecArgs;
    use crate::event::{CaptureMethod, Confidence, EventPayload, RuntimeHeartbeat, RuntimeState};
    use crate::ids::{EventId, MonotonicNanos, RuntimeId, Sequence, WallClockMicros};

    #[test]
    fn client_request_is_kind_tagged() {
        let msg = ClientMessage::Request(ControlRequest::new(
            RequestId::new("req_1"),
            Command::Exec(ExecArgs {
                execution_id: None,
                session_id: None,
                executable: "/bin/true".to_owned(),
                args: vec![],
                cwd: None,
                env: vec![],
                stdin: false,
                timeout_millis: None,
                background: false,
                capture: None,
                graceful_signal: None,
            }),
        ));
        let value = serde_json::to_value(&msg).expect("ser");
        assert_eq!(value["kind"], "request");
        assert_eq!(value["requestId"], "req_1");
        assert_eq!(value["command"]["cmd"], "exec");
        let back: ClientMessage = serde_json::from_value(value).expect("de");
        assert_eq!(back, msg);
    }

    #[test]
    fn server_response_round_trips() {
        let msg = ServerMessage::Response(ControlResponse::accepted(RequestId::new("req_2")));
        let json = serde_json::to_string(&msg).expect("ser");
        let back: ServerMessage = serde_json::from_str(&json).expect("de");
        assert_eq!(back, msg);
    }

    #[test]
    fn server_event_round_trips_with_flattened_payload() {
        let env = EventEnvelope {
            schema_version: crate::SCHEMA_VERSION,
            event_id: EventId::new("evt_9"),
            runtime_id: RuntimeId::new("rt_1"),
            execution_id: None,
            session_id: None,
            process_id: None,
            request_id: None,
            sequence: Sequence(1),
            observed_at: WallClockMicros(1),
            monotonic_timestamp: MonotonicNanos(1),
            capture_method: CaptureMethod::Internal,
            confidence: Confidence::Observed,
            payload: EventPayload::RuntimeHeartbeat(RuntimeHeartbeat {
                state: RuntimeState::Healthy,
            }),
        };
        let msg = ServerMessage::Event(env);
        let value = serde_json::to_value(&msg).expect("ser");
        assert_eq!(value["kind"], "event");
        assert_eq!(value["eventType"], "runtime.heartbeat");
        assert_eq!(value["state"], "healthy");
        let back: ServerMessage = serde_json::from_value(value).expect("de");
        assert_eq!(back, msg);
    }
}
