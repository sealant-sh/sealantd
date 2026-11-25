// The request and result shapes both kinds of connection share.

import type { MessageInitShape } from "@bufbuild/protobuf";
import {
  create,
  encodeClient,
  encodeFrame,
  SCHEMA_VERSION,
  ClientMessageSchema,
  CommandSchema,
  StreamFrameSchema,
  ControlErrorCode,
  type CommandResult,
  type ControlError,
  type ControlResponse,
} from "@sealant/runtime-protocol";

/** Error raised when the daemon returns a typed control error. */
export class SealantError extends Error {
  /** Stable error code (e.g. `ControlErrorCode.PROCESS_START_FAILED`). */
  readonly code: ControlErrorCode;
  /** Optional machine-readable detail JSON. */
  readonly detailJson?: string;
  constructor(error: ControlError) {
    super(error.message || "control error");
    this.name = "SealantError";
    this.code = error.code;
    this.detailJson = error.detailJson;
  }
}

/** The init shape of the `Command` oneof (what callers pass to `SealantClient.request`). */
export type CommandInit = MessageInitShape<typeof CommandSchema>["command"];

/**
 * A W3C trace context (https://www.w3.org/TR/trace-context/), or a bare `traceparent`
 * (`00-<32 hex trace id>-<16 hex parent span id>-<2 hex flags>`). The daemon makes the span it
 * starts for a request a child of it, so the request shows in the caller's trace.
 */
export type TraceInput = string | { traceparent: string; tracestate?: string };

/** The wire field's shape. */
type WireTrace = { traceparent: string; tracestate: string };

const TRACEPARENT = /^[0-9a-f]{2}-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}$/;
// The W3C limit for tracestate (32 members of at most 256 bytes, kept well inside one frame).
const MAX_TRACESTATE = 512;

/**
 * The trace context to put on the wire, or undefined when `input` is not a valid one. A bad trace
 * is dropped, never thrown: tracing must not fail a request.
 */
export function wireTrace(input: TraceInput | undefined): WireTrace | undefined {
  if (input === undefined) return undefined;
  const { traceparent, tracestate } =
    typeof input === "string" ? { traceparent: input, tracestate: undefined } : input;
  if (typeof traceparent !== "string" || !TRACEPARENT.test(traceparent)) return undefined;
  const state =
    typeof tracestate === "string" && tracestate.length <= MAX_TRACESTATE ? tracestate : "";
  return { traceparent, tracestate: state };
}

export function requestFrame(
  requestId: string,
  command: CommandInit,
  trace?: WireTrace,
): Uint8Array {
  const message = create(ClientMessageSchema, {
    message: {
      case: "request",
      value: { schemaVersion: SCHEMA_VERSION, requestId, command: { command }, trace },
    },
  });
  return encodeFrame(encodeClient(message));
}

/** Throw on an error outcome; otherwise return the `CommandResult`. */
export function okResult(response: ControlResponse): CommandResult {
  // ControlResponse.outcome is a ResponseOutcome message whose `outcome` oneof is ok | error.
  const outcome = response.outcome?.outcome;
  if (outcome?.case === "error") {
    throw new SealantError(outcome.value);
  }
  if (outcome?.case === "ok") {
    return outcome.value;
  }
  throw new Error("response had no outcome");
}

/** Assert the `CommandResult` is a specific result case and return its (untyped) value. The caller
 * casts to the exact result type — the public method signatures are the typed contract. */
export function resultValue(result: CommandResult, kase: CommandResult["result"]["case"]): unknown {
  if (result.result.case !== kase) {
    throw new Error(`expected result ${kase}, got ${String(result.result.case)}`);
  }
  return (result.result as { value: unknown }).value;
}


/** The init shape of the `StreamFrame.payload` oneof (what a connection muxes outbound). */
export type StreamPayload = MessageInitShape<typeof StreamFrameSchema>["payload"];

export function streamFrame(channelId: string, payload: StreamPayload): Uint8Array {
  const message = create(ClientMessageSchema, {
    message: { case: "stream", value: { channelId, seq: 0n, payload } },
  });
  return encodeFrame(encodeClient(message));
}

export interface OpenForwardOptions {
  /** Destination host, resolved inside the workspace. */
  host: string;
  port: number;
  /** TCP is a byte stream; UDP is a connected socket where one channel frame is one datagram. */
  protocol: "tcp" | "udp";
  /** Execution to correlate the forward with (a label; the daemon checks nothing about it). */
  executionId?: string;
  /**
   * Bind the forward to this session: it opens only once a process of the session holds the
   * connection's far end, and ends when the session's leader exits. TCP to loopback only. A
   * daemon whose capabilities lack `forward.owner` ignores it, so check that the result's
   * `boundSessionId` echoes it before relying on the binding.
   */
  ownerSessionId?: string;
}

export function openForwardCommand(options: OpenForwardOptions, dedicated = false): CommandInit {
  const { host, port, executionId, protocol, ownerSessionId } = options;
  return {
    case: "openForward",
    // Omit tcp on the wire: the field's absence is the old default.
    value: {
      host,
      port,
      executionId,
      protocol: protocol === "udp" ? "udp" : undefined,
      dedicated: dedicated || undefined,
      ownerSessionId,
    },
  };
}
