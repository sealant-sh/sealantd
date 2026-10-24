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

export function requestFrame(requestId: string, command: CommandInit): Uint8Array {
  const message = create(ClientMessageSchema, {
    message: {
      case: "request",
      value: { schemaVersion: SCHEMA_VERSION, requestId, command: { command } },
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
