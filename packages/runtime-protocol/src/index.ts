// @sealant/runtime-protocol
//
// TypeScript view of the sealantd control protocol. Hand-authored for the Phase 1 vertical slice;
// at monorepo integration these types are generated/validated from the Rust schemars JSON Schema
// (see docs/adr/0010-typescript-type-generation-and-compatibility.md) and re-expressed with Effect
// Schema to match @sealant/api-contracts conventions.

import { Buffer } from "node:buffer";

/** Current wire schema version. */
export const SCHEMA_VERSION = 1;

/** Default maximum control-frame body size (8 MiB). */
export const DEFAULT_MAX_FRAME_BYTES = 8 * 1024 * 1024;

// --- identifiers (opaque strings) ---
export type RequestId = string;
export type RuntimeId = string;
export type ExecutionId = string;
export type SessionId = string;
export type ProcessId = string;
export type EventId = string;

// --- error codes (closed union; see plan §8.6) ---
export type ControlErrorCode =
  | "invalid-json"
  | "unsupported-version"
  | "frame-too-large"
  | "unknown-command"
  | "invalid-argument"
  | "missing-command"
  | "execution-not-found"
  | "session-not-found"
  | "process-not-found"
  | "process-start-failed"
  | "pty-allocation-failed"
  | "permission-denied"
  | "policy-denied"
  | "feature-unavailable"
  | "capability-unavailable"
  | "queue-full"
  | "runtime-shutting-down"
  | "internal-error";

export interface ControlError {
  code: ControlErrorCode;
  message: string;
  detail?: unknown;
}

// --- commands ---
export interface EnvVar {
  key: string;
  value: string;
}

export interface ExecArgs {
  executionId?: string;
  sessionId?: string;
  executable: string;
  args?: string[];
  cwd?: string;
  env?: EnvVar[];
  stdin?: boolean;
  timeoutMillis?: number;
  background?: boolean;
}

export type Signal =
  | "SIGHUP"
  | "SIGINT"
  | "SIGQUIT"
  | "SIGTERM"
  | "SIGKILL"
  | "SIGUSR1"
  | "SIGUSR2"
  | "SIGSTOP"
  | "SIGCONT";

export type Command =
  | { cmd: "runtime.health" }
  | { cmd: "runtime.getCapabilities" }
  | { cmd: "runtime.gracefulShutdown"; args?: { graceMillis?: number } }
  | { cmd: "runtime.kill" }
  | { cmd: "exec"; args: ExecArgs }
  | { cmd: "signalProcess"; args: { processId: string; signal: Signal } }
  | { cmd: "killProcess"; args: { processId: string } }
  | { cmd: "listProcesses"; args?: { executionId?: string } }
  | { cmd: "writeStdin"; args: { processId?: string; sessionId?: string; data: string } }
  | { cmd: "closeStdin"; args: { processId: string } }
  | { cmd: "getRuntimeMetrics" };

export interface ControlRequest {
  schemaVersion: number;
  requestId: string;
  command: Command;
}

// --- results ---
export interface ExecAccepted {
  type: "execAccepted";
  processId: string;
  pid: number;
  pgid: number;
  pidfd: boolean;
}

export interface HealthReport {
  type: "health";
  state: RuntimeState;
  runtimeId: string;
  uptimeMillis: number;
  activeProcesses: number;
  activeSessions: number;
  activeExecutions: number;
  droppedEvents: number;
  sinkConnected: boolean;
  degradationReasons: string[];
  [key: string]: unknown;
}

export interface Capabilities {
  type?: "capabilities";
  schemaVersion: number;
  runtimeId: string;
  sandboxId?: string;
  os: string;
  arch: string;
  daemonVersion: string;
  features: Record<string, unknown>;
  limits: Record<string, number>;
}

export type CommandResult =
  | ExecAccepted
  | HealthReport
  | { type: "capabilities" } & Capabilities
  | { type: "shutdownAccepted"; graceMillis: number }
  | { type: "metrics"; [key: string]: unknown }
  | { type: "processList"; processes: unknown[] }
  | { type: "sessionList"; sessions: unknown[] }
  | { type: "accepted" };

export type ResponseOutcome =
  | { status: "ok"; result?: CommandResult }
  | { status: "error"; error: ControlError };

export interface ControlResponse {
  schemaVersion: number;
  requestId: string;
  outcome: ResponseOutcome;
}

// --- events ---
export type RuntimeState =
  | "starting"
  | "healthy"
  | "degraded"
  | "unhealthy"
  | "shuttingDown"
  | "stopped";

export type StreamKind = "stdin" | "stdout" | "stderr" | "pty.input" | "pty.output";

export interface EventEnvelope {
  schemaVersion: number;
  eventId: string;
  runtimeId: string;
  executionId?: string;
  sessionId?: string;
  processId?: string;
  requestId?: string;
  sequence: number;
  observedAt: number;
  monotonicTimestamp: number;
  captureMethod: string;
  confidence: string;
  eventType: string;
  [key: string]: unknown;
}

export interface IoChunkEvent extends EventEnvelope {
  eventType: "io.chunk";
  stream: StreamKind;
  encoding: "base64";
  byteCount: number;
  streamOffset: number;
  content?: string;
}

export interface ProcessExitedEvent extends EventEnvelope {
  eventType: "process.exited";
  exitCode?: number;
  signal?: number;
  reason: string;
  durationMicros: number;
}

export type ClientMessage = { kind: "request" } & ControlRequest;
export type ServerMessage =
  | ({ kind: "response" } & ControlResponse)
  | ({ kind: "event" } & EventEnvelope);

// --- helpers ---
export function isIoChunk(event: EventEnvelope): event is IoChunkEvent {
  return event.eventType === "io.chunk";
}

export function isProcessExited(event: EventEnvelope): event is ProcessExitedEvent {
  return event.eventType === "process.exited";
}

/** Decode an `io.chunk` event's inline base64 content into raw bytes. */
export function chunkBytes(event: IoChunkEvent): Buffer {
  return event.content ? Buffer.from(event.content, "base64") : Buffer.alloc(0);
}

// --- framing ---

/** Encode a message as a length-prefixed JSON frame. */
export function encodeFrame(message: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

/** Incremental frame decoder: feed socket chunks, get whole JSON messages back. */
export class FrameDecoder {
  #buffer: Buffer = Buffer.alloc(0);
  #maxFrameBytes: number;

  constructor(maxFrameBytes: number = DEFAULT_MAX_FRAME_BYTES) {
    this.#maxFrameBytes = maxFrameBytes;
  }

  push(chunk: Buffer): unknown[] {
    this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);
    const messages: unknown[] = [];
    while (this.#buffer.length >= 4) {
      const length = this.#buffer.readUInt32BE(0);
      if (length > this.#maxFrameBytes) {
        throw new Error(`frame length ${length} exceeds maximum ${this.#maxFrameBytes}`);
      }
      if (this.#buffer.length < 4 + length) {
        break;
      }
      const body = this.#buffer.subarray(4, 4 + length);
      messages.push(JSON.parse(body.toString("utf8")));
      this.#buffer = this.#buffer.subarray(4 + length);
    }
    return messages;
  }
}
