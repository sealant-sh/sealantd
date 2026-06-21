// @sealant/runtime-client
//
// Ergonomic, typed TypeScript client for sealantd over the Protobuf wire (ADR-0012). Uses IPC (a Unix
// domain socket) as the language boundary — never in-process FFI (plan §19). Built on the
// Buf-generated protobuf-es types from @sealant/runtime-protocol, so commands, responses, and events
// are fully typed (discriminated unions + TS enums).

import net from "node:net";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { Buffer } from "node:buffer";
import { setTimeout as delay } from "node:timers/promises";
import type { Duplex } from "node:stream";
import type { MessageInitShape } from "@bufbuild/protobuf";

import {
  create,
  encodeClient,
  encodeFrame,
  FrameDecoder,
  SCHEMA_VERSION,
  ClientMessageSchema,
  CommandSchema,
  ControlErrorCode,
  type CommandResult,
  type Capabilities,
  type ControlError,
  type ControlResponse,
  type EventEnvelope,
  type ExecAccepted,
  type HealthReport,
  type ProcessList,
  type RuntimeMetrics,
  type ServerMessage,
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

type Pending = {
  resolve: (response: ControlResponse) => void;
  reject: (error: Error) => void;
};

/** The init shape of the `Command` oneof (what callers pass to {@link SealantClient.request}). */
type CommandInit = MessageInitShape<typeof CommandSchema>["command"];

/** Throw on an error outcome; otherwise return the `CommandResult`. */
function okResult(response: ControlResponse): CommandResult {
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
function resultValue(result: CommandResult, kase: CommandResult["result"]["case"]): unknown {
  if (result.result.case !== kase) {
    throw new Error(`expected result ${kase}, got ${String(result.result.case)}`);
  }
  return (result.result as { value: unknown }).value;
}

/** Options for {@link SealantClient.exec} (a subset of the wire `ExecArgs`). */
export interface ExecOptions {
  executable: string;
  args?: string[];
  executionId?: string;
  sessionId?: string;
  cwd?: string;
  stdin?: boolean;
  timeoutMillis?: number;
  background?: boolean;
}

/** A connected, typed control client for one sealantd instance. */
export class SealantClient {
  #stream: Duplex;
  #decoder: FrameDecoder = new FrameDecoder();
  #pending: Map<string, Pending> = new Map();
  #counter = 0;
  #closed = false;
  #eventQueue: EventEnvelope[] = [];
  #eventWaiters: Array<(result: IteratorResult<EventEnvelope>) => void> = [];

  constructor(stream: Duplex) {
    this.#stream = stream;
    this.#attach(stream);
  }

  /** Wire a transport stream's data/close/end/error events into the client. */
  #attach(stream: Duplex): void {
    stream.on("data", (chunk: Buffer) => this.#onData(chunk));
    stream.on("close", () => this.#onClose());
    // A `docker exec -i` stdio Duplex emits "end" (not always "close"); #onClose is idempotent.
    stream.on("end", () => this.#onClose());
    stream.on("error", () => {});
  }

  /**
   * Build a client over an arbitrary Node Duplex — e.g. a `docker exec -i` stdio pipe bridged to the
   * daemon's Unix socket. The framing/protocol is transport-agnostic, so this drives the same
   * request/response/event machinery as {@link SealantClient.connect}.
   */
  static fromStream(stream: Duplex): SealantClient {
    return new SealantClient(stream);
  }

  static async connect(
    socketPath: string,
    options: { retries?: number; delayMs?: number } = {},
  ): Promise<SealantClient> {
    const retries = options.retries ?? 100;
    const delayMs = options.delayMs ?? 20;
    let lastError: unknown;
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        return new SealantClient(await connectOnce(socketPath));
      } catch (error) {
        lastError = error;
        await delay(delayMs);
      }
    }
    throw lastError instanceof Error ? lastError : new Error("connection failed");
  }

  static async spawn(options: {
    binPath: string;
    socketPath: string;
    workspace?: string;
    sandboxId?: string;
    executionId?: string;
    spoolDir?: string;
    watchFilesystem?: boolean;
    networkProxy?: boolean;
    logLevel?: string;
  }): Promise<{ client: SealantClient; child: ChildProcess }> {
    const args = ["--socket", options.socketPath, "--log-level", options.logLevel ?? "off"];
    if (options.workspace) args.push("--workspace", options.workspace);
    if (options.sandboxId) args.push("--sandbox-id", options.sandboxId);
    if (options.executionId) args.push("--execution-id", options.executionId);
    if (options.spoolDir) args.push("--spool-dir", options.spoolDir);
    if (options.watchFilesystem) args.push("--watch-filesystem");
    if (options.networkProxy) args.push("--network-proxy");
    const child = spawn(options.binPath, args, { stdio: ["ignore", "ignore", "inherit"] });
    try {
      return { client: await SealantClient.connect(options.socketPath), child };
    } catch (error) {
      child.kill("SIGKILL");
      throw error;
    }
  }

  /** Send a command oneof case and await its single (typed) response. */
  request(command: CommandInit): Promise<ControlResponse> {
    if (this.#closed) {
      return Promise.reject(new Error("client is closed"));
    }
    const requestId = `req_client_${++this.#counter}`;
    const message = create(ClientMessageSchema, {
      message: {
        case: "request",
        value: { schemaVersion: SCHEMA_VERSION, requestId, command: { command } },
      },
    });
    const body = encodeClient(message);
    return new Promise((resolve, reject) => {
      this.#pending.set(requestId, { resolve, reject });
      this.#stream.write(encodeFrame(body), (error) => {
        if (error) {
          this.#pending.delete(requestId);
          reject(error);
        }
      });
    });
  }

  async health(): Promise<HealthReport> {
    return resultValue(okResult(await this.request({ case: "runtimeHealth", value: {} })), "health") as HealthReport;
  }

  async getCapabilities(): Promise<Capabilities> {
    return resultValue(
      okResult(await this.request({ case: "runtimeGetCapabilities", value: {} })),
      "capabilities",
    ) as Capabilities;
  }

  async getMetrics(): Promise<RuntimeMetrics> {
    return resultValue(okResult(await this.request({ case: "getRuntimeMetrics", value: {} })), "metrics") as RuntimeMetrics;
  }

  async listProcesses(executionId?: string): Promise<ProcessList> {
    const value = executionId === undefined ? {} : { executionId };
    return resultValue(okResult(await this.request({ case: "listProcesses", value })), "processList") as ProcessList;
  }

  async exec(options: ExecOptions): Promise<ExecAccepted> {
    const result = okResult(
      await this.request({
        case: "exec",
        value: {
          executable: options.executable,
          args: options.args ?? [],
          executionId: options.executionId,
          sessionId: options.sessionId,
          cwd: options.cwd,
          stdin: options.stdin ?? false,
          // 64-bit wire fields are bigint in protobuf-es.
          timeoutMillis:
            options.timeoutMillis === undefined ? undefined : BigInt(options.timeoutMillis),
          background: options.background ?? false,
        },
      }),
    );
    return resultValue(result, "execAccepted") as ExecAccepted;
  }

  async writeStdin(processId: string, data: Uint8Array): Promise<void> {
    okResult(await this.request({ case: "writeStdin", value: { processId, data } }));
  }

  async signalProcess(processId: string, signal: number): Promise<void> {
    okResult(await this.request({ case: "signalProcess", value: { processId, signal } }));
  }

  async shutdown(graceMillis?: number): Promise<void> {
    const value = graceMillis === undefined ? {} : { graceMillis: BigInt(graceMillis) };
    okResult(await this.request({ case: "runtimeGracefulShutdown", value }));
  }

  /** Async iterator over telemetry events (typed `EventEnvelope`; `payload` is a discriminated union). */
  events(): AsyncIterableIterator<EventEnvelope> {
    const self = this;
    return {
      [Symbol.asyncIterator]() {
        return this;
      },
      next(): Promise<IteratorResult<EventEnvelope>> {
        const queued = self.#eventQueue.shift();
        if (queued !== undefined) {
          return Promise.resolve({ value: queued, done: false });
        }
        if (self.#closed) {
          return Promise.resolve({ value: undefined, done: true });
        }
        return new Promise((resolve) => self.#eventWaiters.push(resolve));
      },
      return(): Promise<IteratorResult<EventEnvelope>> {
        return Promise.resolve({ value: undefined, done: true });
      },
    };
  }

  close(): void {
    this.#stream.end();
  }

  #onData(chunk: Buffer): void {
    let messages: ServerMessage[];
    try {
      messages = this.#decoder.push(chunk);
    } catch (error) {
      this.#stream.destroy(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    for (const message of messages) {
      if (message.message.case === "response") {
        const response = message.message.value;
        const pending = this.#pending.get(response.requestId);
        if (pending) {
          this.#pending.delete(response.requestId);
          pending.resolve(response);
        }
      } else if (message.message.case === "event") {
        this.#emitEvent(message.message.value);
      }
    }
  }

  #emitEvent(event: EventEnvelope): void {
    const waiter = this.#eventWaiters.shift();
    if (waiter) {
      waiter({ value: event, done: false });
    } else {
      this.#eventQueue.push(event);
    }
  }

  #onClose(): void {
    this.#closed = true;
    for (const waiter of this.#eventWaiters.splice(0)) {
      waiter({ value: undefined, done: true });
    }
    for (const pending of this.#pending.values()) {
      pending.reject(new Error("connection closed"));
    }
    this.#pending.clear();
  }
}

function connectOnce(socketPath: string): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const onError = (error: Error) => {
      socket.destroy();
      reject(error);
    };
    socket.once("error", onError);
    socket.once("connect", () => {
      socket.removeListener("error", onError);
      resolve(socket);
    });
  });
}
