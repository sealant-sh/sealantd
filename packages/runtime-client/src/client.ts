// @sealant/runtime-client
//
// Ergonomic TypeScript client for sealantd. Uses IPC (a Unix domain socket) as the language
// boundary — never in-process FFI (plan §19). Runs on plain Node (no build step) via native type
// stripping; relative imports keep the Phase 1 slice runnable without a workspace install.

import net from "node:net";
import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

import {
  encodeFrame,
  FrameDecoder,
  SCHEMA_VERSION,
} from "../../runtime-protocol/src/index.ts";
import type {
  Capabilities,
  Command,
  ControlError,
  ControlResponse,
  EventEnvelope,
  ExecAccepted,
  ExecArgs,
  HealthReport,
  ResponseOutcome,
  ServerMessage,
} from "../../runtime-protocol/src/index.ts";

/** Error raised when the daemon returns a typed control error. */
export class SealantError extends Error {
  readonly code: string;
  readonly detail: unknown;
  constructor(error: ControlError) {
    super(error.message);
    this.name = "SealantError";
    this.code = error.code;
    this.detail = error.detail;
  }
}

type Pending = {
  resolve: (response: ControlResponse) => void;
  reject: (error: Error) => void;
};

function unwrap(outcome: ResponseOutcome): CommandResultOrUndefined {
  if (outcome.status === "error") {
    throw new SealantError(outcome.error);
  }
  return outcome.result;
}
type CommandResultOrUndefined = Exclude<
  Extract<ResponseOutcome, { status: "ok" }>["result"],
  never
>;

/** A connected control client for one sealantd instance. */
export class SealantClient {
  #socket: net.Socket;
  #decoder: FrameDecoder = new FrameDecoder();
  #pending: Map<string, Pending> = new Map();
  #counter = 0;
  #closed = false;
  #eventQueue: EventEnvelope[] = [];
  #eventWaiters: Array<(result: IteratorResult<EventEnvelope>) => void> = [];

  constructor(socket: net.Socket) {
    this.#socket = socket;
    this.#socket.on("data", (chunk: Buffer) => this.#onData(chunk));
    this.#socket.on("close", () => this.#onClose());
    this.#socket.on("error", () => {
      /* surfaced to callers via pending rejection on close */
    });
  }

  /** Connect to an existing daemon socket, retrying until it is accepting. */
  static async connect(
    socketPath: string,
    options: { retries?: number; delayMs?: number } = {},
  ): Promise<SealantClient> {
    const retries = options.retries ?? 100;
    const delayMs = options.delayMs ?? 20;
    let lastError: unknown;
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const socket = await connectOnce(socketPath);
        return new SealantClient(socket);
      } catch (error) {
        lastError = error;
        await delay(delayMs);
      }
    }
    throw lastError instanceof Error ? lastError : new Error("connection failed");
  }

  /** Spawn the daemon bound to a fresh socket and connect to it. */
  static async spawn(options: {
    binPath: string;
    socketPath: string;
    workspace?: string;
    sandboxId?: string;
    executionId?: string;
    logLevel?: string;
  }): Promise<{ client: SealantClient; child: ChildProcess }> {
    const args = ["--socket", options.socketPath, "--log-level", options.logLevel ?? "off"];
    if (options.workspace) args.push("--workspace", options.workspace);
    if (options.sandboxId) args.push("--sandbox-id", options.sandboxId);
    if (options.executionId) args.push("--execution-id", options.executionId);
    const child = spawn(options.binPath, args, { stdio: ["ignore", "ignore", "inherit"] });
    try {
      const client = await SealantClient.connect(options.socketPath);
      return { client, child };
    } catch (error) {
      child.kill("SIGKILL");
      throw error;
    }
  }

  /** Send a command and await its single response. */
  request(command: Command): Promise<ControlResponse> {
    if (this.#closed) {
      return Promise.reject(new Error("client is closed"));
    }
    const requestId = `req_client_${++this.#counter}`;
    const message = { kind: "request", schemaVersion: SCHEMA_VERSION, requestId, command };
    return new Promise((resolve, reject) => {
      this.#pending.set(requestId, { resolve, reject });
      this.#socket.write(encodeFrame(message), (error) => {
        if (error) {
          this.#pending.delete(requestId);
          reject(error);
        }
      });
    });
  }

  async health(): Promise<HealthReport> {
    const result = unwrap((await this.request({ cmd: "runtime.health" })).outcome);
    return result as HealthReport;
  }

  async getCapabilities(): Promise<Capabilities> {
    const result = unwrap((await this.request({ cmd: "runtime.getCapabilities" })).outcome);
    return result as Capabilities;
  }

  async exec(args: ExecArgs): Promise<ExecAccepted> {
    const result = unwrap((await this.request({ cmd: "exec", args })).outcome);
    return result as ExecAccepted;
  }

  async writeStdin(processId: string, data: Buffer): Promise<void> {
    unwrap(
      (
        await this.request({
          cmd: "writeStdin",
          args: { processId, data: data.toString("base64") },
        })
      ).outcome,
    );
  }

  async closeStdin(processId: string): Promise<void> {
    unwrap((await this.request({ cmd: "closeStdin", args: { processId } })).outcome);
  }

  async shutdown(graceMillis?: number): Promise<void> {
    unwrap(
      (
        await this.request({
          cmd: "runtime.gracefulShutdown",
          args: graceMillis === undefined ? undefined : { graceMillis },
        })
      ).outcome,
    );
  }

  /** Async iterator over telemetry events as they arrive. */
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
          return Promise.resolve({ value: undefined as never, done: true });
        }
        return new Promise((resolve) => self.#eventWaiters.push(resolve));
      },
      return(): Promise<IteratorResult<EventEnvelope>> {
        return Promise.resolve({ value: undefined as never, done: true });
      },
    };
  }

  close(): void {
    this.#socket.end();
  }

  #onData(chunk: Buffer): void {
    let messages: unknown[];
    try {
      messages = this.#decoder.push(chunk);
    } catch (error) {
      this.#socket.destroy(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    for (const raw of messages) {
      const message = raw as ServerMessage;
      if (message.kind === "response") {
        const pending = this.#pending.get(message.requestId);
        if (pending) {
          this.#pending.delete(message.requestId);
          pending.resolve(message);
        }
      } else if (message.kind === "event") {
        this.#emitEvent(message);
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
      waiter({ value: undefined as never, done: true });
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
