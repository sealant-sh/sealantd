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

import {
  CommandSchema,
  create,
  FrameDecoder,
  AttachMode,
  SessionMode,
  type Capabilities,
  type ControlResponse,
  type EventEnvelope,
  type ExecAccepted,
  type ForwardOpened,
  type HealthReport,
  type ProcessAttached,
  type ProcessList,
  type RuntimeMetrics,
  type ServerMessage,
  type SessionList,
  type SessionOpened,
  type SessionOutput,
  type SftpOpened,
  type Signal,
  type StreamAttached,
  type StreamFrame,
} from "@sealant/runtime-protocol";

import { Channel, type ChannelTransport } from "./channel.js";
import { Drain } from "./drain.js";
import {
  okResult,
  openForwardCommand,
  requestFrame,
  resultValue,
  streamFrame,
  type CommandInit,
  type OpenForwardOptions,
  type StreamPayload,
} from "./wire.js";

export { Channel } from "./channel.js";
export type { ChannelTransport, ChannelClose } from "./channel.js";
export { SealantError, type OpenForwardOptions } from "./wire.js";

type Pending = {
  resolve: (response: ControlResponse) => void;
  reject: (error: Error) => void;
};

/** Options for {@link SealantClient.openSession} (a subset of the wire `OpenSessionArgs`). */
export interface OpenSessionOptions {
  /** Shell/command to run; defaults to the daemon's configured default shell. */
  shell?: string;
  /** Arguments to the shell/command. */
  args?: string[];
  /** Working directory (defaults to the workspace root). */
  cwd?: string;
  /** Environment overlay entries. */
  env?: Array<{ key: string; value: string }>;
  /** Variables for the leader only, as {@link ExecOptions.secretEnv}. */
  secretEnv?: Array<{ key: string; value: string }>;
  /** Initial terminal columns. */
  cols: number;
  /** Initial terminal rows. */
  rows: number;
  /** `TERM` to advertise (defaults daemon-side). */
  term?: string;
  /** Execution to associate the session with. */
  executionId?: string;
  /**
   * How the leader is wired. `PTY` (default) allocates a pseudoterminal — interactive shells and
   * TUIs. `PIPE` gives the leader plain stdio pipes and no tty — the shape for processes that
   * speak a byte protocol over stdin/stdout (JSON-RPC / NDJSON servers): stdout is the journaled,
   * attachable output, stderr is recorded as telemetry only, `writeSessionInput` feeds stdin, and
   * `resizePty` is rejected. `cols`/`rows` are ignored in pipe mode.
   */
  mode?: SessionMode;
}

/** Options for {@link SealantClient.attachSession}. */
export interface AttachSessionOptions {
  /** Consumption mode (interactive by default). */
  mode?: AttachMode;
  /**
   * Replay the durable output journal from this sequence (0 = full retained scrollback) before
   * live frames; data-frame `seq` values are journal sequences. Omit for a live tail only.
   */
  fromSequence?: number | bigint;
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
  /**
   * Variables for this process only, each value masked in everything the daemon records of it.
   * Sent only to a daemon that names {@link SECRET_ENV_CAPABILITY} on this connection (an older
   * one would ignore the field): otherwise the call throws and nothing is sent. {@link
   * SealantClient.request} applies the same check to any `exec` or `openSession` it sends.
   */
  secretEnv?: Array<{ key: string; value: string }>;
}

/** The capability a daemon names when it honours `secretEnv` on exec and both session shapes. */
export const SECRET_ENV_CAPABILITY = "process.secret-env.v1";

/** A connected, typed control client for one sealantd instance. */
export class SealantClient {
  #stream: Duplex;
  #decoder: FrameDecoder = new FrameDecoder();
  #pending: Map<string, Pending> = new Map();
  #counter = 0;
  #closed = false;
  #eventQueue: EventEnvelope[] = [];
  #eventWaiters: Array<(result: IteratorResult<EventEnvelope>) => void> = [];
  /** Demux table: channel_id → open `Channel`. Inbound `ServerMessage::Stream` frames route here. */
  #channels: Map<string, Channel> = new Map();
  /**
   * Frames that arrived for a channel the caller has not registered yet. The daemon may write
   * channel frames BEFORE the response that carries the channel id reaches the caller (journal
   * replay on `attachSession({fromSequence})` does this by design; a fast exec-attach can too), so
   * they are buffered here and flushed by {@link SealantClient.openChannel}. Bounded per channel;
   * cleared on connection close.
   */
  #pendingFrames: Map<string, StreamFrame[]> = new Map();
  #transport: ChannelTransport;
  #drain: Drain;

  constructor(stream: Duplex) {
    this.#stream = stream;
    this.#drain = new Drain(stream);
    // The transport every Channel uses to mux outbound frames back over this one connection.
    this.#transport = {
      sendData: (channelId, data) => this.#sendStream(channelId, { case: "data", value: data }),
      sendWindowUpdate: (channelId, credits) => {
        this.#sendStream(channelId, { case: "windowUpdate", value: { credits } });
      },
      sendEnd: (channelId, end) => {
        this.#sendStream(channelId, { case: "end", value: end ?? {} });
      },
      drained: () => this.#drain.wait(),
      inboundQueued: () => {},
      release: (channelId) => this.#channels.delete(channelId),
    };
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
    workspaceId?: string;
    executionId?: string;
    spoolDir?: string;
    watchFilesystem?: boolean;
    networkProxy?: boolean;
    logLevel?: string;
  }): Promise<{ client: SealantClient; child: ChildProcess }> {
    const args = ["--socket", options.socketPath, "--log-level", options.logLevel ?? "off"];
    if (options.workspace) args.push("--workspace", options.workspace);
    if (options.workspaceId) args.push("--workspace-id", options.workspaceId);
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
    // Encoded now, so the command sent is the one asked for, whatever its options become.
    const frame = requestFrame(requestId, command);
    const sent = create(CommandSchema, { command }).command;
    const secret =
      (sent.case === "exec" || sent.case === "openSession") && sent.value.secretEnv.length > 0;
    if (!secret) return this.#send(requestId, frame);
    // A daemon without the capability would drop `secretEnv` and start the process without it.
    return this.getCapabilities().then(({ supports }) => {
      if (!supports.includes(SECRET_ENV_CAPABILITY)) {
        throw new Error(`the daemon does not support ${SECRET_ENV_CAPABILITY}: secretEnv not sent`);
      }
      if (this.#closed) throw new Error("client is closed");
      return this.#send(requestId, frame);
    });
  }

  #send(requestId: string, frame: Uint8Array): Promise<ControlResponse> {
    return new Promise((resolve, reject) => {
      this.#pending.set(requestId, { resolve, reject });
      this.#stream.write(frame, (error) => {
        if (error) {
          this.#pending.delete(requestId);
          reject(error);
        }
      });
    });
  }

  /** Mux one outbound `ClientMessage::Stream` frame onto the shared connection. */
  #sendStream(channelId: string, payload: StreamPayload): boolean {
    if (this.#closed) throw new Error("client is closed");
    return this.#stream.write(streamFrame(channelId, payload));
  }

  /**
   * Register a {@link Channel} for `channelId` so inbound `ServerMessage::Stream` frames demux into
   * it and writes mux back out. Low-level: the high-level openers ({@link SealantClient.attachSession},
   * {@link SealantClient.openForward}, {@link SealantClient.openSftp}, {@link SealantClient.execAttached})
   * call this with the daemon-allocated id from their result. A multiplexing consumer (the gateway)
   * can also call it directly when it already holds a channel id.
   */
  openChannel(channelId: string): Channel {
    const existing = this.#channels.get(channelId);
    if (existing) return existing;
    const channel = new Channel(channelId, this.#transport);
    this.#channels.set(channelId, channel);
    // Flush any frames that raced ahead of the response carrying this channel id.
    const pending = this.#pendingFrames.get(channelId);
    if (pending) {
      this.#pendingFrames.delete(channelId);
      for (const frame of pending) this.#deliverFrame(channel, frame);
    }
    return channel;
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
          secretEnv: options.secretEnv ?? [],
        },
      }),
    );
    return resultValue(result, "execAccepted") as ExecAccepted;
  }

  /**
   * Write input bytes to a process's stdin or an interactive PTY session's input.
   *
   * The daemon's `WriteStdinArgs` carries an exclusive choice of `processId` (non-PTY stdin) OR
   * `sessionId` (PTY input); it routes by whichever is set (see runtime dispatch). The gateway needs
   * the `sessionId` path to deliver SSH PTY keystrokes to a live session.
   *
   * Backward compatible: a bare string `target` is treated as a `processId` (the original signature).
   * Pass `{ sessionId }` to target a session, or `{ processId }` to be explicit.
   */
  async writeStdin(
    target: string | { processId: string } | { sessionId: string },
    data: Uint8Array,
  ): Promise<void> {
    const value =
      typeof target === "string"
        ? { processId: target, data }
        : "sessionId" in target
          ? { sessionId: target.sessionId, data }
          : { processId: target.processId, data };
    okResult(await this.request({ case: "writeStdin", value }));
  }

  /**
   * Convenience for the gateway's interactive path: deliver `data` to a PTY session's input by
   * `sessionId`. Equivalent to `writeStdin({ sessionId }, data)`.
   */
  async writeSessionInput(sessionId: string, data: Uint8Array): Promise<void> {
    okResult(await this.request({ case: "writeStdin", value: { sessionId, data } }));
  }

  async signalProcess(processId: string, signal: number): Promise<void> {
    okResult(await this.request({ case: "signalProcess", value: { processId, signal } }));
  }

  /**
   * Point a bindable mount's path at a subdirectory of its root (ADR-0014): `/workspace/repo` at
   * `wt-<id>`, or `/workspace/repos/<name>` at a sibling repository's worktree. An empty subpath
   * unbinds. The daemon records the bind and re-applies it when it restarts in the same container.
   */
  async bindMount(mountPath: string, subpath: string): Promise<void> {
    okResult(await this.request({ case: "bindMount", value: { mountPath, subpath } }));
  }

  async shutdown(graceMillis?: number): Promise<void> {
    const value = graceMillis === undefined ? {} : { graceMillis: BigInt(graceMillis) };
    okResult(await this.request({ case: "runtimeGracefulShutdown", value }));
  }

  // ===================== channel multiplexing =====================
  //
  // Each opener sends its command, reads the daemon-allocated channel_id out of the typed result, and
  // returns an open {@link Channel} already wired into the demux table — an async-iterable of that
  // channel's inbound bytes plus `write`/`windowUpdate`/`end` for outbound bytes.

  // ===================== interactive sessions =====================

  /** Open an interactive PTY session (arbitrary command or the default shell). */
  async openSession(options: OpenSessionOptions): Promise<SessionOpened> {
    return resultValue(
      okResult(
        await this.request({
          case: "openSession",
          value: {
            shell: options.shell,
            args: options.args ?? [],
            cwd: options.cwd,
            env: options.env ?? [],
            cols: options.cols,
            rows: options.rows,
            term: options.term,
            executionId: options.executionId,
            mode: options.mode ?? SessionMode.PTY,
            secretEnv: options.secretEnv ?? [],
          },
        }),
      ),
      "sessionOpened",
    ) as SessionOpened;
  }

  /**
   * Close a session: hang up a running session's terminal (SIGHUP), or drop an exited session's
   * retained tombstone (and its journal).
   */
  async closeSession(sessionId: string): Promise<void> {
    okResult(await this.request({ case: "closeSession", value: { sessionId } }));
  }

  /** Resize a running session's PTY. */
  async resizePty(sessionId: string, cols: number, rows: number): Promise<void> {
    okResult(await this.request({ case: "resizePty", value: { sessionId, cols, rows } }));
  }

  /** List sessions: running first, then retained exited tombstones (state + exit code). */
  async listSessions(): Promise<SessionList> {
    return resultValue(
      okResult(await this.request({ case: "listSessions", value: {} })),
      "sessionList",
    ) as SessionList;
  }

  /** Deliver a signal (e.g. SIGINT/SIGTERM) to a running session's process group. */
  async signalSession(sessionId: string, signal: Signal): Promise<void> {
    okResult(await this.request({ case: "signalSession", value: { sessionId, signal } }));
  }

  /**
   * One-shot batch read of a session's durable output journal from `fromSequence` (clamped to the
   * first retained record). Works for running and exited sessions; the result carries the cursors
   * (`nextSequence`, `firstAvailableSequence`) and lifecycle state.
   */
  async readSessionOutput(
    sessionId: string,
    fromSequence: number | bigint,
    maxBytes?: number | bigint,
  ): Promise<SessionOutput> {
    return resultValue(
      okResult(
        await this.request({
          case: "readSessionOutput",
          value: {
            sessionId,
            fromSequence: BigInt(fromSequence),
            maxBytes: maxBytes === undefined ? undefined : BigInt(maxBytes),
          },
        }),
      ),
      "sessionOutput",
    ) as SessionOutput;
  }

  /**
   * Attach to an existing PTY session as a multiplexed channel (interactive by default). Pass
   * `{ fromSequence }` to replay the durable journal (scrollback) before live output — data-frame
   * `seq` values are then journal sequences, resumable across disconnects.
   */
  async attachSession(
    sessionId: string,
    modeOrOptions: AttachMode | AttachSessionOptions = AttachMode.INTERACTIVE,
  ): Promise<{ result: StreamAttached; channel: Channel }> {
    const options: AttachSessionOptions =
      typeof modeOrOptions === "object" ? modeOrOptions : { mode: modeOrOptions };
    const result = resultValue(
      okResult(
        await this.request({
          case: "attachSession",
          value: {
            sessionId,
            mode: options.mode ?? AttachMode.INTERACTIVE,
            fromSequence:
              options.fromSequence === undefined ? undefined : BigInt(options.fromSequence),
          },
        }),
      ),
      "streamAttached",
    ) as StreamAttached;
    return { result, channel: this.openChannel(result.channelId) };
  }

  /** Detach a previously attached session channel and tear down its local {@link Channel}. */
  async detachSession(channelId: string): Promise<void> {
    okResult(await this.request({ case: "detachSession", value: { channelId } }));
    // Explicit teardown command: fully close the local channel, don't leave inbound half-open.
    this.#channels.get(channelId)?.destroy();
  }

  /** Open a direct forward to `host:port` as a multiplexed channel on this connection. For a
   * forward that holds back its producer, use {@link openForwardConnection} instead. */
  async openForward(
    options: OpenForwardOptions,
  ): Promise<{ result: ForwardOpened; channel: Channel }> {
    const result = resultValue(
      okResult(await this.request(openForwardCommand(options))),
      "forwardOpened",
    ) as ForwardOpened;
    return { result, channel: this.openChannel(result.channelId) };
  }

  /** Close a forward channel and tear down its local {@link Channel}. */
  async closeForward(channelId: string): Promise<void> {
    okResult(await this.request({ case: "closeForward", value: { channelId } }));
    // Explicit teardown command: fully close the local channel, don't leave inbound half-open.
    this.#channels.get(channelId)?.destroy();
  }

  /**
   * Open an SFTP subsystem channel as a multiplexed byte channel. With `user`, the sftp-server runs
   * as that user (a daemon whose capabilities name `sftp.user`; an older one ignores it).
   */
  async openSftp(options: { executionId?: string; cwd?: string; user?: string } = {}): Promise<{
    result: SftpOpened;
    channel: Channel;
  }> {
    const result = resultValue(
      okResult(
        await this.request({
          case: "openSftp",
          value: { executionId: options.executionId, cwd: options.cwd, user: options.user },
        }),
      ),
      "sftpOpened",
    ) as SftpOpened;
    return { result, channel: this.openChannel(result.channelId) };
  }

  /** Close an SFTP channel and tear down its local {@link Channel}. */
  async closeSftp(channelId: string): Promise<void> {
    okResult(await this.request({ case: "closeSftp", value: { channelId } }));
    // Explicit teardown command: fully close the local channel, don't leave inbound half-open.
    this.#channels.get(channelId)?.destroy();
  }

  /**
   * Exec with `attach=true`: the daemon allocates a byte channel bound to the process's stdio and
   * returns {@link ProcessAttached} with its `channelId`. Returns the typed result plus the open
   * {@link Channel} (stdout/stderr ride inbound frames; stdin rides outbound `write`).
   */
  async execAttached(
    options: ExecOptions,
  ): Promise<{ result: ProcessAttached; channel: Channel }> {
    const result = resultValue(
      okResult(
        await this.request({
          case: "exec",
          value: {
            executable: options.executable,
            args: options.args ?? [],
            executionId: options.executionId,
            sessionId: options.sessionId,
            cwd: options.cwd,
            stdin: options.stdin ?? false,
            timeoutMillis:
              options.timeoutMillis === undefined ? undefined : BigInt(options.timeoutMillis),
            background: options.background ?? false,
            attach: true,
            secretEnv: options.secretEnv ?? [],
          },
        }),
      ),
      "processAttached",
    ) as ProcessAttached;
    return { result, channel: this.openChannel(result.channelId) };
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
    this.#drain.fail(new Error("client is closed"));
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
      } else if (message.message.case === "stream") {
        this.#routeStream(message.message.value);
      }
    }
  }

  /** Frames buffered per not-yet-registered channel (a full session journal replay fits). */
  static readonly #MAX_PENDING_FRAMES = 65536;

  /** Demultiplex one inbound `ServerMessage::Stream` frame into its `Channel` by `channelId`. */
  #routeStream(frame: StreamFrame): void {
    const channel = this.#channels.get(frame.channelId);
    if (!channel) {
      // The channel id is not registered (yet): buffer bounded, flushed by openChannel. Frames
      // beyond the bound (or for channels that are never opened) are dropped on close.
      const pending = this.#pendingFrames.get(frame.channelId) ?? [];
      if (pending.length < SealantClient.#MAX_PENDING_FRAMES) {
        pending.push(frame);
        this.#pendingFrames.set(frame.channelId, pending);
      }
      return;
    }
    this.#deliverFrame(channel, frame);
  }

  #deliverFrame(channel: Channel, frame: StreamFrame): void {
    switch (frame.payload.case) {
      case "data":
        channel.pushData(frame.payload.value);
        break;
      case "windowUpdate":
        channel.pushWindowUpdate(frame.payload.value);
        break;
      case "end":
        channel.pushEnd(frame.payload.value);
        break;
      default:
        break;
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
    this.#drain.fail(new Error("connection closed"));
    for (const waiter of this.#eventWaiters.splice(0)) {
      waiter({ value: undefined, done: true });
    }
    for (const pending of this.#pending.values()) {
      pending.reject(new Error("connection closed"));
    }
    this.#pending.clear();
    // Fail every open channel so consumers iterating their bytes/`closed` promise unblock.
    for (const channel of [...this.#channels.values()]) {
      channel.fail(new Error("connection closed"));
    }
    this.#channels.clear();
    this.#pendingFrames.clear();
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
