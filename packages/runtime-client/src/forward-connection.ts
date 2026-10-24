// A forward on a connection of its own, so pausing the connection holds back only that forward.

import type { Buffer } from "node:buffer";
import type { Duplex } from "node:stream";

import {
  FrameDecoder,
  type ControlResponse,
  type ForwardOpened,
  type ServerMessage,
  type StreamEnd,
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
  type OpenForwardOptions,
} from "./wire.js";

export interface ForwardConnectionOptions extends OpenForwardOptions {
  /**
   * Pause reading the connection while the forward holds more than this many unread bytes, and
   * resume once the consumer has read it back under. sealantd then stops reading the forward's
   * target, so a slow consumer holds back a fast producer. The bytes held can pass the mark by
   * what one transport chunk carries.
   */
  highWaterMarkBytes: number;
}

/**
 * Open one forward on `stream`, a connection to sealantd that carries nothing else, and own the
 * connection from then on. sealantd stops sending events on it. The connection closes when the
 * forward's channel closes: `channel.destroy()` (or leaving its iterator) drops it at once, and
 * the target's `End` ends it once queued writes have flushed. sealantd reaps the forward when the
 * connection closes, so there is no `closeForward`.
 *
 * Rejects with the daemon's {@link SealantError} when the forward does not open, and with an
 * error when the connection closes first or more than the mark arrives before the daemon
 * confirms the forward (the connection cannot pause before then).
 */
export async function openForwardConnection(
  stream: Duplex,
  options: ForwardConnectionOptions,
): Promise<{ result: ForwardOpened; channel: Channel }> {
  const mark = options.highWaterMarkBytes;
  if (!Number.isSafeInteger(mark) || mark <= 0) {
    throw new RangeError(`highWaterMarkBytes must be a positive integer, got ${mark}`);
  }
  return new ForwardConnection(stream, mark).open(options);
}

type Opened = { result: ForwardOpened; channel: Channel };

type State =
  | {
      kind: "opening";
      resolve: (opened: Opened) => void;
      reject: (error: Error) => void;
      early: StreamFrame[];
      earlyBytes: number;
    }
  | { kind: "open"; channel: Channel }
  | { kind: "closed" };

const REQUEST_ID = "req_forward";

class ForwardConnection implements ChannelTransport {
  readonly #stream: Duplex;
  readonly #mark: number;
  readonly #decoder = new FrameDecoder();
  readonly #drain: Drain;
  #state: State = { kind: "closed" };
  #queued = 0;
  #paused = false;

  constructor(stream: Duplex, mark: number) {
    this.#stream = stream;
    this.#mark = mark;
    this.#drain = new Drain(stream);
  }

  open(options: OpenForwardOptions): Promise<Opened> {
    return new Promise((resolve, reject) => {
      const stream = this.#stream;
      if (stream.destroyed || !stream.writable) {
        reject(new Error("connection closed"));
        return;
      }
      this.#state = { kind: "opening", resolve, reject, early: [], earlyBytes: 0 };
      stream.on("data", (chunk: Buffer) => this.#onData(chunk));
      stream.on("end", () => this.#teardown());
      stream.on("close", () => this.#teardown());
      stream.on("error", (error: Error) => this.#teardown(error));
      stream.write(requestFrame(REQUEST_ID, openForwardCommand(options, true)));
    });
  }

  #onData(chunk: Buffer): void {
    let messages: ServerMessage[];
    try {
      messages = this.#decoder.push(chunk);
    } catch (error) {
      this.#teardown(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    for (const message of messages) {
      if (this.#state.kind === "closed") return;
      if (message.message.case === "response") this.#onResponse(message.message.value);
      else if (message.message.case === "stream") this.#onStream(message.message.value);
    }
  }

  #onResponse(response: ControlResponse): void {
    const state = this.#state;
    if (state.kind !== "opening" || response.requestId !== REQUEST_ID) return;
    let result: ForwardOpened;
    try {
      result = resultValue(okResult(response), "forwardOpened") as ForwardOpened;
    } catch (error) {
      this.#teardown(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    const channel = new Channel(result.channelId, this);
    this.#state = { kind: "open", channel };
    for (const frame of state.early) this.#deliver(channel, frame);
    state.resolve({ result, channel });
  }

  #onStream(frame: StreamFrame): void {
    // A queued payload is a view into the transport chunk it arrived in, which can be far
    // larger (other frames, discarded events); a copy holds only its own bytes.
    if (frame.payload.case === "data") frame.payload.value = new Uint8Array(frame.payload.value);
    const state = this.#state;
    if (state.kind === "open") {
      if (frame.channelId === state.channel.channelId) this.#deliver(state.channel, frame);
      return;
    }
    if (state.kind !== "opening") return;
    const bytes = frame.payload.case === "data" ? frame.payload.value.byteLength : 0;
    if (state.early.length > 0 && state.earlyBytes + bytes > this.#mark) {
      this.#teardown(
        new Error(`more than ${this.#mark} bytes arrived before sealantd confirmed the forward`),
      );
      return;
    }
    state.early.push(frame);
    state.earlyBytes += bytes;
  }

  #deliver(channel: Channel, frame: StreamFrame): void {
    if (frame.channelId !== channel.channelId) return;
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

  #teardown(error?: Error): void {
    const state = this.#state;
    this.#state = { kind: "closed" };
    const cause = error ?? new Error("connection closed");
    this.#drain.fail(cause);
    if (state.kind === "opening") state.reject(cause);
    if (state.kind === "open") state.channel.fail(cause);
    this.#stream.destroy();
  }

  #applyMark(): void {
    const state = this.#state;
    const holding = state.kind === "open" && !state.channel.isClosed;
    if (!this.#paused && holding && this.#queued > this.#mark) {
      this.#paused = true;
      this.#stream.pause();
    } else if (this.#paused && (!holding || this.#queued <= this.#mark)) {
      this.#paused = false;
      this.#stream.resume();
    }
  }

  sendData(channelId: string, data: Uint8Array): boolean {
    return this.#stream.write(streamFrame(channelId, { case: "data", value: data }));
  }

  drained(): Promise<void> {
    return this.#drain.wait();
  }

  inboundQueued(delta: number): void {
    this.#queued += delta;
    this.#applyMark();
  }

  sendWindowUpdate(channelId: string, credits: bigint): void {
    this.#stream.write(streamFrame(channelId, { case: "windowUpdate", value: { credits } }));
  }

  sendEnd(channelId: string, end?: StreamEnd): void {
    this.#stream.write(streamFrame(channelId, { case: "end", value: end ?? {} }));
  }

  release(): void {
    const state = this.#state;
    if (state.kind !== "open") return;
    this.#state = { kind: "closed" };
    this.#drain.fail(new Error("forward closed"));
    if (state.channel.closeCause?.kind === "remote") {
      this.#applyMark();
      this.#stream.end();
    } else {
      this.#stream.destroy();
    }
  }
}
