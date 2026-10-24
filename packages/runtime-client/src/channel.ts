// @sealant/runtime-client — channel multiplexing.
//
// A `Channel` is one logical byte conduit inside the single length-prefixed control connection
// (ADR-0012). The daemon addresses frames by `channelId`; the client demuxes inbound
// `ServerMessage::Stream` frames into the matching `Channel` and the `Channel` muxes outbound bytes
// back out as `ClientMessage::Stream` frames. This is the substrate the gateway builds SSH channels
// (session attach, direct-tcpip forwards, SFTP subsystem) on top of.

import type { StreamEnd, StreamWindowUpdate } from "@sealant/runtime-protocol";

/** How a `Channel` writes a frame back to the daemon over the shared connection. The client wires
 * this to its framed-socket writer; the channel never touches the socket directly. */
export interface ChannelTransport {
  /** Send a `StreamFrame::Data` for this channel. Returns the connection's `write()` result: `false`
   * once its outbound buffer is above its high-water mark. */
  sendData(channelId: string, data: Uint8Array): boolean;
  /** Resolves when the connection's outbound buffer has drained (at once if it is not full). */
  drained(): Promise<void>;
  /** The bytes queued in a channel's inbound buffer changed by `delta`. */
  inboundQueued(delta: number): void;
  /** Send a `StreamFrame::WindowUpdate` (flow-control credits) for this channel. */
  sendWindowUpdate(channelId: string, credits: bigint): void;
  /** Send a `StreamFrame::End` for this channel (half-close from the client side). */
  sendEnd(channelId: string, end?: StreamEnd): void;
  /** Detach this channel from the client's demux table once it is fully closed. */
  release(channelId: string): void;
}

/** Why a channel fully closed: a daemon `StreamEnd`, a local `destroy()` teardown, or the
 * connection dying. Note that a half-close via `end()` does NOT resolve `closed` — only the *full*
 * close does, and for a well-behaved peer that arrives as `remote` (the daemon's `StreamEnd`). */
export type ChannelClose =
  | { kind: "remote"; end: StreamEnd }
  | { kind: "local" }
  | { kind: "error"; error: Error };

/**
 * One demultiplexed byte channel. It is an async-iterable of inbound `Uint8Array` chunks (the bytes
 * the daemon wrote on this `channelId`) and exposes `write`/`windowUpdate`/`end` for outbound bytes.
 *
 * Inbound chunks queue until consumed, and a forward connection counts them against its high-water
 * mark; `closed` resolves with the close cause.
 */
export class Channel implements AsyncIterable<Uint8Array> {
  /** The daemon-assigned channel id this conduit is bound to. */
  readonly channelId: string;

  #transport: ChannelTransport;
  #inbound: Uint8Array[] = [];
  #waiters: Array<(result: IteratorResult<Uint8Array>) => void> = [];
  #windowWaiters: Array<(credits: bigint) => void> = [];
  /** Outbound half-closed: we have sent our `StreamEnd`; `write`/`windowUpdate` are now rejected.
   * Inbound delivery is unaffected — this is the SSH-style half-close. */
  #outboundClosed = false;
  /** Fully closed: both halves are done. Inbound iterator completes and `closed` resolves. */
  #closed = false;
  #close?: ChannelClose;
  #resolveClosed!: (cause: ChannelClose) => void;

  /** Resolves with the cause when the channel is *fully* closed (remote End, local `destroy()`, or
   * error). A half-close via `end()` does NOT resolve this — inbound keeps flowing until the remote
   * `StreamEnd`, at which point it resolves as `remote`. */
  readonly closed: Promise<ChannelClose>;

  constructor(channelId: string, transport: ChannelTransport) {
    this.channelId = channelId;
    this.#transport = transport;
    this.closed = new Promise((resolve) => {
      this.#resolveClosed = resolve;
    });
  }

  /** True once the channel has been *fully* closed (both halves done). */
  get isClosed(): boolean {
    return this.#closed;
  }

  /** True once the outbound half has been closed via `end()` (or a full close). Inbound may still
   * be flowing while this is true. */
  get isOutboundClosed(): boolean {
    return this.#outboundClosed;
  }

  /** The close cause, if the channel is closed; otherwise `undefined`. */
  get closeCause(): ChannelClose | undefined {
    return this.#close;
  }

  // --- inbound (demux target; called by the client) -------------------------------------------

  /** Route an inbound `StreamFrame::Data` payload into this channel's byte stream. */
  pushData(data: Uint8Array): void {
    if (this.#closed) return;
    const waiter = this.#waiters.shift();
    if (waiter) {
      waiter({ value: data, done: false });
    } else {
      this.#inbound.push(data);
      this.#transport.inboundQueued(data.byteLength);
    }
  }

  /** Route an inbound `StreamFrame::WindowUpdate`: release outbound writers waiting on credits. */
  pushWindowUpdate(update: StreamWindowUpdate): void {
    if (this.#closed) return;
    for (const w of this.#windowWaiters.splice(0)) w(update.credits);
  }

  /** Route an inbound `StreamFrame::End`: drain queued bytes, then close the iterator. */
  pushEnd(end: StreamEnd): void {
    this.#finish({ kind: "remote", end });
  }

  /** The connection died under us; fail the channel. */
  fail(error: Error): void {
    this.#finish({ kind: "error", error });
  }

  // --- outbound (mux source; called by the consumer) ------------------------------------------

  /** Write bytes to the daemon as a `StreamFrame::Data` on this channel. Throws once the outbound
   * half has been closed (via `end()`/`destroy()`) or the channel is fully closed.
   *
   * Returns `false` when the connection's outbound buffer is full, as Node's `write()` does: the
   * bytes are queued, and a writer that respects backpressure awaits {@link Channel.drained}. */
  write(data: Uint8Array): boolean {
    if (this.#outboundClosed) throw new Error(`channel ${this.channelId} outbound is closed`);
    return this.#transport.sendData(this.channelId, data);
  }

  /** Resolves once the connection's outbound buffer has drained; at once if it is not full.
   * Rejects once the connection can take no more writes: a write error, a close, or `end()`. */
  drained(): Promise<void> {
    return this.#transport.drained();
  }

  /** Grant the daemon `credits` more bytes of send window (`StreamFrame::WindowUpdate`). Throws once
   * the outbound half is closed. (Credits flow with outbound frames; once we have half-closed we no
   * longer issue them.) */
  windowUpdate(credits: bigint): void {
    if (this.#outboundClosed) throw new Error(`channel ${this.channelId} outbound is closed`);
    this.#transport.sendWindowUpdate(this.channelId, credits);
  }

  /** Await the next inbound `WindowUpdate`'s credit count (for outbound flow control). */
  awaitWindow(): Promise<bigint> {
    return new Promise((resolve) => this.#windowWaiters.push(resolve));
  }

  /**
   * Half-close the outbound direction: send a `StreamFrame::End` to the daemon (our EOF) and reject
   * further `write`/`windowUpdate`. Crucially this does NOT tear down inbound — the channel keeps
   * delivering the daemon's output and stays open until the remote `StreamEnd` arrives (which then
   * resolves `closed` as `remote`). This is the SSH semantics `ssh host cmd` relies on: stdin can
   * hit EOF immediately while stdout/stderr and the exit status are still in flight.
   *
   * Idempotent; a no-op if the outbound half is already closed or the channel is fully closed.
   */
  end(end?: StreamEnd): void {
    if (this.#outboundClosed || this.#closed) return;
    this.#outboundClosed = true;
    this.#transport.sendEnd(this.channelId, end);
  }

  /**
   * Full local teardown: half-close the outbound direction if it is still open, then close inbound
   * too and resolve `closed` as `local`. Use this for a real abort/teardown where you do not intend
   * to keep reading the daemon's remaining output. For normal completion prefer `end()` and let the
   * remote `StreamEnd` close the channel.
   *
   * Inbound bytes still queued are dropped, also on a channel the remote end already closed, so
   * they no longer count against a forward connection's high-water mark.
   */
  destroy(end?: StreamEnd): void {
    if (!this.#closed) {
      if (!this.#outboundClosed) {
        this.#outboundClosed = true;
        this.#transport.sendEnd(this.channelId, end);
      }
      this.#finish({ kind: "local" });
    }
    const dropped = this.#inbound.splice(0);
    const bytes = dropped.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    if (bytes > 0) this.#transport.inboundQueued(-bytes);
  }

  // --- async iteration --------------------------------------------------------------------------

  [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    return {
      next: (): Promise<IteratorResult<Uint8Array>> => {
        const queued = this.#inbound.shift();
        if (queued !== undefined) {
          this.#transport.inboundQueued(-queued.byteLength);
          return Promise.resolve({ value: queued, done: false });
        }
        if (this.#closed) return Promise.resolve({ value: undefined, done: true });
        return new Promise((resolve) => this.#waiters.push(resolve));
      },
      // The consumer stopped iterating (e.g. `break`): they will read no more inbound bytes, so this
      // is a real teardown, not a half-close. Destroy fully.
      return: (): Promise<IteratorResult<Uint8Array>> => {
        this.destroy();
        return Promise.resolve({ value: undefined, done: true });
      },
    };
  }

  /** Internal: mark closed once, drain waiters, resolve `closed`, and detach from the demux table. */
  #finish(cause: ChannelClose): void {
    if (this.#closed) return;
    this.#closed = true;
    // A full close implies the outbound half is closed too (block any late writes).
    this.#outboundClosed = true;
    this.#close = cause;
    for (const waiter of this.#waiters.splice(0)) {
      waiter({ value: undefined, done: true });
    }
    for (const w of this.#windowWaiters.splice(0)) w(0n);
    this.#transport.release(this.channelId);
    this.#resolveClosed(cause);
  }
}
