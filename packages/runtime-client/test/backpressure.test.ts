import { test } from "node:test";
import assert from "node:assert/strict";
import { Duplex } from "node:stream";
import { Buffer } from "node:buffer";
import { setImmediate as tick } from "node:timers/promises";

import { fromBinary } from "@bufbuild/protobuf";

import { SealantClient, openForwardConnection, type Channel } from "@sealant/runtime-client";
import {
  create,
  encodeFrame,
  encodeServer,
  ClientMessageSchema,
  ServerMessageSchema,
  type OpenForwardArgs,
} from "@sealant/runtime-protocol";

const CHUNK = 16 * 1024;
const CHANNEL = "chan_fwd";
const TCP = { host: "127.0.0.1", port: 3000, protocol: "tcp" } as const;

function dataFrame(payload: Uint8Array, channelId = CHANNEL): Buffer {
  const message = create(ServerMessageSchema, {
    message: {
      case: "stream",
      value: { channelId, seq: 0n, payload: { case: "data", value: payload } },
    },
  });
  return encodeFrame(encodeServer(message));
}

function endFrame(): Buffer {
  const message = create(ServerMessageSchema, {
    message: {
      case: "stream",
      value: { channelId: CHANNEL, seq: 0n, payload: { case: "end", value: {} } },
    },
  });
  return encodeFrame(encodeServer(message));
}

function eventFrame(bytes: number): Buffer {
  const message = create(ServerMessageSchema, {
    message: {
      case: "event",
      value: { schemaVersion: 1, eventId: "evt_1", runtimeId: "x".repeat(bytes) },
    },
  });
  return encodeFrame(encodeServer(message));
}

function chunkBytes(index: number): Uint8Array {
  return new Uint8Array(CHUNK).fill(index % 256);
}

function assertBytes(actual: Uint8Array | undefined, expected: Uint8Array, message: string): void {
  assert.ok(actual !== undefined && Buffer.from(actual).equals(Buffer.from(expected)), message);
}

class Daemon extends Duplex {
  args: OpenForwardArgs | undefined;
  requests = 0;
  preamble = 0;
  next = 0;
  delivered = 0;
  readonly total: number;
  readonly early: Buffer[];
  readonly frameBytes = dataFrame(chunkBytes(0)).length;
  constructor(options: { total?: number; early?: Buffer[]; writableHighWaterMark?: number } = {}) {
    super({ writableHighWaterMark: options.writableHighWaterMark });
    this.total = options.total ?? 0;
    this.early = options.early ?? [];
    this.on("data", (chunk: Buffer) => {
      this.delivered += chunk.length;
    });
  }
  _read(): void {
    if (this.args === undefined || this.next >= this.total) return;
    this.push(dataFrame(chunkBytes(this.next++)));
  }
  _write(chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    const message = fromBinary(ClientMessageSchema, chunk.subarray(4, 4 + chunk.readUInt32BE(0)));
    if (message.message.case === "request") {
      const request = message.message.value;
      this.requests += 1;
      if (request.command?.command.case === "openForward") this.args = request.command.command.value;
      const response = create(ServerMessageSchema, {
        message: {
          case: "response",
          value: {
            schemaVersion: request.schemaVersion,
            requestId: request.requestId,
            outcome: {
              outcome: {
                case: "ok",
                value: {
                  result: {
                    case: "forwardOpened",
                    value: { channelId: CHANNEL, boundSessionId: this.args?.ownerSessionId },
                  },
                },
              },
            },
          },
        },
      });
      queueMicrotask(() => {
        for (const frame of [...this.early, encodeFrame(encodeServer(response))]) {
          this.preamble += frame.length;
          this.push(frame);
        }
        this._read();
      });
    }
    cb();
  }
}

async function readChunks(channel: Channel, count: number, consumed: { chunks: number }) {
  const iterator = channel[Symbol.asyncIterator]();
  for (let i = 0; i < count; i++) {
    const { value, done } = await iterator.next();
    assert.equal(done, false);
    assertBytes(value, chunkBytes(consumed.chunks), `chunk ${consumed.chunks} whole and in order`);
    consumed.chunks += 1;
  }
}

async function ticks(count: number): Promise<void> {
  for (let i = 0; i < count; i++) await tick();
}

test("a forward connection keeps the bytes it holds under the mark plus one chunk", { timeout: 5000 }, async () => {
  const mark = 256 * 1024;
  const total = 512;
  const daemon = new Daemon({ total });
  const { channel } = await openForwardConnection(daemon, { ...TCP, highWaterMarkBytes: mark });
  const consumed = { chunks: 0 };
  const held = () =>
    ((daemon.delivered - daemon.preamble) / daemon.frameBytes - consumed.chunks) * CHUNK;

  await ticks(50);
  assert.ok(held() <= mark + CHUNK, `held ${held()} bytes with nothing read`);
  assert.ok(daemon.next < total, "the producer was held back");

  while (consumed.chunks < total) {
    await readChunks(channel, 1, consumed);
    assert.ok(held() <= mark + CHUNK, `held ${held()} bytes after ${consumed.chunks} reads`);
    if (consumed.chunks % 64 === 0) await tick();
  }
  assert.equal(daemon.next, total, "every chunk was produced");
  channel.destroy();
});

test("the multiplexed client still takes everything the producer sends", { timeout: 5000 }, async () => {
  const total = 512;
  const daemon = new Daemon({ total });
  const client = SealantClient.fromStream(daemon);
  await client.openForward(TCP);
  await ticks(2000);
  assert.equal(daemon.next, total);
  client.close();
});

test("a queued payload holds only its own bytes, not the transport chunk it came in", { timeout: 5000 }, async () => {
  const daemon = new Daemon();
  const { channel } = await openForwardConnection(daemon, {
    ...TCP,
    highWaterMarkBytes: 256 * 1024,
  });
  for (let i = 0; i < 128; i++) {
    daemon.push(Buffer.concat([dataFrame(new Uint8Array([i])), eventFrame(64 * 1024)]));
  }
  await ticks(20);
  const iterator = channel[Symbol.asyncIterator]();
  let retained = 0;
  for (let i = 0; i < 128; i++) {
    const { value } = await iterator.next();
    assert.equal(value?.[0], i);
    retained += value?.buffer.byteLength ?? 0;
  }
  assert.equal(retained, 128, "128 one-byte payloads hold 128 bytes");
  channel.destroy();
});

test("destroying a paused forward closes its connection without a request", { timeout: 5000 }, async () => {
  const daemon = new Daemon({ total: 64 });
  const { channel } = await openForwardConnection(daemon, { ...TCP, highWaterMarkBytes: CHUNK });
  await ticks(20);
  assert.ok(daemon.isPaused(), "the connection is paused");

  channel.destroy();
  assert.deepEqual(await channel.closed, { kind: "local" });
  assert.ok(daemon.destroyed, "the connection is closed");
  assert.equal(daemon.requests, 1, "only the open was ever asked");
});

test("an End on a paused forward resumes and ends the connection, keeping queued bytes", { timeout: 5000 }, async () => {
  const daemon = new Daemon({ total: 4 });
  const { channel } = await openForwardConnection(daemon, { ...TCP, highWaterMarkBytes: CHUNK });
  await ticks(20);
  assert.ok(daemon.isPaused());
  daemon.push(endFrame());
  const consumed = { chunks: 0 };
  await readChunks(channel, 1, consumed);
  await ticks(20);
  await readChunks(channel, 3, consumed);
  assert.equal((await channel.closed).kind, "remote");
  assert.ok(!daemon.isPaused(), "reading resumed for good");
  assert.ok(daemon.writableEnded, "the connection was ended");
});

test("more than the mark before the forward opens rejects the open", { timeout: 5000 }, async () => {
  const early = [dataFrame(chunkBytes(0)), dataFrame(chunkBytes(1)), dataFrame(chunkBytes(2))];
  const daemon = new Daemon({ early });
  await assert.rejects(
    openForwardConnection(daemon, { ...TCP, highWaterMarkBytes: 2 * CHUNK }),
    /more than 32768 bytes arrived before sealantd confirmed the forward/,
  );
  assert.ok(daemon.destroyed);
});

test("a frame larger than the mark before the forward opens is still delivered", { timeout: 5000 }, async () => {
  const daemon = new Daemon({ early: [dataFrame(chunkBytes(9))] });
  const { channel } = await openForwardConnection(daemon, { ...TCP, highWaterMarkBytes: 1024 });
  const first = await channel[Symbol.asyncIterator]().next();
  assertBytes(first.value, chunkBytes(9), "the early frame arrives whole");
  channel.destroy();
});

test("the mark is a positive integer, checked before the connection is touched", async () => {
  for (const mark of [Number.NaN, Number.POSITIVE_INFINITY, -1, 0, 1.5]) {
    const daemon = new Daemon();
    await assert.rejects(
      openForwardConnection(daemon, { ...TCP, highWaterMarkBytes: mark }),
      RangeError,
      String(mark),
    );
    assert.equal(daemon.listenerCount("data"), 1, "only the test's own listener");
    assert.equal(daemon.args, undefined, "nothing was sent");
  }
});

test("a forward connection asks for no events and ignores any that come", { timeout: 5000 }, async () => {
  const daemon = new Daemon({ early: [eventFrame(64)] });
  const { channel } = await openForwardConnection(daemon, { ...TCP, highWaterMarkBytes: CHUNK });
  assert.equal(daemon.args?.dedicated, true);
  daemon.push(eventFrame(64));
  daemon.push(dataFrame(chunkBytes(3)));
  assertBytes((await channel[Symbol.asyncIterator]().next()).value, chunkBytes(3), "data still flows");
  channel.destroy();

  const shared = new Daemon();
  await SealantClient.fromStream(shared).openForward(TCP);
  assert.equal(shared.args?.dedicated, undefined, "a multiplexed forward keeps its events");
});

class SlowSink extends Duplex {
  readonly callbacks: Array<(error?: Error) => void> = [];
  constructor(options: { autoDestroy?: boolean } = {}) {
    super({ writableHighWaterMark: 1024, autoDestroy: options.autoDestroy });
  }
  _read(): void {}
  _write(_chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    this.callbacks.push((error) => cb(error));
  }
  flush(error?: Error): void {
    for (const cb of this.callbacks.splice(0)) cb(error);
  }
}

test("write() reports a full connection and drained() resolves when it empties", { timeout: 5000 }, async () => {
  const conn = new SlowSink();
  const client = SealantClient.fromStream(conn);
  const channel = client.openChannel("up");

  assert.equal(channel.write(new Uint8Array(16)), true, "room left under the mark");
  conn.flush();
  await channel.drained();
  assert.equal(channel.write(new Uint8Array(4096)), false, "above the connection's mark");

  let drained = false;
  const wait = channel.drained().then(() => {
    drained = true;
  });
  await tick();
  assert.equal(drained, false, "still full");
  while (conn.callbacks.length > 0) {
    conn.flush();
    await tick();
  }
  await wait;
  assert.equal(drained, true);
  client.close();
});

test("drained() rejects when the connection closes first", { timeout: 5000 }, async () => {
  const conn = new SlowSink();
  const client = SealantClient.fromStream(conn);
  const channel = client.openChannel("up");
  channel.write(new Uint8Array(4096));
  const wait = channel.drained();
  conn.destroy();
  await assert.rejects(wait, /connection closed/);
});

test("drained() rejects after a write fails, with no close to follow", { timeout: 5000 }, async () => {
  const conn = new SlowSink({ autoDestroy: false });
  const client = SealantClient.fromStream(conn);
  const channel = client.openChannel("up");
  channel.write(new Uint8Array(4096));
  const wait = channel.drained();
  conn.flush(new Error("broken pipe"));
  await assert.rejects(wait, /broken pipe/);
  await assert.rejects(channel.drained(), /broken pipe/, "and so does every later wait");
});

test("drained() rejects once the client is closed, though no drain follows end()", { timeout: 5000 }, async () => {
  const conn = new SlowSink();
  const client = SealantClient.fromStream(conn);
  const channel = client.openChannel("up");
  channel.write(new Uint8Array(4096));
  const wait = channel.drained();
  client.close();
  await assert.rejects(wait, /client is closed/);
});

test("openForward sends its object's fields, leaving tcp off the wire", { timeout: 5000 }, async () => {
  const conn = new Daemon();
  const client = SealantClient.fromStream(conn);

  const tcp = await client.openForward(TCP);
  assert.equal(tcp.channel.channelId, CHANNEL);
  assert.equal(conn.args?.host, "127.0.0.1");
  assert.equal(conn.args?.port, 3000);
  assert.equal(conn.args?.protocol, undefined);
  assert.equal(conn.args?.executionId, undefined);

  await client.openForward({ host: "docker", port: 53, protocol: "udp", executionId: "exe_1" });
  assert.equal(conn.args?.protocol, "udp");
  assert.equal(conn.args?.executionId, "exe_1");
  assert.equal(conn.args?.ownerSessionId, undefined);

  const bound = await client.openForward({ ...TCP, ownerSessionId: "sess_1" });
  assert.equal(conn.args?.ownerSessionId, "sess_1");
  assert.equal(bound.result.boundSessionId, "sess_1");
  client.close();
});

test("a forward connection can be bound to a session", { timeout: 5000 }, async () => {
  const daemon = new Daemon();
  const { result, channel } = await openForwardConnection(daemon, {
    ...TCP,
    ownerSessionId: "sess_1",
    highWaterMarkBytes: CHUNK,
  });
  assert.equal(daemon.args?.ownerSessionId, "sess_1");
  assert.equal(result.boundSessionId, "sess_1");
  channel.destroy();
});
