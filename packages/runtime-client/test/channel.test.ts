// Unit tests for channel multiplexing / demux in SealantClient. No daemon: a controllable in-memory
// Duplex stands in for the connection, so we can inject synthetic `ServerMessage::Stream` frames and
// assert they route to the right `Channel` by channel_id, and that a `StreamEnd` closes the channel.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Duplex } from "node:stream";
import { Buffer } from "node:buffer";

import { fromBinary } from "@bufbuild/protobuf";

import { SealantClient } from "@sealant/runtime-client";
import {
  create,
  encodeServer,
  encodeFrame,
  ServerMessageSchema,
  ClientMessageSchema,
  type StreamFrame,
} from "@sealant/runtime-protocol";

/**
 * A Duplex the test fully controls: `inject()` pushes daemon→client bytes (the client reads these via
 * its "data" handler); everything the client writes is captured in `written` for assertions.
 */
class MockConn extends Duplex {
  readonly written: Buffer[] = [];
  _read(): void {}
  _write(chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    this.written.push(Buffer.from(chunk));
    cb();
  }
  /** Push a fully-framed ServerMessage to the client. */
  inject(message: Parameters<typeof encodeServer>[0]): void {
    this.push(encodeFrame(encodeServer(message)));
  }
}

/** Build a `ServerMessage::Stream` for `channelId` carrying a data payload. */
function dataFrame(channelId: string, bytes: number[]) {
  return create(ServerMessageSchema, {
    message: {
      case: "stream",
      value: { channelId, seq: 0n, payload: { case: "data", value: new Uint8Array(bytes) } },
    },
  });
}

/** Build a `ServerMessage::Stream` for `channelId` carrying an End payload. */
function endFrame(channelId: string, exitCode?: number) {
  return create(ServerMessageSchema, {
    message: {
      case: "stream",
      value: { channelId, seq: 1n, payload: { case: "end", value: { exitCode } } },
    },
  });
}

/** Build a `ServerMessage::Stream` for `channelId` carrying a WindowUpdate payload. */
function windowFrame(channelId: string, credits: bigint) {
  return create(ServerMessageSchema, {
    message: {
      case: "stream",
      value: { channelId, seq: 2n, payload: { case: "windowUpdate", value: { credits } } },
    },
  });
}

/** Read at most `n` chunks from a channel's async iterator (stops early if it closes). */
async function take(channel: AsyncIterable<Uint8Array>, n: number): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of channel) {
    chunks.push(chunk);
    if (chunks.length >= n) break;
  }
  return chunks;
}

test("demux routes frames for channel A vs B to the correct channel", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);

  const a = client.openChannel("chan-A");
  const b = client.openChannel("chan-B");

  conn.inject(dataFrame("chan-A", [0x61, 0x61])); // "aa"
  conn.inject(dataFrame("chan-B", [0x62])); // "b"
  conn.inject(dataFrame("chan-A", [0x61])); // "a"
  conn.inject(dataFrame("chan-B", [0x62, 0x62])); // "bb"

  const aChunks = await take(a, 2);
  const bChunks = await take(b, 2);

  assert.deepEqual(aChunks.map((c) => [...c]), [[0x61, 0x61], [0x61]]);
  assert.deepEqual(bChunks.map((c) => [...c]), [[0x62], [0x62, 0x62]]);

  client.close();
});

test("a StreamEnd frame closes only its own channel", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);

  const a = client.openChannel("chan-A");
  const b = client.openChannel("chan-B");

  conn.inject(dataFrame("chan-A", [0x01]));
  conn.inject(endFrame("chan-A", 0));
  conn.inject(dataFrame("chan-B", [0x02]));

  // Draining A yields the one data chunk then completes because of the End.
  const aChunks: Uint8Array[] = [];
  for await (const chunk of a) aChunks.push(chunk);
  assert.deepEqual(aChunks.map((c) => [...c]), [[0x01]]);
  assert.equal(a.isClosed, true);

  const cause = await a.closed;
  assert.equal(cause.kind, "remote");
  if (cause.kind === "remote") assert.equal(cause.end.exitCode, 0);

  // B is untouched and still delivers its data.
  assert.equal(b.isClosed, false);
  const bChunks = await take(b, 1);
  assert.deepEqual(bChunks.map((c) => [...c]), [[0x02]]);

  client.close();
});

test("frames for an unknown/closed channel are dropped (no throw)", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  conn.inject(endFrame("chan-A"));
  await a.closed;

  // Late frames for the now-released channel must not crash the connection.
  conn.inject(dataFrame("chan-A", [0x99]));
  conn.inject(dataFrame("never-opened", [0x99]));

  // The client is still usable: open a fresh channel and route to it.
  const c = client.openChannel("chan-C");
  conn.inject(dataFrame("chan-C", [0x43]));
  const chunks = await take(c, 1);
  assert.deepEqual(chunks.map((x) => [...x]), [[0x43]]);

  client.close();
});

test("channel.write muxes an outbound ClientMessage::Stream data frame", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  a.write(new Uint8Array([0x68, 0x69])); // "hi"

  // Decode what the client wrote back over the wire.
  const buf = Buffer.concat(conn.written);
  const len = buf.readUInt32BE(0);
  const msg = fromBinary(ClientMessageSchema, buf.subarray(4, 4 + len));
  assert.equal(msg.message.case, "stream");
  const frame = (msg.message as { value: StreamFrame }).value;
  assert.equal(frame.channelId, "chan-A");
  assert.equal(frame.payload.case, "data");
  if (frame.payload.case === "data") assert.deepEqual([...frame.payload.value], [0x68, 0x69]);

  client.close();
});

test("an inbound WindowUpdate releases an awaitWindow waiter", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  const credits = a.awaitWindow();
  conn.inject(windowFrame("chan-A", 4096n));
  assert.equal(await credits, 4096n);

  client.close();
});

test("connection close fails open channels", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  client.close();
  conn.destroy();

  const cause = await a.closed;
  assert.equal(cause.kind, "error");
  assert.equal(a.isClosed, true);
});

// --- half-close (SSH `ssh host cmd` semantics) -------------------------------------------------

/** Decode the most recent ClientMessage::Stream frame the client wrote, if any. */
function lastClientStream(conn: MockConn): StreamFrame | undefined {
  for (let i = conn.written.length - 1; i >= 0; i--) {
    const buf = conn.written[i];
    const len = buf.readUInt32BE(0);
    const msg = fromBinary(ClientMessageSchema, buf.subarray(4, 4 + len));
    if (msg.message.case === "stream") return (msg.message as { value: StreamFrame }).value;
  }
  return undefined;
}

test("end() is a half-close: outbound End sent, inbound keeps flowing until remote StreamEnd", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  // Half-close outbound. This must NOT close the channel or stop inbound delivery.
  a.end({ exitCode: undefined });
  assert.equal(a.isOutboundClosed, true, "outbound half should be closed after end()");
  assert.equal(a.isClosed, false, "channel must stay open after a half-close");

  // The client wrote a StreamFrame::End for this channel (our EOF).
  const sent = lastClientStream(conn);
  assert.equal(sent?.channelId, "chan-A");
  assert.equal(sent?.payload.case, "end");

  // Outbound writes are now rejected, but inbound still delivers the daemon's remaining output.
  assert.throws(() => a.write(new Uint8Array([0x01])), /outbound is closed/);

  // Pull inbound through the raw iterator (not a for-await `break`, which would trigger return() and
  // tear the channel down locally). The daemon's output arrives AFTER our stdin EOF.
  const it = a[Symbol.asyncIterator]();
  conn.inject(dataFrame("chan-A", [0x6f, 0x6b])); // "ok"
  const first = await it.next();
  assert.equal(first.done, false);
  assert.deepEqual([...(first.value as Uint8Array)], [0x6f, 0x6b]);

  // The remote StreamEnd is what finally closes the channel — and as `remote`, not `local`.
  conn.inject(endFrame("chan-A", 0));
  const next = await it.next();
  assert.equal(next.done, true);
  const cause = await a.closed;
  assert.equal(cause.kind, "remote");
  if (cause.kind === "remote") assert.equal(cause.end.exitCode, 0);
  assert.equal(a.isClosed, true);

  client.close();
});

test("end() then remote drain delivers all buffered inbound before completing", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  // Daemon output races in before we half-close; then more arrives; then End.
  conn.inject(dataFrame("chan-A", [0x01]));
  a.end();
  conn.inject(dataFrame("chan-A", [0x02]));
  conn.inject(endFrame("chan-A", 7));

  const drained: Uint8Array[] = [];
  for await (const chunk of a) drained.push(chunk);
  assert.deepEqual(drained.map((c) => [...c]), [[0x01], [0x02]]);

  const cause = await a.closed;
  assert.equal(cause.kind, "remote");
  if (cause.kind === "remote") assert.equal(cause.end.exitCode, 7);

  client.close();
});

test("end() is idempotent and sends End only once", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  a.end();
  a.end();
  a.end();

  const endFrames = conn.written.filter((buf) => {
    const len = buf.readUInt32BE(0);
    const msg = fromBinary(ClientMessageSchema, buf.subarray(4, 4 + len));
    return (
      msg.message.case === "stream" &&
      (msg.message as { value: StreamFrame }).value.payload.case === "end"
    );
  });
  assert.equal(endFrames.length, 1, "End must be sent exactly once");

  client.close();
});

test("destroy() is a full local teardown: inbound completes, closed resolves local", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  // Queue some inbound that destroy() should discard (consumer is tearing down, not draining).
  conn.inject(dataFrame("chan-A", [0xff]));
  a.destroy();

  assert.equal(a.isClosed, true);
  assert.equal(a.isOutboundClosed, true);
  // Outbound End was sent as part of the teardown.
  assert.equal(lastClientStream(conn)?.payload.case, "end");

  const cause = await a.closed;
  assert.equal(cause.kind, "local");

  // Late inbound after a full close is dropped without throwing.
  conn.inject(dataFrame("chan-A", [0x00]));

  client.close();
});

test("destroy() after end() does not send a second End and closes as local", async () => {
  const conn = new MockConn();
  const client = SealantClient.fromStream(conn);
  const a = client.openChannel("chan-A");

  a.end(); // half-close (sends End)
  a.destroy(); // full teardown (must NOT send another End)

  const endFrames = conn.written.filter((buf) => {
    const len = buf.readUInt32BE(0);
    const msg = fromBinary(ClientMessageSchema, buf.subarray(4, 4 + len));
    return (
      msg.message.case === "stream" &&
      (msg.message as { value: StreamFrame }).value.payload.case === "end"
    );
  });
  assert.equal(endFrames.length, 1, "destroy() after end() must not re-send End");

  const cause = await a.closed;
  assert.equal(cause.kind, "local");

  client.close();
});
