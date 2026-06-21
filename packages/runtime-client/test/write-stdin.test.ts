// Unit tests for SDK input routing: `writeStdin` must be able to target a non-PTY process (the
// original signature) OR an interactive PTY session by `sessionId` (what the gateway needs to deliver
// SSH keystrokes). No daemon: a controllable in-memory Duplex captures the outbound ClientMessage and
// auto-acks each request so the promise resolves.

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
  type ControlRequest,
  type WriteStdinArgs,
} from "@sealant/runtime-protocol";

/**
 * A Duplex that captures what the client writes and, for every `ClientMessage::request`, injects a
 * minimal OK response so the awaited request resolves. Each captured request is recorded.
 */
class AckConn extends Duplex {
  readonly requests: ControlRequest[] = [];
  _read(): void {}
  _write(chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    const len = chunk.readUInt32BE(0);
    const msg = fromBinary(ClientMessageSchema, chunk.subarray(4, 4 + len));
    if (msg.message.case === "request") {
      const request = msg.message.value;
      this.requests.push(request);
      // Auto-ack: an OK outcome carrying an empty "accepted" result.
      const response = create(ServerMessageSchema, {
        message: {
          case: "response",
          value: {
            schemaVersion: request.schemaVersion,
            requestId: request.requestId,
            outcome: { outcome: { case: "ok", value: { result: { case: "accepted", value: {} } } } },
          },
        },
      });
      // Deliver asynchronously, after _write returns, like a real socket round-trip.
      queueMicrotask(() => this.push(encodeFrame(encodeServer(response))));
    }
    cb();
  }
}

/** Pull the `writeStdin` args out of the last captured request. */
function lastWriteStdin(conn: AckConn): WriteStdinArgs {
  const request = conn.requests[conn.requests.length - 1];
  assert.equal(request.command?.command.case, "writeStdin");
  return (request.command!.command as { value: WriteStdinArgs }).value;
}

test("writeStdin(string, data) targets processId (backward compatible)", async () => {
  const conn = new AckConn();
  const client = SealantClient.fromStream(conn);

  await client.writeStdin("proc-1", new Uint8Array([0x61]));

  const args = lastWriteStdin(conn);
  assert.equal(args.processId, "proc-1");
  assert.equal(args.sessionId, undefined); // unset optional string stays undefined
  assert.deepEqual([...args.data], [0x61]);

  client.close();
});

test("writeStdin({ processId }, data) targets processId explicitly", async () => {
  const conn = new AckConn();
  const client = SealantClient.fromStream(conn);

  await client.writeStdin({ processId: "proc-2" }, new Uint8Array([0x62]));

  const args = lastWriteStdin(conn);
  assert.equal(args.processId, "proc-2");
  assert.equal(args.sessionId, undefined);

  client.close();
});

test("writeStdin({ sessionId }, data) targets a PTY session", async () => {
  const conn = new AckConn();
  const client = SealantClient.fromStream(conn);

  await client.writeStdin({ sessionId: "sess-9" }, new Uint8Array([0x6c, 0x73, 0x0a])); // "ls\n"

  const args = lastWriteStdin(conn);
  assert.equal(args.sessionId, "sess-9");
  assert.equal(args.processId, undefined); // not set: daemon routes by sessionId
  assert.deepEqual([...args.data], [0x6c, 0x73, 0x0a]);

  client.close();
});

test("writeSessionInput(sessionId, data) is the session-targeted convenience", async () => {
  const conn = new AckConn();
  const client = SealantClient.fromStream(conn);

  await client.writeSessionInput("sess-7", new Uint8Array([0x71])); // "q"

  const args = lastWriteStdin(conn);
  assert.equal(args.sessionId, "sess-7");
  assert.equal(args.processId, undefined);
  assert.deepEqual([...args.data], [0x71]);

  client.close();
});
