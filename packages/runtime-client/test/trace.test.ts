// Trace context on requests: the client reads its hook as a request starts and sends the context in
// `ControlRequest.trace` (field 4); a bad one leaves the request untraced, never failed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Duplex } from "node:stream";
import { Buffer } from "node:buffer";

import { fromBinary } from "@bufbuild/protobuf";
import { Effect } from "effect";

import { SECRET_ENV_CAPABILITY, SealantClient } from "@sealant/runtime-client";
import { effectTraceContext } from "@sealant/runtime-client/effect";
import {
  ClientMessageSchema,
  ControlRequestSchema,
  ServerMessageSchema,
  create,
  encodeFrame,
  encodeServer,
  type ControlRequest,
} from "@sealant/runtime-protocol";

const PARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const OTHER = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00";

/** A daemon stand-in that records each request and answers it, capabilities with `supports`. */
class FakeDaemon extends Duplex {
  readonly requests: ControlRequest[] = [];
  readonly supports: string[];
  constructor(supports: string[] = []) {
    super();
    this.supports = supports;
  }
  _read(): void {}
  _write(chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    const msg = fromBinary(ClientMessageSchema, chunk.subarray(4, 4 + chunk.readUInt32BE(0)));
    if (msg.message.case === "request") {
      const request = msg.message.value;
      this.requests.push(request);
      const result =
        request.command?.command.case === "runtimeGetCapabilities"
          ? { case: "capabilities" as const, value: { supports: this.supports } }
          : request.command?.command.case === "exec"
            ? { case: "execAccepted" as const, value: { processId: "proc_1" } }
            : { case: "health" as const, value: {} };
      const response = create(ServerMessageSchema, {
        message: {
          case: "response",
          value: {
            schemaVersion: request.schemaVersion,
            requestId: request.requestId,
            outcome: { outcome: { case: "ok", value: { result } } },
          },
        },
      });
      queueMicrotask(() => this.push(encodeFrame(encodeServer(response))));
    }
    cb();
  }
}

test("trace is field 4 on ControlRequest", () => {
  const field = ControlRequestSchema.fields.find((f) => f.name === "trace");
  assert.equal(field?.number, 4);
});

test("a client without a hook sends no trace", async () => {
  const daemon = new FakeDaemon();
  const client = SealantClient.fromStream(daemon);
  try {
    await client.health();
    assert.equal(daemon.requests[0]?.trace, undefined);
  } finally {
    client.close();
  }
});

test("the hook's context goes on each request, and an explicit one wins", async () => {
  const daemon = new FakeDaemon();
  let current: string | { traceparent: string; tracestate?: string } | undefined = {
    traceparent: PARENT,
    tracestate: "congo=t61rcWkgMzE",
  };
  const client = SealantClient.fromStream(daemon, { traceContext: () => current });
  try {
    await client.health();
    current = undefined;
    await client.health();
    await client.request({ case: "runtimeHealth", value: {} }, { trace: OTHER });
    const [first, second, third] = daemon.requests;
    assert.equal(first?.trace?.traceparent, PARENT);
    assert.equal(first?.trace?.tracestate, "congo=t61rcWkgMzE");
    assert.equal(second?.trace, undefined);
    assert.equal(third?.trace?.traceparent, OTHER);
    assert.equal(third?.trace?.tracestate, "");
  } finally {
    client.close();
  }
});

test("a malformed or throwing hook leaves the request untraced, not failed", async () => {
  const sent: ControlRequest[] = [];
  const hooks = [
    () => "not-a-traceparent",
    () => "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
    () => PARENT.toUpperCase(),
    () => ({ traceparent: PARENT, tracestate: "x".repeat(513) }),
    () => {
      throw new Error("tracer is gone");
    },
  ];
  for (const hook of hooks) {
    const daemon = new FakeDaemon();
    const client = SealantClient.fromStream(daemon, { traceContext: hook });
    try {
      await client.health();
      sent.push(...daemon.requests);
    } finally {
      client.close();
    }
  }
  assert.deepEqual(
    sent.map((r) => r.trace?.traceparent),
    [undefined, undefined, undefined, PARENT, undefined],
  );
  // An oversized tracestate is dropped and the traceparent kept.
  assert.equal(sent[3]?.trace?.tracestate, "");
});

test("a secret-env exec carries the context current when it was called", async () => {
  const daemon = new FakeDaemon([SECRET_ENV_CAPABILITY]);
  let current = PARENT;
  const client = SealantClient.fromStream(daemon, { traceContext: () => current });
  try {
    const sent = client.exec({ executable: "/bin/true", secretEnv: [{ key: "K", value: "v" }] });
    // The exec waits on the capability round trip; the caller's context has moved on by then.
    current = OTHER;
    await sent;
    const exec = daemon.requests.find((r) => r.command?.command.case === "exec");
    assert.equal(exec?.trace?.traceparent, PARENT);
  } finally {
    client.close();
  }
});

test("effectTraceContext gives the calling fiber's span", async () => {
  const daemon = new FakeDaemon();
  const client = SealantClient.fromStream(daemon, { traceContext: effectTraceContext });
  try {
    const span = await Effect.runPromise(
      Effect.gen(function* () {
        const span = yield* Effect.currentSpan;
        yield* Effect.tryPromise(() => client.health());
        return span;
      }).pipe(Effect.withSpan("test.health")),
    );
    assert.equal(daemon.requests[0]?.trace?.traceparent, `00-${span.traceId}-${span.spanId}-01`);

    // Outside any span, and outside any fiber, there is nothing to send.
    await Effect.runPromise(Effect.tryPromise(() => client.health()));
    await client.health();
    assert.equal(daemon.requests[1]?.trace, undefined);
    assert.equal(daemon.requests[2]?.trace, undefined);
  } finally {
    client.close();
  }
});
