// Acceptance over the Protobuf wire (ADR-0012) with the Buf-generated typed SDK: the client starts
// the daemon, execs, streams typed events (discriminated `payload.case`), gets the typed result, and
// shuts down — including binary-safe (NUL / non-UTF-8) output that rides native protobuf `bytes`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { rmSync } from "node:fs";
import { Buffer } from "node:buffer";
import net from "node:net";
import type { AddressInfo } from "node:net";
import type { ChildProcess } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

import { toJson } from "@bufbuild/protobuf";

import { SealantClient, SealantError, openForwardConnection } from "@sealant/runtime-client";
import {
  ControlErrorCode,
  EventEnvelopeSchema,
  RuntimeState,
  StreamKind,
  type ProcessStarted,
} from "@sealant/runtime-protocol";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const binPath = join(repoRoot, "target", "debug", "sealantd");

let socketCounter = 0;
function uniqueSocket(): string {
  socketCounter += 1;
  return join(tmpdir(), `sealantd-e2e-${process.pid}-${Date.now()}-${socketCounter}.sock`);
}

function waitExit(child: ChildProcess, ms = 5000): Promise<void> {
  return new Promise((resolveExit) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolveExit();
      return;
    }
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolveExit();
    }, ms);
    child.once("exit", () => {
      clearTimeout(timer);
      resolveExit();
    });
  });
}

test("starts daemon, execs, streams typed events, gets the result, and shuts down", async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({
    binPath,
    socketPath,
    workspace: tmpdir(),
    workspaceId: "ws-e2e",
    executionId: "run-e2e",
  });
  try {
    const health = await client.health();
    assert.equal(health.state, RuntimeState.HEALTHY);

    const caps = await client.getCapabilities();
    assert.equal(caps.features?.ioCapture, true);
    assert.equal(caps.features?.pty, true);
    // Mend's per-person layout runs only on a daemon that names what it needs.
    for (const name of ["exec.user", "dotfiles.user", "restore.owner_map"]) {
      assert.ok(caps.supports.includes(name), name);
    }

    const events = client.events();
    const accepted = await client.exec({ executable: "/bin/echo", args: ["hello"] });
    assert.ok(accepted.processId.startsWith("proc_"));
    assert.equal(typeof accepted.pid, "number");

    let stdout = Buffer.alloc(0);
    let exitCode: number | undefined;
    for await (const event of events) {
      if (event.payload.case === "ioChunk" && event.payload.value.stream === StreamKind.STDOUT) {
        const content = event.payload.value.content;
        if (content) stdout = Buffer.concat([stdout, Buffer.from(content)]);
      }
      if (event.payload.case === "processExited") {
        exitCode = event.payload.value.exitCode;
        break;
      }
    }
    assert.equal(stdout.toString("utf8"), "hello\n");
    assert.equal(exitCode, 0);

    await client.shutdown(200);
  } finally {
    client.close();
    await waitExit(child);
    rmSync(socketPath, { force: true });
  }
});

test("process.started describes the arguments and never carries their text", async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({ binPath, socketPath, workspace: tmpdir() });
  try {
    const marker = "withheld-marker-7f3a";
    const args = ["-c", "exit 0", "sh", marker, "", "  whitespace-led", "multi\nline é"];
    const events = client.events();
    await client.exec({ executable: "/bin/sh", args });

    let started: ProcessStarted | undefined;
    for await (const event of events) {
      const json = JSON.stringify(toJson(EventEnvelopeSchema, event));
      assert.ok(!json.includes(marker), `an event carried argument text: ${json}`);
      if (event.payload.case === "processStarted") started = event.payload.value;
      if (event.payload.case === "processExited") break;
    }
    assert.ok(started, "process.started arrived");
    assert.deepEqual(started.args, []);
    assert.equal(started.argCount, args.length);
    assert.deepEqual(
      started.argLengths,
      args.map((a) => Buffer.byteLength(a, "utf8")),
    );
    assert.deepEqual(started.argLengths, [2, 6, 2, 20, 0, 16, 13]);

    await client.shutdown(200);
  } finally {
    client.close();
    await waitExit(child);
    rmSync(socketPath, { force: true });
  }
});

test("captures binary-unsafe output exactly (NUL and high bytes, native protobuf bytes)", async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({ binPath, socketPath, workspace: tmpdir() });
  try {
    const events = client.events();
    await client.exec({ executable: "/bin/sh", args: ["-c", "printf 'x\\000y\\377z'"] });

    let stdout = Buffer.alloc(0);
    let exited = false;
    for await (const event of events) {
      if (event.payload.case === "ioChunk" && event.payload.value.stream === StreamKind.STDOUT) {
        const content = event.payload.value.content;
        if (content) stdout = Buffer.concat([stdout, Buffer.from(content)]);
      }
      if (event.payload.case === "processExited") {
        exited = true;
        break;
      }
    }
    assert.ok(exited);
    assert.deepEqual([...stdout], [0x78, 0x00, 0x79, 0xff, 0x7a]);

    await client.shutdown(200);
  } finally {
    client.close();
    await waitExit(child);
    rmSync(socketPath, { force: true });
  }
});

test("returns a typed control error for an unknown executable", async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({ binPath, socketPath, workspace: tmpdir() });
  try {
    await assert.rejects(
      () => client.exec({ executable: "/no/such/binary-xyz", args: [] }),
      (error: unknown) => {
        assert.ok(error instanceof SealantError);
        assert.equal(error.code, ControlErrorCode.PROCESS_START_FAILED);
        return true;
      },
    );
    await client.shutdown(200);
  } finally {
    client.close();
    await waitExit(child);
    rmSync(socketPath, { force: true });
  }
});

async function producer(): Promise<{
  port: number;
  written: () => number;
  closed: Promise<void>;
  server: net.Server;
}> {
  let written = 0;
  let onClosed!: () => void;
  const closed = new Promise<void>((resolveClosed) => {
    onClosed = resolveClosed;
  });
  const block = Buffer.alloc(64 * 1024, 0x5a);
  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    socket.on("close", onClosed);
    const pump = () => {
      let room = true;
      while (room && !socket.destroyed) {
        room = socket.write(block);
        written += block.length;
      }
    };
    socket.on("drain", pump);
    pump();
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  return {
    port: (server.address() as AddressInfo).port,
    written: () => written,
    closed,
    server,
  };
}

async function plateau(read: () => number): Promise<number> {
  let last = -1;
  for (let steady = 0; steady < 4; ) {
    await delay(250);
    const now = read();
    steady = now === last ? steady + 1 : 0;
    last = now;
  }
  return last;
}

test("a forward connection holds back the target, and closes while paused", { timeout: 60000 }, async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({ binPath, socketPath, workspace: tmpdir() });
  const target = await producer();
  const conn = net.createConnection(socketPath);
  try {
    const { channel } = await openForwardConnection(conn, {
      host: "127.0.0.1",
      port: target.port,
      protocol: "tcp",
      highWaterMarkBytes: 256 * 1024,
    });

    const stalled = await plateau(target.written);
    assert.ok(stalled < 64 * 1024 * 1024, `the target wrote ${stalled} bytes with nothing read`);

    let read = 0;
    const iterator = channel[Symbol.asyncIterator]();
    while (read < 8 * 1024 * 1024) {
      const { value, done } = await iterator.next();
      assert.equal(done, false);
      read += value.byteLength;
    }
    const resumed = await plateau(target.written);
    assert.ok(resumed > stalled, `the target wrote on once read (${stalled} then ${resumed})`);

    channel.destroy();
    assert.deepEqual(await channel.closed, { kind: "local" });
    await Promise.race([
      target.closed,
      delay(5000).then(() => assert.fail("sealantd closed the target once the connection closed")),
    ]);
    assert.ok(conn.destroyed, "the connection is closed");

    await client.shutdown(200);
  } finally {
    conn.destroy();
    target.server.close();
    client.close();
    await waitExit(child);
    rmSync(socketPath, { force: true });
  }
});

test("a forward connection to nothing rejects with the daemon's error", { timeout: 20000 }, async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({ binPath, socketPath, workspace: tmpdir() });
  const reserved = net.createServer();
  await new Promise<void>((resolveListen) => reserved.listen(0, "127.0.0.1", resolveListen));
  const port = (reserved.address() as AddressInfo).port;
  await new Promise<void>((resolveClose) => reserved.close(() => resolveClose()));
  const conn = net.createConnection(socketPath);
  try {
    await assert.rejects(
      openForwardConnection(conn, {
        host: "127.0.0.1",
        port,
        protocol: "tcp",
        highWaterMarkBytes: 64 * 1024,
      }),
      SealantError,
    );
    assert.ok(conn.destroyed, "the connection is closed");
    await client.shutdown(200);
  } finally {
    conn.destroy();
    client.close();
    await waitExit(child);
    rmSync(socketPath, { force: true });
  }
});
