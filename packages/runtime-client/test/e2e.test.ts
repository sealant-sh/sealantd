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
import type { ChildProcess } from "node:child_process";

import { SealantClient, SealantError } from "@sealant/runtime-client";
import {
  ControlErrorCode,
  RuntimeState,
  StreamKind,
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
