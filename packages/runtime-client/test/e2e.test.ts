// Phase 1 acceptance: the TypeScript client starts the daemon, executes a command, streams events,
// receives the correct result, and shuts it down — including binary-safe (NUL / non-UTF-8) output.

import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { rmSync } from "node:fs";
import type { ChildProcess } from "node:child_process";

import { SealantClient } from "../src/client.ts";
import { chunkBytes, isIoChunk, isProcessExited } from "../../runtime-protocol/src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../.."); // packages/runtime-client/test -> repo root
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

test("starts daemon, execs a command, streams events, gets the result, and shuts down", async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({
    binPath,
    socketPath,
    workspace: tmpdir(),
    sandboxId: "sbx-e2e",
    executionId: "run-e2e",
  });
  try {
    const health = await client.health();
    assert.equal(health.state, "healthy");

    const caps = await client.getCapabilities();
    assert.equal(caps.features.ioCapture, true);
    assert.equal(caps.features.pty, false);

    const events = client.events();
    const accepted = await client.exec({ executable: "/bin/echo", args: ["hello"] });
    assert.ok(accepted.processId.startsWith("proc_"));
    assert.equal(typeof accepted.pid, "number");

    let stdout = Buffer.alloc(0);
    let exitCode: number | undefined;
    for await (const event of events) {
      if (isIoChunk(event) && event.stream === "stdout") {
        stdout = Buffer.concat([stdout, chunkBytes(event)]);
      }
      if (isProcessExited(event)) {
        exitCode = event.exitCode;
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

test("captures binary-unsafe output exactly (NUL and high bytes round-trip)", async () => {
  const socketPath = uniqueSocket();
  const { client, child } = await SealantClient.spawn({ binPath, socketPath, workspace: tmpdir() });
  try {
    const events = client.events();
    await client.exec({ executable: "/bin/sh", args: ["-c", "printf 'x\\000y\\377z'"] });

    let stdout = Buffer.alloc(0);
    let exited = false;
    for await (const event of events) {
      if (isIoChunk(event) && event.stream === "stdout") {
        stdout = Buffer.concat([stdout, chunkBytes(event)]);
      }
      if (isProcessExited(event)) {
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
        assert.ok(error instanceof Error);
        assert.equal((error as { code?: string }).code, "process-start-failed");
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
