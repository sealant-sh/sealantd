// `verify daemon` against a real daemon built from this tree (CI's node job runs this after its
// daemon build). Each case checks what the run left behind, not only its status.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validate } from "./result.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../..");
const cli = path.join(here, "verify.mjs");

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

// Runs the verb; `onStderr` sees progress as it arrives and may signal the run.
const runDaemon = (args, onStderr = () => {}) =>
  new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, "daemon", ...args, "--json"], {
      cwd: repo,
      env: { ...process.env, VERIFY_ROOT: repo },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => {
      stderr += c;
      onStderr(stderr, child);
    });
    child.on("close", (code) => resolve({ code, result: JSON.parse(stdout), stderr }));
  });

const driver = (t, source) => {
  const dir = mkdtempSync(path.join(tmpdir(), "verify-driver-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "driver.mjs");
  writeFileSync(file, source);
  return file;
};

const pidOf = (result) => Number(result.steps.find((s) => s.id === "ready").detail.match(/pid (\d+)/)[1]);
const scratchOf = (result) => path.dirname(result.steps.find((s) => s.id === "ready").detail.match(/socket (\S+)/)[1]);

test("the example driver passes, its events are recorded, and nothing is left", async () => {
  const { code, result } = await runDaemon(["--driver", "tooling/verify/drivers/exec.mjs"]);
  assert.deepEqual(validate(result), []);
  assert.equal(result.status, "passed", JSON.stringify(result.steps));
  assert.equal(code, 0);
  const events = readFileSync(path.join(repo, result.evidence.find((e) => e.kind === "events").path), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const exited = events.find((e) => e.processExited);
  assert.equal(exited.processExited.exitCode ?? 0, 0);
  assert.ok(events.some((e) => e.ioChunk && e.processId === exited.processId));
  assert.deepEqual(result.cleanup, { status: "clean", left: [] });
  assert.ok(!alive(pidOf(result)));
  assert.ok(!existsSync(scratchOf(result)));
});

test("a failing driver fails the run and the daemon is still torn down", async (t) => {
  const { code, result } = await runDaemon(["--driver", driver(t, "process.exit(3);\n")]);
  assert.equal(result.steps.find((s) => s.id === "driver").detail, "exit 3");
  assert.equal(result.status, "failed");
  assert.equal(code, 1);
  assert.deepEqual(result.cleanup, { status: "clean", left: [] });
  assert.ok(!alive(pidOf(result)));
  assert.ok(!existsSync(scratchOf(result)));
});

test("Ctrl-C during the driver tears everything down", async (t) => {
  const file = driver(t, 'console.log("driver started");\nsetTimeout(() => {}, 120_000);\n');
  let sent = false;
  const { code, result } = await runDaemon(["--driver", file], (stderr, child) => {
    if (!sent && stderr.includes("driver started")) {
      sent = true;
      child.kill("SIGINT");
    }
  });
  assert.ok(sent);
  assert.equal(result.status, "failed");
  assert.equal(code, 1);
  assert.equal(result.steps.find((s) => s.id === "driver").detail, "interrupted");
  assert.deepEqual(result.cleanup, { status: "clean", left: [] });
  assert.ok(!alive(pidOf(result)));
  assert.ok(!existsSync(scratchOf(result)));
});

test("--keep leaves a daemon that answers, and says how to stop it", async (t) => {
  const { code, result } = await runDaemon(["--driver", driver(t, "process.exit(0);\n"), "--keep"]);
  const { pid, socket, scratch, sealantctl, stop } = result.keep;
  t.after(() => {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {}
    rmSync(scratch, { recursive: true, force: true });
  });
  assert.equal(code, 0);
  assert.equal(result.cleanup.status, "left");
  assert.ok(alive(pid));
  assert.match(execFileSync(sealantctl, ["--socket", socket, "health"], { encoding: "utf8" }), /HEALTHY|healthy/i);
  execFileSync("sh", ["-c", stop]);
  for (let i = 0; i < 100 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
  assert.ok(!alive(pid));
  assert.ok(!existsSync(scratch));
});
