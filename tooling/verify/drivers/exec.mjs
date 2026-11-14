// An example driver for `pnpm verify daemon --driver tooling/verify/drivers/exec.mjs`.
//
// `verify daemon` starts the daemon, then runs this with:
//   SEALANTD_SOCKET          the daemon's control socket
//   SEALANTD_WORKSPACE       its scratch workspace
//   SEALANTCTL, SEALANTD_BIN the binaries it built
//   SEALANT_RUNTIME_CLIENT   the built @sealant/runtime-client, to import from anywhere
//   VERIFY_EVIDENCE_DIR      where to write anything worth keeping
// Every event the daemon emits is recorded beside this run's result, so a driver drives and
// checks; it need not record. Exit 0 when the behaviour held, anything else when it did not.
//
// Copy it outside the repo and change the middle to exercise your change. This one runs a command
// that writes a file in the workspace and prints it, and checks the output and the exit code.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

const { SealantClient } = await import(process.env.SEALANT_RUNTIME_CLIENT);

const client = await SealantClient.connect(process.env.SEALANTD_SOCKET);
try {
  const events = client.events();
  const { processId } = await client.exec({
    executable: "/bin/sh",
    args: ["-c", "echo hello-from-verify > note.txt && cat note.txt"],
  });
  let stdout = "";
  let exitCode;
  for await (const event of events) {
    const { case: kind, value } = event.payload;
    if (event.processId !== processId) continue;
    if (kind === "ioChunk" && value.content) stdout += Buffer.from(value.content).toString();
    if (kind === "processExited") {
      exitCode = value.exitCode;
      break;
    }
  }
  // sealantctl and the exec response both report success for a command that failed: the exit
  // event is what says.
  assert.equal(exitCode, 0, "the command's exit code");
  assert.equal(stdout, "hello-from-verify\n");
  assert.equal(readFileSync(path.join(process.env.SEALANTD_WORKSPACE, "note.txt"), "utf8"), "hello-from-verify\n");
  console.log(`exec ${processId}: exit 0, stdout and the workspace file match`);
} finally {
  client.close();
}
