// Mount-workspace demo driver (run by demo-mount.sh with the container already booted in mount
// mode over a caller-owned host worktree).
//
// Proves, over the real wire: exec edits land through the workspace; fileChange events for those
// edits appear in the record stamped with the run's execution id; graceful shutdown emits the
// final file.changed batch + file.diffAvailable. Host-side persistence is verified by the shell
// wrapper after `docker rm -f`.

import { connectToContainer, jsonish, ok, withTimeout } from "./support.ts";

const container = process.argv[2];
if (!container) throw new Error("usage: demo-mount.ts <container>");

const EXECUTION_ID = "exec-mount-demo";
const conn = connectToContainer(container);
const { client } = conn;

const health = await client.health();
console.log(`  daemon healthy: state=${health.state} runtime=${health.runtimeId}`);
const caps = await client.getCapabilities();
if (!caps.features?.filesystem) throw new Error("filesystem watching is not enabled");
ok("capabilities report filesystem watching enabled (default-on)");

// Start collecting the record before the run so nothing is missed.
const fileEvents: Array<{ path: string; kind: string; executionId?: string }> = [];
let sawDiffAvailable = false;
const wanted = new Set(["file.txt", "created-in-session.txt", "sub/deep.txt"]);
const seen = new Set<string>();
let exitCode: number | undefined;
let resolveDone: () => void;
const done = new Promise<void>((r) => (resolveDone = r));

void (async () => {
  for await (const event of client.events()) {
    const p = event.payload;
    if (p.case === "fileChange") {
      const change = p.value;
      fileEvents.push({
        path: change.path,
        kind: String(change.kind),
        executionId: event.executionId,
      });
      if (wanted.has(change.path)) seen.add(change.path);
    }
    if (p.case === "fileDiffAvailable") {
      sawDiffAvailable = true;
      console.log(`  final diff: ${jsonish(p.value).replaceAll("\n", " ").replaceAll("  ", "")}`);
    }
    if (p.case === "processExited" && exitCode === undefined) {
      exitCode = p.value.exitCode === undefined ? undefined : Number(p.value.exitCode);
    }
    if (exitCode !== undefined && seen.size === wanted.size && sawDiffAvailable) resolveDone();
  }
  resolveDone!();
})();

// The run: edit an existing file, create a file, create a file inside a brand-new directory.
const accepted = await client.exec({
  executable: "/bin/sh",
  args: [
    "-c",
    'echo "edited by workspace run" >> file.txt && echo fresh > created-in-session.txt && mkdir -p sub && echo deep > sub/deep.txt',
  ],
  executionId: EXECUTION_ID,
});
console.log(`  exec accepted: pid=${accepted.pid}`);

// Ask for shutdown once the edits are visible, so the final diff is also demonstrated.
await withTimeout("run exit + live file events", 15000, waitFor(() => exitCode !== undefined && seen.size === wanted.size));
ok(`run exited with code ${exitCode}; live fileChange for all ${wanted.size} paths`);
// The daemon may drop the connection before the shutdown ack flushes through socat; the proof of
// shutdown is the final diff arriving, not the ack.
await client.shutdown(1000).catch(() => {});
await withTimeout("final file.diffAvailable", 15000, done);

if (exitCode !== 0) throw new Error(`run failed with ${exitCode}`);
const mislabeled = fileEvents.filter((e) => wanted.has(e.path) && e.executionId !== EXECUTION_ID);
if (mislabeled.length > 0) throw new Error(`file events missing execution id: ${jsonish(mislabeled)}`);
ok("all run-edit file events carry the run's execution id");
ok("final file.changed batch + file.diffAvailable present in the record");
console.log(`  record file events (${fileEvents.length}):`);
for (const e of fileEvents) console.log(`    ${e.kind.padEnd(4)} ${e.path} exec=${e.executionId ?? "-"}`);
conn.destroy();

async function waitFor(cond: () => boolean): Promise<void> {
  while (!cond()) await new Promise((r) => setTimeout(r, 50));
}
