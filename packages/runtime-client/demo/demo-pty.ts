// Interactive PTY session demo driver (run by demo-pty.sh against a mount-mode workspace
// container). Definition of done, capability 2, over the real wire:
//
//   start a PTY session -> produce output -> KILL the attached client -> reattach from a fresh
//   connection -> replay the full scrollback from sequence 0 -> send input and a resize and see
//   them take effect -> signal the session -> observe the exited state -> replay after exit.
//
// Also proves capability 3 on capability 1: a file edited from INSIDE the PTY produces a
// fileChange event on a mounted workspace directory.

import { Signal } from "@sealant/runtime-protocol";
import type { Channel } from "@sealant/runtime-client";
import { connectToContainer, ok, textOf, withTimeout } from "./support.ts";

const container = process.argv[2];
if (!container) throw new Error("usage: demo-pty.ts <container>");

// ---------- client A: open, attach live, produce output, then die abruptly ----------
const a = connectToContainer(container);
const opened = await a.client.openSession({
  shell: "/bin/bash",
  args: ["--norc", "-i"],
  cols: 80,
  rows: 24,
  executionId: "exec-pty-demo",
});
const sessionId = opened.sessionId;
console.log(`  session opened: ${sessionId} pid=${opened.pid}`);

const attachedA = await a.client.attachSession(sessionId);
await a.client.writeSessionInput(sessionId, new TextEncoder().encode("echo MARKER_A_$((6*7))\n"));
await withTimeout("MARKER_A on live attach", 10000, readUntil(attachedA.channel, "MARKER_A_42"));
ok("client A attached live and saw MARKER_A_42");

a.destroy(); // SIGKILL the transport: no detach, no goodbye — a crashed client.
ok("client A killed abruptly (no detach)");
await new Promise((r) => setTimeout(r, 500));

// ---------- client B: fresh connection — the session must have survived ----------
const b = connectToContainer(container);
const sessions = await b.client.listSessions();
const mine = sessions.sessions.find((s) => s.sessionId === sessionId);
if (!mine) throw new Error("session vanished after client disconnect");
if (mine.state !== 1) throw new Error(`expected running state, got ${mine.state}`);
ok(`session survived the disconnect (state=running, journal cursor=${mine.nextJournalSequence})`);

// One-shot journal read from 0 (the poll-friendly surface).
const batch = await b.client.readSessionOutput(sessionId, 0);
const batchText = batch.chunks.map((c) => textOf(c.data)).join("");
if (!batchText.includes("MARKER_A_42")) throw new Error("scrollback batch missing MARKER_A");
ok(`readSessionOutput(from=0) returned ${batch.chunks.length} chunks incl. MARKER_A (next=${batch.nextSequence})`);

// Streaming reattach with full scrollback replay, then live continuation.
const attachedB = await b.client.attachSession(sessionId, { fromSequence: 0 });
let replayText = "";
let lastSeq = -1n;
const frames = attachedB.channel[Symbol.asyncIterator]
  ? attachedB.channel
  : (() => { throw new Error("channel not iterable"); })();
// Consume with sequence tracking via the raw channel: Channel yields bytes; sequence continuity is
// asserted daemon-side by tests — here we assert content ordering.
const collectB = (async () => {
  for await (const data of frames as AsyncIterable<Uint8Array>) {
    replayText += textOf(data);
  }
})();
await withTimeout("scrollback replay", 10000, waitFor(() => replayText.includes("MARKER_A_42")));
ok("reattach(fromSequence=0) replayed the full scrollback (MARKER_A_42 present)");

// Live input on the same channel after replay.
await b.client.writeSessionInput(sessionId, new TextEncoder().encode("echo MARKER_B_$((7*8))\n"));
await withTimeout("MARKER_B live after replay", 10000, waitFor(() => replayText.includes("MARKER_B_56")));
if (replayText.indexOf("MARKER_A_42") > replayText.indexOf("MARKER_B_56")) {
  throw new Error("replay/live ordering broken");
}
ok("input after reattach took effect; replay precedes live output in order");

// Resize takes effect inside the terminal.
await b.client.resizePty(sessionId, 100, 40);
await b.client.writeSessionInput(sessionId, new TextEncoder().encode("stty size\n"));
await withTimeout("stty size after resize", 10000, waitFor(() => /40 100/.test(replayText)));
ok("resize(100x40) took effect (stty size reported '40 100')");

// A PTY-driven write on the MOUNTED workspace directory produces a fileChange event.
const sawPtyEdit = watchForFileChange(b, "pty-edit.txt");
await b.client.writeSessionInput(
  sessionId,
  new TextEncoder().encode("echo written-from-pty > /workspace/repo/pty-edit.txt\n"),
);
await withTimeout("fileChange for PTY write on mount", 10000, sawPtyEdit);
ok("PTY write inside the mounted repo produced a fileChange event");

// Signal the session (SIGTERM to the process group) and observe the exited lifecycle state.
// An interactive bash ignores SIGTERM, so first `exec` the leader into a signal-responsive
// process (same pid, same group, scrollback retained) — like a real harness leader would be.
await b.client.writeSessionInput(sessionId, new TextEncoder().encode("exec sleep 300\n"));
await new Promise((r) => setTimeout(r, 500));
await b.client.signalSession(sessionId, Signal.TERM);
await withTimeout("session exit after SIGTERM", 10000, waitFor(async () => {
  const list = await b.client.listSessions();
  const s = list.sessions.find((x) => x.sessionId === sessionId);
  return s !== undefined && s.state === 2;
}));
const after = (await b.client.listSessions()).sessions.find((x) => x.sessionId === sessionId)!;
ok(`SIGTERM delivered; lifecycle reports exited (signal=${after.signal})`);

// Reattach to the EXITED session: scrollback still replays, then the End frame closes the channel.
const attachedC = await b.client.attachSession(sessionId, { fromSequence: 0 });
let postExitText = "";
for await (const data of attachedC.channel as AsyncIterable<Uint8Array>) {
  postExitText += textOf(data);
}
if (!postExitText.includes("MARKER_A_42") || !postExitText.includes("MARKER_B_56")) {
  throw new Error("post-exit replay incomplete");
}
ok("post-exit reattach replayed the full scrollback and delivered the End frame");

// Explicit close drops the tombstone.
await b.client.closeSession(sessionId);
const finalList = await b.client.listSessions();
if (finalList.sessions.some((s) => s.sessionId === sessionId)) {
  throw new Error("tombstone not removed by closeSession");
}
ok("closeSession removed the exited tombstone");

b.destroy();
void collectB;
console.log("  PTY DEMO PASSED");
process.exit(0);

// ---------- helpers ----------

async function readUntil(channel: Channel, needle: string): Promise<void> {
  let acc = "";
  for await (const data of channel as AsyncIterable<Uint8Array>) {
    acc += textOf(data);
    if (acc.includes(needle)) return;
  }
  throw new Error(`channel ended before ${needle}; got ${acc}`);
}

async function waitFor(cond: () => boolean | Promise<boolean>): Promise<void> {
  while (!(await cond())) await new Promise((r) => setTimeout(r, 50));
}

function watchForFileChange(conn: { client: { events(): AsyncIterableIterator<any> } }, path: string): Promise<void> {
  return (async () => {
    for await (const event of conn.client.events()) {
      if (event.payload.case === "fileChange" && event.payload.value.path === path) return;
    }
    throw new Error(`event stream ended before fileChange for ${path}`);
  })();
}
