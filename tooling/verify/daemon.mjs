// `verify daemon --driver <file>`: build the daemon from this tree, start it on a socket in a
// scratch directory with a scratch workspace, wait until it answers healthy, run the driver against
// it while a second connection records every event, then tear everything down, on failure and on
// Ctrl-C too. `--keep` leaves the daemon running and says how to reach and stop it.
import { spawn, spawnSync } from "node:child_process";
import { closeSync, createWriteStream, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, readlinkSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const READY_MS = 60_000;
const SHUTDOWN_GRACE_MS = 2_000;
const EXIT_MS = 30_000;

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

const waitGone = async (pid, ms) => {
  const until = Date.now() + ms;
  while (alive(pid) && Date.now() < until) await delay(50);
  return !alive(pid);
};

// Processes whose working directory is inside `dir`: what the daemon started and left behind.
const processesIn = (dir) => {
  const found = [];
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/.test(entry) || Number(entry) === process.pid) continue;
    try {
      const cwd = readlinkSync(`/proc/${entry}/cwd`);
      if (cwd === dir || cwd.startsWith(`${dir}/`)) found.push(Number(entry));
    } catch {}
  }
  return found;
};

// `node` for JavaScript and TypeScript, `bash` for shell, the file itself otherwise.
export const driverCommand = (file) => {
  if (/\.(m?js|cjs|m?ts)$/.test(file)) return [process.execPath, file];
  if (/\.sh$/.test(file)) return ["bash", file];
  return [file];
};

// The binaries `cargo build` produced, from its JSON messages: wherever the target directory is.
const build = (root, log) => {
  const out = openSync(path.join(root, log), "w");
  const result = spawnSync(
    "cargo",
    ["build", "--locked", "-p", "sealantd", "-p", "sealantctl", "--message-format", "json-render-diagnostics"],
    { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", out], maxBuffer: 256 * 1024 * 1024 },
  );
  closeSync(out);
  if (result.error) return { code: 127 };
  const bins = {};
  for (const line of (result.stdout ?? "").split("\n")) {
    if (!line.includes('"compiler-artifact"')) continue;
    const message = JSON.parse(line);
    if (message.executable && ["sealantd", "sealantctl"].includes(message.target?.name)) bins[message.target.name] = message.executable;
  }
  return { code: result.status, bins };
};

export const daemon = async (root, { driver, keep, timeoutS = 600, daemonArgs = [], progress = () => {}, signal }) => {
  const steps = [];
  const evidence = [];
  const left = [];
  const next = [];
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const evidenceDir = path.join(".verify", "evidence", `daemon-${stamp}`);
  mkdirSync(path.join(root, evidenceDir), { recursive: true });
  mkdirSync(path.join(root, ".verify", "logs"), { recursive: true });
  const timed = async (id, title, fn) => {
    progress(title);
    const started = Date.now();
    const step = { id, title, status: "passed", ...(await fn()) };
    step.durationMs = Date.now() - started;
    progress(`${title}: ${step.status}${step.detail ? ` (${step.detail})` : ""}`);
    steps.push(step);
    return step;
  };
  const finish = (cleanup) => ({ steps, evidence, cleanup, next });
  const stopped = () => signal?.aborted;

  if (!existsSync(path.resolve(root, driver))) {
    steps.push({ id: "driver", title: "Driver", status: "failed", detail: `no driver at ${driver}` });
    return finish({ status: "none", left: [] });
  }
  if (spawnSync("sh", ["-c", "command -v cargo"]).status !== 0) {
    steps.push({ id: "build", title: "Build the daemon", status: "blocked_by_prerequisite", detail: "cargo is not on PATH: install rustup, which reads rust-toolchain.toml" });
    return finish({ status: "none", left: [] });
  }

  // 1. Build the daemon and sealantctl from this tree, and the TypeScript client the events are read with.
  let bins;
  const built = await timed("build", "Build sealantd and sealantctl", () => {
    const log = ".verify/logs/daemon-build.log";
    const r = build(root, log);
    bins = r.bins;
    const ok = r.code === 0 && bins?.sealantd && bins?.sealantctl;
    return { status: ok ? "passed" : "failed", command: "cargo build --locked -p sealantd -p sealantctl", log, ...(ok && { detail: bins.sealantd }) };
  });
  if (built.status !== "passed" || stopped()) return finish({ status: "none", left: [] });
  const client = await timed("client", "Build the TypeScript client", () => {
    const log = ".verify/logs/daemon-client.log";
    const out = openSync(path.join(root, log), "w");
    const run = (argv) => spawnSync(argv[0], argv.slice(1), { cwd: root, stdio: ["ignore", out, out] }).status;
    const code =
      (existsSync(path.join(root, "node_modules")) ? 0 : run(["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"])) ||
      run(["pnpm", "-r", "build"]);
    closeSync(out);
    return { status: code === 0 ? "passed" : "failed", command: "pnpm -r build", log };
  });
  if (client.status !== "passed" || stopped()) return finish({ status: "none", left: [] });
  const clientEntry = path.join(root, "packages/runtime-client/dist/index.js");
  const protocolEntry = path.join(root, "packages/runtime-protocol/dist/index.js");
  const { SealantClient } = await import(pathToFileURL(clientEntry).href);
  const { EventEnvelopeSchema, RuntimeState } = await import(pathToFileURL(protocolEntry).href);
  const { toJson } = createRequire(path.join(root, "packages/runtime-protocol/package.json"))("@bufbuild/protobuf");

  // 2. Start it in a scratch directory, in its own process group so Ctrl-C reaches us, not it.
  const scratch = mkdtempSync(path.join(tmpdir(), "verify-daemon-"));
  const workspace = path.join(scratch, "workspace");
  const socket = path.join(scratch, "sealantd.sock");
  mkdirSync(workspace);
  const daemonLog = path.join(evidenceDir, "daemon.log");
  const logFd = openSync(path.join(root, daemonLog), "w");
  const argv = [bins.sealantd, "--socket", socket, "--workspace", workspace, "--workspace-id", "verify", "--execution-id", "verify", ...daemonArgs];
  const child = spawn(argv[0], argv.slice(1), {
    cwd: scratch,
    detached: true,
    stdio: ["ignore", logFd, logFd],
    env: { ...process.env, NO_COLOR: "1" },
  });
  closeSync(logFd);
  evidence.push({ kind: "log", path: daemonLog });
  let exited = null;
  child.on("exit", (code, sig) => (exited = { code, signal: sig }));
  // A crash of this process must not leave the daemon or its directory behind.
  const lastResort = () => {
    if (!keep && alive(child.pid)) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    }
    if (!keep) rmSync(scratch, { recursive: true, force: true });
  };
  process.on("exit", lastResort);

  // 3. Ready means a connection that answers health with HEALTHY, not a socket file.
  let observer;
  const ready = await timed("ready", "Wait until the daemon answers healthy", async () => {
    const until = Date.now() + READY_MS;
    let last = "no answer";
    while (Date.now() < until && !exited && !stopped()) {
      try {
        observer ??= await SealantClient.connect(socket, { retries: 1, delayMs: 0 });
        const health = await observer.health();
        if (health.state === RuntimeState.HEALTHY) return { detail: `pid ${child.pid}, socket ${socket}` };
        last = `state ${RuntimeState[health.state]}`;
      } catch (error) {
        last = error.message;
        observer = undefined;
      }
      await delay(100);
    }
    if (stopped()) return { status: "failed", detail: "interrupted" };
    return { status: "failed", detail: exited ? `the daemon exited (${exited.code ?? exited.signal}) before answering: see ${daemonLog}` : `not healthy after ${READY_MS / 1000}s: ${last}` };
  });

  // 4. Record every event from here on: each connection receives all of them.
  const eventsPath = path.join(evidenceDir, "events.jsonl");
  const eventsOut = createWriteStream(path.join(root, eventsPath));
  let eventCount = 0;
  const recording =
    ready.status === "passed"
      ? (async () => {
          for await (const event of observer.events()) {
            eventsOut.write(`${JSON.stringify(toJson(EventEnvelopeSchema, event))}\n`);
            eventCount++;
          }
        })().catch(() => {})
      : Promise.resolve();
  evidence.push({ kind: "events", path: eventsPath });

  // 5. Run the driver against it.
  if (ready.status === "passed" && !stopped()) {
    const driverLog = path.join(evidenceDir, "driver.log");
    evidence.push({ kind: "log", path: driverLog });
    const command = driverCommand(path.resolve(root, driver));
    await timed("driver", `Run the driver ${driver}`, () =>
      new Promise((resolve) => {
        const out = createWriteStream(path.join(root, driverLog));
        const run = spawn(command[0], command.slice(1), {
          cwd: root,
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            SEALANTD_SOCKET: socket,
            SEALANTD_WORKSPACE: workspace,
            SEALANTD_BIN: bins.sealantd,
            SEALANTCTL: bins.sealantctl,
            SEALANT_RUNTIME_CLIENT: clientEntry,
            SEALANT_RUNTIME_PROTOCOL: protocolEntry,
            VERIFY_EVIDENCE_DIR: path.join(root, evidenceDir),
          },
        });
        for (const stream of [run.stdout, run.stderr]) {
          stream.on("data", (chunk) => {
            out.write(chunk);
            process.stderr.write(chunk);
          });
        }
        const kill = () => run.kill("SIGTERM");
        const timer = setTimeout(kill, timeoutS * 1000);
        signal?.addEventListener("abort", kill, { once: true });
        run.on("close", (code, sig) => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", kill);
          out.end();
          const why = stopped() ? "interrupted" : sig ? `killed by ${sig}${sig === "SIGTERM" ? ` after ${timeoutS}s` : ""}` : `exit ${code}`;
          resolve({ status: code === 0 ? "passed" : "failed", command: command.join(" "), detail: why, log: driverLog });
        });
      }),
    );
  }

  // 6. Keep it, or tear it down: a graceful shutdown whose final events are recorded, then the
  // process group, anything still working in the scratch directory, and the directory.
  if (keep && !stopped() && !exited) {
    process.off("exit", lastResort);
    observer?.close();
    await recording;
    eventsOut.end();
    child.unref();
    const stop = `kill -TERM -${child.pid}; rm -rf ${scratch}`;
    steps.push({
      id: "keep",
      title: "Leave the daemon running",
      status: "passed",
      detail: `socket ${socket}, workspace ${workspace}, pid ${child.pid}. Reach it: ${bins.sealantctl} --socket ${socket} health. Stop it: ${stop}`,
    });
    left.push(`sealantd pid ${child.pid} on ${socket}`, `scratch directory ${scratch}`);
    return { ...finish({ status: "left", left }), keep: { pid: child.pid, socket, workspace, scratch, sealantctl: bins.sealantctl, stop } };
  }
  await timed("teardown", "Shut the daemon down and remove what this run made", async () => {
    let how = "graceful shutdown";
    if (observer && !exited) {
      await Promise.race([observer.shutdown(SHUTDOWN_GRACE_MS).catch(() => {}), delay(EXIT_MS, undefined, { ref: false })]);
    }
    if (!(await waitGone(child.pid, EXIT_MS))) {
      how = "SIGTERM";
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {}
      if (!(await waitGone(child.pid, 10_000))) {
        how = "SIGKILL";
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {}
        await waitGone(child.pid, 5_000);
      }
    }
    observer?.close();
    await Promise.race([recording, delay(5_000, undefined, { ref: false })]);
    eventsOut.end();
    const stragglers = processesIn(scratch);
    for (const pid of stragglers) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {}
    }
    const stillThere = [];
    for (const pid of stragglers) if (!(await waitGone(pid, 5_000))) stillThere.push(`pid ${pid} in ${scratch}`);
    if (alive(child.pid)) stillThere.push(`sealantd pid ${child.pid}`);
    if (stillThere.length === 0) rmSync(scratch, { recursive: true, force: true });
    else stillThere.push(`scratch directory ${scratch}`);
    left.push(...stillThere);
    process.off("exit", lastResort);
    const lagged = readFileSync(path.join(root, daemonLog), "utf8").includes("event subscriber lagged");
    const detail = `${how}; ${eventCount} event(s) recorded${stragglers.length ? `; killed ${stragglers.length} leftover process(es)` : ""}`;
    if (lagged) return { status: "failed", detail: `${detail}; the daemon dropped events to the recorder, so ${eventsPath} is incomplete` };
    return { status: stillThere.length ? "failed" : "passed", detail };
  });
  if (stopped()) steps.push({ id: "interrupted", title: "Interrupted", status: "failed", detail: "stopped by a signal; torn down" });
  return finish({ status: left.length ? "left" : "clean", left });
};
