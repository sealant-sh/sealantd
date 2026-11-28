// `verify formal`: the models, property tests and fuzz targets whose covered files the change
// touches, from the obligations map's `formal` entries.
//
// A model (an entry with `dir`, docs/formal/<area>/) stands for the code its COVERAGE names at its
// sync commit. For each owed model:
// - the guard (this diff): a change to covered code must change the model or move COVERAGE's sync
//   commit, after the area's skill says the model still describes the code; otherwise it fails;
// - drift (since the sync commit): covered files changed since the model was last confirmed,
//   reported, not failed;
// - the check: `check.sh --quick`, or the full bounds with --full.
// A fuzz target needs nightly Rust and cargo-fuzz, and says so when they are missing.
//
// No dependency outside node: CI's `formal` job runs `node tooling/verify/formal.mjs ci …` with no
// install.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { matchesAny } from "./repo.mjs";

export const FUZZ_SECONDS = 20;

const gitOut = (root, args) =>
  execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });

/** COVERAGE's `sync`, `model` and `path` lines; model files are given relative to the repo root. */
export const parseCoverage = (text, dir) => {
  const coverage = { dir, sync: null, model: [], paths: [] };
  for (const line of text.split("\n")) {
    const [word, value] = line.trim().split(/\s+/, 2);
    if (word === "sync") coverage.sync = value;
    else if (word === "model") coverage.model.push(path.posix.join(dir, value));
    else if (word === "path") coverage.paths.push(value);
  }
  if (!/^[0-9a-f]{40}$/.test(coverage.sync ?? "")) throw new Error(`${dir}/COVERAGE names no full sync commit`);
  if (coverage.paths.length === 0) throw new Error(`${dir}/COVERAGE names no covered path`);
  return coverage;
};

export const readCoverage = (root, dir) => parseCoverage(readFileSync(path.join(root, dir, "COVERAGE"), "utf8"), dir);

/** The sync commit COVERAGE named at `ref`, or null where it did not exist yet. */
const syncAt = (root, dir, ref) => {
  try {
    return parseCoverage(gitOut(root, ["show", `${ref}:${dir}/COVERAGE`]), dir).sync;
  } catch {
    return null;
  }
};

const gitOk = (root, args) => {
  try {
    gitOut(root, args);
    return true;
  } catch {
    return false;
  }
};

// Why a sync commit can be missing. CI's checkout holds branches and tags, no pull request ref, and
// a squash merge puts none of a pull request's own commits on main.
const WHY_SYNC_VANISHES =
  "A squash merge puts none of a pull request's own commits on main. Once its branch is deleted, only GitHub's pull request ref holds its last pushed head and the commits under it, and verify formal fetches those by SHA. A commit that a rebase or force-push replaced before the merge, or one never pushed, is held by nothing";

/** Whether this clone has `sha`, fetching it from origin by SHA when it does not. */
export const fetchCommit = (root, sha) => {
  if (gitOk(root, ["cat-file", "-e", `${sha}^{commit}`])) return true;
  try {
    execFileSync("git", ["fetch", "--quiet", "--no-tags", "origin", sha], { cwd: root, stdio: "ignore", timeout: 120_000 });
  } catch {
    return false;
  }
  return gitOk(root, ["cat-file", "-e", `${sha}^{commit}`]);
};

/**
 * The guard for one model over a diff's files; `base` is where the diff starts and `head` where it
 * ends. A sync commit the diff moves must be one `head` reaches, so that main or the pull request's
 * last pushed head still holds it after the squash merge.
 */
export const guard = (root, coverage, { files, base, head = "HEAD" }) => {
  const before = base ? syncAt(root, coverage.dir, base) : null;
  if (before !== null && before !== coverage.sync && !gitOk(root, ["merge-base", "--is-ancestor", coverage.sync, head])) {
    return {
      status: "failed",
      detail: `${coverage.dir}/COVERAGE moves sync to ${coverage.sync.slice(0, 10)}, which this branch does not reach: a commit that a rebase or force-push replaced, one from another branch, or one never pushed. After the squash merge GitHub keeps only main and this pull request's last pushed head, so the commit would vanish. Name a commit on main, or this branch's commit that holds the code you checked, as pushed, and re-point it after every rebase`,
    };
  }
  const code = files.filter((f) => coverage.paths.includes(f));
  if (code.length === 0) return { status: "passed", detail: "no covered code changed" };
  const model = files.filter((f) => coverage.model.includes(f));
  if (model.length > 0) return { status: "passed", detail: `covered code and the model changed (${model.join(", ")})` };
  if (before !== null && before !== coverage.sync) {
    return { status: "passed", detail: `covered code changed and the sync commit moved to ${coverage.sync.slice(0, 10)}` };
  }
  const area = path.posix.basename(coverage.dir);
  return {
    status: "failed",
    detail: `${code.join(", ")} changed, and neither the model nor COVERAGE's sync commit moved. Follow .agents/skills/${area}: account for each hunk in the model, run the full check, then move the sync line in ${coverage.dir}/COVERAGE`,
  };
};

/**
 * Covered files that changed since the sync commit, at `head`. A sync commit this clone lacks is
 * fetched from origin; `known` is false when origin does not serve it either.
 */
export const drift = (root, coverage, head, fetch = fetchCommit) => {
  if (!fetch(root, coverage.sync)) return { known: false, files: [] };
  const files = gitOut(root, ["diff", "--name-only", coverage.sync, head, "--", ...coverage.paths]).split("\n").filter(Boolean);
  return { known: true, files };
};

const driftDetail = (coverage, moved) =>
  `drift since ${coverage.sync.slice(0, 10)}: ${moved.known ? (moved.files.length ? moved.files.join(", ") : "none") : "unknown, the sync commit cannot be read"}`;

/** The guard and the check for each owed model. `run(argv, log)` resolves to { code }. */
export const modelSteps = async (root, models, { files, base, head, full = false, run }) => {
  const steps = [];
  const evidence = [];
  const next = [];
  for (const o of models) {
    let coverage;
    try {
      coverage = readCoverage(root, o.dir);
    } catch (error) {
      steps.push({ id: `${o.id}-guard`, title: o.model, status: "failed", detail: error.message });
      continue;
    }
    const verdict = base ? guard(root, coverage, { files, base, head }) : { status: "passed", detail: "no base: the guard needs a diff" };
    const moved = drift(root, coverage, head);
    if (!moved.known) {
      const area = path.posix.basename(coverage.dir);
      steps.push({
        id: `${o.id}-sync`,
        title: `${o.model}: the sync commit in COVERAGE can be read`,
        status: "failed",
        detail: `${area}'s sync commit ${coverage.sync} is not in this clone, and origin does not serve it. ${WHY_SYNC_VANISHES}. Point the sync line in ${coverage.dir}/COVERAGE at the commit on main that holds the code the model was last checked against (usually the squash commit of the pull request that set it: git log origin/main --format=%H -- ${coverage.dir}/COVERAGE), and account for any covered hunk between the two as .agents/skills/${area} says`,
      });
    }
    steps.push({
      id: `${o.id}-guard`,
      title: `${o.model}: covered code changes move the model or its sync commit`,
      status: verdict.status,
      detail: `${verdict.detail}. ${driftDetail(coverage, moved)}`,
    });
    // check.sh runs tlx, which docs/formal/tlx.sh builds from its pinned commit the first time.
    const argv = ["bash", path.join(o.dir, "check.sh"), ...(full ? [] : ["--quick"])];
    const log = `.verify/logs/formal-${o.id}.log`;
    const started = Date.now();
    const { code } = await run(argv, log);
    evidence.push({ kind: "log", path: log });
    if (code === 2) next.push("check.sh builds tlx the first time: it needs git, cargo (rustup: https://rustup.rs) and a C compiler as cc");
    steps.push({
      id: `${o.id}-check`,
      title: `${o.model}: model check, ${full ? "full" : "quick"} bounds`,
      command: argv.join(" "),
      log,
      durationMs: Date.now() - started,
      ...(code === 0
        ? { status: "passed", detail: "every row as expected" }
        : code === 2
          ? { status: "blocked_by_prerequisite", detail: `no tlx, and it could not be built: see ${log}` }
          : { status: "failed", detail: `a row is NOT AS EXPECTED: ${log} names it, and .agents/skills/${path.posix.basename(o.dir)} step 3 classifies it` }),
    });
  }
  return { steps, evidence, next };
};

const runLogged = (root, argv, log) =>
  new Promise((resolve) => {
    const out = createWriteStream(path.join(root, log));
    out.write(`$ ${argv.join(" ")}\n`);
    const env = { ...process.env, CARGO_TERM_COLOR: "never" };
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(argv[0], argv.slice(1), { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
    let text = "";
    const take = (chunk) => {
      text += chunk;
      out.write(chunk);
    };
    child.stdout.on("data", take);
    child.stderr.on("data", take);
    child.on("error", (error) => take(`${error.message}\n`));
    child.on("close", (code) => out.end(() => resolve({ code: code ?? 1, text })));
  });

const works = (argv, cwd) => spawnSync(argv[0], argv.slice(1), { cwd, stdio: "ignore" }).status === 0;

// What libFuzzer leaves for an input that crashed, leaked or hung.
const findings = (root, target) => {
  const dir = path.join(root, "fuzz", "artifacts", target);
  return existsSync(dir) ? readdirSync(dir).map((f) => path.join("fuzz", "artifacts", target, f)) : [];
};

// A property test passes only when exactly the named test ran and passed: a name that matches
// nothing would otherwise pass with 0 tests.
export const propertyVerdict = (code, text) => {
  const ran = [...text.matchAll(/test result: \w+\. (\d+) passed; (\d+) failed/g)].reduce(
    (sum, m) => sum + Number(m[1]) + Number(m[2]),
    0,
  );
  if (code !== 0) return { status: "failed", detail: "the property failed" };
  if (ran !== 1) return { status: "failed", detail: `${ran} tests ran: the map names a test that does not exist` };
  return { status: "passed", detail: "1 passed" };
};

export const formal = async (
  root,
  { obligations, files = [], base = null, head = "HEAD", full = false, fuzzSeconds = FUZZ_SECONDS, progress = () => {} },
) => {
  mkdirSync(path.join(root, ".verify", "logs"), { recursive: true });
  const models = obligations.filter((o) => o.kind === "formal" && o.dir);
  const owed = obligations.filter((o) => o.kind === "formal" && (o.test || o.fuzz));
  if (models.length === 0 && owed.length === 0) {
    return {
      steps: [{ id: "formal", title: "Nothing covered", status: "passed", detail: "the change touches no file a model, property test or fuzz target covers" }],
      evidence: [],
      next: [],
    };
  }
  const { steps, evidence, next } = await modelSteps(root, models, {
    files,
    base,
    head,
    full,
    run: (argv, log) => {
      progress(argv.join(" "));
      return runLogged(root, argv, log);
    },
  });
  if (owed.length === 0) return { steps, evidence, next };
  if (!works(["cargo", "--version"], root)) {
    for (const o of owed) steps.push({ id: o.id, title: o.model, status: "blocked_by_prerequisite", detail: "cargo is not on PATH: install rustup, which reads rust-toolchain.toml" });
    return { steps, evidence, next };
  }

  for (const o of owed.filter((o) => o.test)) {
    const log = `.verify/logs/formal-${o.id}.log`;
    // A test in the crate's own source runs from --lib; one in tests/<file>.rs from --test <file>.
    const target = o.test.file ? ["--test", o.test.file] : ["--lib"];
    const argv = ["cargo", "test", "-p", o.test.package, ...target, "--", "--exact", o.test.name];
    progress(`${o.model}: ${argv.join(" ")}`);
    const started = Date.now();
    const { code, text } = await runLogged(root, argv, log);
    steps.push({ id: o.id, title: o.model, command: argv.join(" "), log, durationMs: Date.now() - started, ...propertyVerdict(code, text) });
    evidence.push({ kind: "log", path: log });
  }

  const fuzzing = owed.filter((o) => o.fuzz);
  if (fuzzing.length > 0) {
    // Asked from rustup's list: `cargo +nightly` itself would download a missing toolchain (1.6 GB)
    // as a side effect of checking for it.
    const toolchains = spawnSync("rustup", ["toolchain", "list"], { encoding: "utf8" });
    const nightly = toolchains.status === 0 && /^nightly\b/m.test(toolchains.stdout);
    const cargoFuzz = nightly && works(["cargo", "+nightly", "fuzz", "--version"], root);
    // libfuzzer-sys compiles libFuzzer, which is C++.
    const cxx = works(["sh", "-c", "command -v c++"], root);
    if (!cargoFuzz || !cxx) {
      const missing = !nightly
        ? "nightly Rust is not installed (through rustup)"
        : !cargoFuzz
          ? "cargo-fuzz is not installed"
          : "no C++ compiler (c++) on PATH: libFuzzer is built from C++";
      for (const o of fuzzing) steps.push({ id: o.id, title: o.model, status: "blocked_by_prerequisite", detail: missing });
      if (!nightly) next.push("rustup toolchain install nightly --profile minimal");
      if (!cargoFuzz) next.push("cargo install cargo-fuzz --locked");
    } else {
      for (const o of fuzzing) {
        const log = `.verify/logs/formal-${o.id}.log`;
        const argv = ["cargo", "+nightly", "fuzz", "run", o.fuzz, "--", `-max_total_time=${fuzzSeconds}`];
        progress(`${o.model}: ${argv.join(" ")}`);
        const before = new Set(findings(root, o.fuzz));
        const started = Date.now();
        const { code } = await runLogged(root, argv, log);
        const found = findings(root, o.fuzz).filter((f) => !before.has(f));
        for (const f of found) evidence.push({ kind: "input", path: f });
        evidence.push({ kind: "log", path: log });
        steps.push({
          id: o.id,
          title: o.model,
          command: argv.join(" "),
          log,
          durationMs: Date.now() - started,
          status: code === 0 ? "passed" : "failed",
          detail: code === 0 ? `no crash in ${fuzzSeconds}s` : found.length ? `crashed: ${found.join(", ")}` : `exit ${code}: see ${log}`,
        });
      }
    }
  }
  return { steps, evidence, next: [...new Set(next)] };
};

// CI: `node tooling/verify/formal.mjs ci <base sha|-> <head sha> [--full]`. The models only: the
// property tests run in the rust job, the fuzz targets nightly. With `-` (a push to main, the
// nightly run) there is no diff: every model runs and the guard is not asked.
const ci = async (argv) => {
  const [base, head, ...flags] = argv;
  if (!base || !head) {
    process.stderr.write("usage: node tooling/verify/formal.mjs ci <base sha|-> <head sha> [--full]\n");
    return 2;
  }
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const map = JSON.parse(readFileSync(new URL("./obligations.json", import.meta.url), "utf8"));
  const diffBase = base === "-" ? null : gitOut(root, ["merge-base", base, head]).trim();
  const files = diffBase === null ? [] : gitOut(root, ["diff", "--name-only", "--no-renames", diffBase, head]).split("\n").filter(Boolean);
  const models = map.flatMap((entry) =>
    diffBase !== null && !files.some((f) => matchesAny(f, entry.paths ?? []))
      ? []
      : entry.owes.filter((o) => o.kind === "formal" && o.dir).map((o) => ({ id: entry.id, ...o })),
  );
  if (models.length === 0) {
    console.log("passed  formal: the change touches no file a model covers");
    return 0;
  }
  const { steps } = await modelSteps(root, models, {
    files,
    base: diffBase,
    head,
    full: flags.includes("--full"),
    run: (cmd) =>
      new Promise((resolve) => {
        console.log(`$ ${cmd.join(" ")}`);
        const child = spawn(cmd[0], cmd.slice(1), { cwd: root, stdio: "inherit" });
        child.once("error", () => resolve({ code: 127 }));
        child.once("close", (code) => resolve({ code: code ?? 1 }));
      }),
  });
  for (const step of steps) console.log(`${step.status.padEnd(24)} ${step.id}: ${step.detail}`);
  const bad = steps.filter((step) => step.status !== "passed");
  if (bad.length > 0) console.log(`::error::${bad.map((step) => step.id).join(", ")} did not pass`);
  return bad.length === 0 ? 0 : 1;
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = process.argv[2] === "ci" ? await ci(process.argv.slice(3)) : 2;
  if (process.argv[2] !== "ci") process.stderr.write("usage: node tooling/verify/formal.mjs ci <base sha|-> <head sha> [--full]\n");
}
