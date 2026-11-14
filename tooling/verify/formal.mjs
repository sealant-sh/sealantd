// `verify formal`: the property tests and fuzz targets whose covered files the change touches, from
// the obligations map's `formal` entries. sealantd has no model with a sync commit, so there is no
// drift to report; a fuzz target needs nightly Rust and cargo-fuzz, and says so when they are missing.
import { spawn, spawnSync } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, readdirSync } from "node:fs";
import path from "node:path";

export const FUZZ_SECONDS = 20;

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

export const formal = async (root, { obligations, fuzzSeconds = FUZZ_SECONDS, progress = () => {} }) => {
  mkdirSync(path.join(root, ".verify", "logs"), { recursive: true });
  const steps = [];
  const evidence = [];
  const next = [];
  const owed = obligations.filter((o) => o.kind === "formal" && (o.test || o.fuzz));
  if (owed.length === 0) {
    steps.push({ id: "formal", title: "Nothing covered", status: "passed", detail: "the change touches no file a property test or fuzz target covers" });
    return { steps, evidence, next };
  }
  if (!works(["cargo", "--version"], root)) {
    for (const o of owed) steps.push({ id: o.id, title: o.model, status: "blocked_by_prerequisite", detail: "cargo is not on PATH: install rustup, which reads rust-toolchain.toml" });
    return { steps, evidence, next };
  }

  for (const o of owed.filter((o) => o.test)) {
    const log = `.verify/logs/formal-${o.id}.log`;
    const argv = ["cargo", "test", "-p", o.test.package, "--lib", "--", "--exact", o.test.name];
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
