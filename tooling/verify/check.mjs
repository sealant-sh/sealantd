// `verify check`: the checks AGENTS.md lists before a PR, scoped to what the change touches, each a
// step, with every skipped or ignored test reported with its gate. A skip is never a pass.
import { spawn, spawnSync } from "node:child_process";
import { createWriteStream, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { git, matchesAny } from "./repo.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

// Paths whose change rebuilds or re-lints every crate.
const RUST_WORKSPACE = [
  "Cargo.toml",
  "Cargo.lock",
  "rust-toolchain.toml",
  ".cargo/**",
  "rustfmt.toml",
  "clippy.toml",
  ".config/nextest.toml",
];
// AGENTS.md: "When the change touches packages/, also run" the pnpm checks.
const TYPESCRIPT = ["packages/**", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"];
// The repo's own scripts and workflows, whose tests ci.yml's node job lists.
const SCRIPTS = ["scripts/**", "tooling/**", ".github/**", "package.json", "pnpm-lock.yaml"];

// The variables CI sets so a test that would skip fails instead. `check` sets each one this
// machine can satisfy; one it cannot is a skip, never a quiet pass.
export const GATES = [
  {
    env: "SEALANTD_REQUIRE_DOTFILES_TOOLS",
    tests: ["sealantd boot::dotfiles::*"],
    ready: (onPath) => onPath("stow") && onPath("chezmoi"),
    unready: "stow or chezmoi is not on PATH: the real dotfiles applies were not exercised",
    next: "scripts/ci-install-dotfiles-tools.sh",
  },
  {
    env: "SEALANTD_REQUIRE_NNP_FREE",
    // Passes without proving anything when the environment already imposes no-new-privileges.
    tests: ["sealantd::no_new_privileges a_per_person_daemon_leaves_no_new_privileges_unset"],
    ready: () => !/^NoNewPrivs:\s*1$/m.test(readFileSync("/proc/self/status", "utf8")),
    unready: "this environment imposes no-new-privileges, so leaving it unset was not proved",
  },
];

export const loadAllowedSkips = (file = path.join(here, "allowed-skips.json")) =>
  JSON.parse(readFileSync(file, "utf8")).check;

// Test-name patterns: `*` matches anything.
const nameMatches = (name, pattern) =>
  new RegExp(`^${pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`).test(name);

// Marks each skipped test allowed when the list names it with the same gate. A step with any skip
// the list does not allow is `skipped`.
export const judgeSkips = (skipped, allowed) =>
  skipped.map((s) => {
    const entry = allowed.find((a) => nameMatches(s.name, a.test) && a.gate === s.gate);
    return entry ? { ...s, allowed: true, reason: s.reason ?? entry.reason } : { ...s, allowed: false };
  });

// nextest's human output with `--status-level all --success-output immediate`: SKIP lines are
// `#[ignore]`d tests; a passing test whose stderr says it skipped is a runtime skip.
export const nextestSkips = (output, gates = []) => {
  const skipped = [];
  const passed = new Set();
  let current = null;
  let stream = null;
  for (const line of output.split("\n")) {
    const status = line.match(/^\s*(PASS|SKIP|FAIL|SIGSEGV|SIGABRT|TIMEOUT|LEAK)\s+\[[^\]]*\]\s+(?:\([^)]*\)\s+)?(\S+)\s+(\S+)/);
    if (status) {
      current = `${status[2]} ${status[3]}`;
      stream = null;
      if (status[1] === "SKIP") skipped.push({ name: current, gate: "#[ignore]" });
      if (status[1] === "PASS") passed.add(current);
      continue;
    }
    const header = line.match(/^\s*(stdout|stderr) ─/);
    if (header) {
      stream = header[1];
      continue;
    }
    if (current && stream === "stderr" && /\bskip(ped)?\b/i.test(line) && passed.has(current)) {
      if (!skipped.some((s) => s.name === current)) {
        const gate = gates.find((g) => g.tests.some((t) => nameMatches(current, t)));
        const env = line.match(/\b(SEALANTD_[A-Z_]+)\b/)?.[1];
        skipped.push({ name: current, gate: gate?.env ?? env ?? "unknown", reason: line.trim() });
      }
    }
  }
  return { skipped, passed };
};

// node --test's spec reporter marks a skip `﹣ name (1ms) # reason`; TAP marks it `# SKIP`.
export const nodeSkips = (output) => {
  const skipped = [];
  for (const line of output.split("\n")) {
    const spec = line.match(/﹣ (.+?) \([\d.]+m?s\)(?: # (.*))?\s*$/);
    const tap = line.match(/\bok \d+ - (.+?) # SKIP\b\s*(.*)$/);
    const hit = spec ?? tap;
    if (hit) skipped.push({ name: hit[1].trim(), gate: hit[2]?.trim() || "skip", reason: hit[2]?.trim() || undefined });
  }
  return skipped;
};

// Finds the `#[ignore = "…"]` reason above `fn <test>` in its crate.
const ignoreReason = (root, name) => {
  const [crate] = name.split(/::| /);
  const fn = name.split(/::| /).pop();
  try {
    const hits = git(root, "grep", "-n", "-B", "4", "-E", `fn ${fn}\\b`, "--", `crates/${crate}`);
    return hits.match(/#\[ignore = "([^"]*)"\]/)?.[1];
  } catch {
    return undefined;
  }
};

const onPathIn = (env) => (bin) => spawnSync("sh", ["-c", `command -v ${bin}`], { env }).status === 0;

// The crates the change touches and every workspace crate that depends on them, or "workspace".
export const rustScope = (files, packages, all) => {
  if (all || files.some((f) => matchesAny(f, RUST_WORKSPACE))) return "workspace";
  const byDir = new Map(packages.map((p) => [p.dir, p]));
  const touched = new Set();
  for (const f of files) {
    const dir = f.match(/^(crates\/[^/]+)\//)?.[1];
    if (dir && byDir.has(dir)) touched.add(byDir.get(dir).name);
  }
  let grew = true;
  while (grew) {
    grew = false;
    for (const p of packages) {
      if (!touched.has(p.name) && p.deps.some((d) => touched.has(d))) {
        touched.add(p.name);
        grew = true;
      }
    }
  }
  return [...touched].sort();
};

const workspacePackages = (root) => {
  const result = spawnSync("cargo", ["metadata", "--no-deps", "--format-version", "1", "--offline"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`cargo metadata failed: ${result.stderr}`);
  const meta = JSON.parse(result.stdout);
  const names = new Set(meta.packages.map((p) => p.name));
  return meta.packages.map((p) => ({
    name: p.name,
    dir: path.relative(root, path.dirname(p.manifest_path)),
    deps: p.dependencies.map((d) => d.name).filter((n) => names.has(n)),
    hasLib: p.targets.some((t) => t.kind.includes("lib")),
  }));
};

// The `node --test …` line from ci.yml's node job, so this runs exactly the list CI runs.
export const scriptTests = (root) => {
  const workflow = parse(readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8"));
  const run = workflow.jobs.node.steps.map((s) => s.run ?? "").find((r) => r.trim().startsWith("node --test"));
  if (!run) throw new Error("ci.yml's node job has no `node --test` step");
  return run.trim().split(/\s+/);
};

const runLogged = (root, argv, { env, log }) =>
  new Promise((resolve) => {
    const out = createWriteStream(path.join(root, log));
    out.write(`$ ${argv.join(" ")}\n`);
    const child = spawn(argv[0], argv.slice(1), { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
    let text = "";
    const take = (chunk) => {
      text += chunk;
      out.write(chunk);
    };
    child.stdout.on("data", take);
    child.stderr.on("data", take);
    child.on("error", (error) => {
      take(`${error.message}\n`);
      out.end(() => resolve({ code: 127, text }));
    });
    child.on("close", (code) => out.end(() => resolve({ code: code ?? 1, text })));
  });

export const check = async (root, { files, all, progress = () => {} }) => {
  mkdirSync(path.join(root, ".verify", "logs"), { recursive: true });
  const env = { ...process.env, CARGO_TERM_COLOR: "never", NO_COLOR: "1", FORCE_COLOR: "0" };
  // Set when `check` itself runs under `node --test`; inherited, it would make the suites check
  // runs report in the runner's child protocol instead of printing their skips.
  delete env.NODE_TEST_CONTEXT;
  const onPath = onPathIn(env);
  const steps = [];
  const next = [];
  const allowed = loadAllowedSkips();

  const touchesRust = all || files.some((f) => f.startsWith("crates/") || matchesAny(f, RUST_WORKSPACE));
  const touchesTs = all || files.some((f) => matchesAny(f, TYPESCRIPT));
  const touchesScripts = all || files.some((f) => matchesAny(f, SCRIPTS));

  const step = async (id, title, argv, { stepEnv = env, after } = {}) => {
    const log = `.verify/logs/check-${id}.log`;
    progress(`${title}: ${argv.join(" ")}`);
    const started = Date.now();
    const { code, text } = await runLogged(root, argv, { env: stepEnv, log });
    const result = {
      id,
      title,
      status: code === 0 ? "passed" : "failed",
      command: argv.join(" "),
      durationMs: Date.now() - started,
      log,
    };
    if (after) after(result, text);
    progress(`${title}: ${result.status}${result.detail ? ` (${result.detail})` : ""}`);
    steps.push(result);
    return result;
  };
  const notRun = (id, title, status, detail) => steps.push({ id, title, status, detail });

  // Rust: fmt, clippy, nextest and doc tests on the touched crates and their dependents.
  if (touchesRust) {
    const hasCargo = onPath("cargo");
    const hasNextest = hasCargo && spawnSync("cargo", ["nextest", "--version"], { env }).status === 0;
    if (!hasCargo) {
      for (const [id, title] of [
        ["fmt", "Rust format"],
        ["clippy", "Clippy"],
        ["nextest", "Rust tests"],
        ["doctests", "Rust doc tests"],
      ]) {
        notRun(id, title, "blocked_by_prerequisite", "cargo is not on PATH: install rustup, which reads rust-toolchain.toml");
      }
    } else {
      const packages = workspacePackages(root);
      const scope = rustScope(files, packages, all);
      const flags = scope === "workspace" ? ["--workspace"] : scope.flatMap((p) => ["-p", p]);
      const where = scope === "workspace" ? "the workspace" : scope.join(", ");
      await step("fmt", "Rust format", ["cargo", "fmt", "--all", "--check"]);
      if (scope.length === 0) {
        notRun("clippy", "Clippy", "passed", "no crate touched");
      } else {
        await step("clippy", "Clippy", ["cargo", "clippy", ...flags, "--all-targets", "--", "-D", "warnings"], {
          after: (r) => (r.detail = where),
        });
        if (!hasNextest) {
          notRun("nextest", "Rust tests", "blocked_by_prerequisite", "cargo-nextest is not installed");
          next.push("cargo install cargo-nextest --locked");
        } else {
          const gateEnv = { ...env };
          const unready = [];
          for (const gate of GATES) {
            if (gate.ready(onPath)) gateEnv[gate.env] = "1";
            else unready.push(gate);
          }
          await step(
            "nextest",
            "Rust tests",
            ["cargo", "nextest", "run", ...flags, "--no-fail-fast", "--status-level", "all", "--success-output", "immediate", "--color", "never"],
            {
              stepEnv: gateEnv,
              after: (r, text) => {
                const { skipped, passed } = nextestSkips(text, GATES);
                for (const gate of unready) {
                  for (const test of gate.tests.filter((t) => !t.includes("*") && passed.has(t))) {
                    if (!skipped.some((s) => s.name === test)) skipped.push({ name: test, gate: gate.env, reason: gate.unready });
                  }
                  if (gate.next) next.push(gate.next);
                }
                for (const s of skipped) if (s.gate === "#[ignore]") s.reason ??= ignoreReason(root, s.name);
                r.skipped = judgeSkips(skipped, allowed);
                const summary = text.match(/Summary \[[^\]]*\]\s+(.*)/)?.[1];
                r.detail = `${where}: ${summary ?? "no summary"}`;
                if (r.status === "passed" && r.skipped.some((s) => !s.allowed)) r.status = "skipped";
              },
            },
          );
        }
        const libs = scope === "workspace" ? ["--workspace"] : packages.filter((p) => scope.includes(p.name) && p.hasLib).flatMap((p) => ["-p", p.name]);
        if (libs.length === 0) notRun("doctests", "Rust doc tests", "passed", "no library crate touched");
        else await step("doctests", "Rust doc tests", ["cargo", "test", ...libs, "--doc"]);
      }
    }
  }

  // The repo's own scripts: exactly the list ci.yml's node job runs.
  if (touchesScripts) {
    await step("scripts", "Script tests", scriptTests(root), {
      after: (r, text) => {
        r.skipped = judgeSkips(nodeSkips(text), allowed);
        if (r.status === "passed" && r.skipped.some((s) => !s.allowed)) r.status = "skipped";
        r.detail = text.match(/ℹ pass (\d+)/) ? `${text.match(/ℹ pass (\d+)/)[1]} passed` : undefined;
      },
    });
  }

  // The TypeScript client: install, build, build the daemon its e2e spawns, test.
  if (touchesTs) {
    const install = await step("ts-install", "pnpm install", ["pnpm", "install", "--frozen-lockfile"]);
    const build = install.status === "passed" ? await step("ts-build", "TypeScript build", ["pnpm", "-r", "build"]) : null;
    const daemon = onPath("cargo")
      ? await step("daemon-build", "Daemon build for the e2e", ["cargo", "build", "--locked", "-p", "sealantd"])
      : notRun("daemon-build", "Daemon build for the e2e", "blocked_by_prerequisite", "cargo is not on PATH");
    if (build?.status === "passed" && daemon?.status === "passed") {
      await step("ts-test", "TypeScript tests", ["pnpm", "-r", "test"], {
        after: (r, text) => {
          r.skipped = judgeSkips(nodeSkips(text), allowed);
          if (r.status === "passed" && r.skipped.some((s) => !s.allowed)) r.status = "skipped";
        },
      });
    } else {
      notRun("ts-test", "TypeScript tests", steps.some((s) => s.status === "blocked_by_prerequisite") ? "blocked_by_prerequisite" : "failed", "not run: an earlier TypeScript step did not pass");
    }
  }

  if (steps.length === 0) notRun("scope", "Nothing to check", "passed", "the change touches no crate, package or script");
  for (const s of steps) if (s.skipped && s.skipped.length === 0) delete s.skipped;
  return {
    steps,
    evidence: steps.filter((s) => s.log).map((s) => ({ kind: "log", path: s.log })),
    next: [...new Set(next)],
  };
};
