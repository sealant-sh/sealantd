import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { GATES, judgeSkips, nextestSkips, nodeSkips, rustScope } from "./check.mjs";
import { ciSaysCode, loadMap, obligationsFor } from "./plan.mjs";
import { globToRegExp } from "./repo.mjs";
import { exitCode, rollUp, validate } from "./result.mjs";
import { resolve } from "./status.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../..");
const cli = path.join(here, "verify.mjs");

const run = (args, { root = repo, env = {} } = {}) => {
  const r = spawnSync(process.execPath, [cli, ...args, "--json"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, VERIFY_ROOT: root, ...env },
  });
  return { code: r.status, result: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
};

const git = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
const write = (root, file, content) => {
  mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  writeFileSync(path.join(root, file), content);
};

// A repository with CI's scoping script and a ci.yml whose node job runs `tests`.
const fixture = (t, tests) => {
  const root = mkdtempSync(path.join(tmpdir(), "verify-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.name", "verify test");
  git(root, "config", "user.email", "verify@localhost");
  write(root, "scripts/ci-docs-only.sh", readFileSync(path.join(repo, "scripts/ci-docs-only.sh"), "utf8"));
  write(
    root,
    ".github/workflows/ci.yml",
    `jobs:\n  changes:\n    steps: []\n  node:\n    if: \${{ needs.changes.outputs.code != 'false' }}\n    steps:\n      - run: node --test ${tests.join(" ")}\n`,
  );
  write(root, "README.md", "# fixture\n");
  git(root, "add", "-A");
  git(root, "commit", "-qm", "base");
  return root;
};

test("every verb's result matches the schema, with the exit code its status implies", (t) => {
  const root = fixture(t, ["scripts/a.test.mjs"]);
  write(root, "scripts/a.test.mjs", 'import test from "node:test";\ntest("ok", () => {});\n');
  for (const args of [
    ["plan", "--files", "crates/sealant-protocol/src/convert.rs"],
    ["status", "--files", "README.md"],
    ["formal"],
    ["db"],
  ]) {
    const { code, result } = run(args, { root });
    assert.deepEqual(validate(result), [], args.join(" "));
    assert.equal(code, exitCode(result.status), args.join(" "));
  }
  const { code, result } = run(["check", "--files", "scripts/a.test.mjs"], { root });
  assert.deepEqual(validate(result), []);
  assert.equal(result.status, "passed");
  assert.equal(code, 0);
});

test("a verb's status is its worst step's, in the spec's order", () => {
  assert.equal(rollUp(["passed", "skipped", "not_implemented"]), "skipped");
  assert.equal(rollUp(["skipped", "blocked_by_prerequisite", "passed"]), "blocked_by_prerequisite");
  assert.equal(rollUp(["evidence_withheld", "requires_external_observer"]), "requires_external_observer");
  assert.equal(rollUp(["passed", "failed", "blocked_by_prerequisite"]), "failed");
  assert.equal(rollUp([]), "passed");
  assert.deepEqual(
    ["passed", "failed", "blocked_by_prerequisite", "skipped", "not_implemented", "evidence_withheld"].map(exitCode),
    [0, 1, 3, 4, 4, 4],
  );
});

test("wrong usage exits 2 and prints no result", () => {
  for (const args of [["bogus"], ["plan", "--nope"]]) {
    const r = spawnSync(process.execPath, [cli, ...args, "--json"], { encoding: "utf8" });
    assert.equal(r.status, 2, args.join(" "));
    assert.equal(r.stdout, "");
  }
});

test("a suite that skips makes check skipped, not passed", (t) => {
  const root = fixture(t, ["scripts/gated.test.mjs"]);
  write(
    root,
    "scripts/gated.test.mjs",
    'import test from "node:test";\ntest("runs", () => {});\ntest("needs a database", { skip: "FIXTURE_DATABASE_URL is unset" }, () => {});\n',
  );
  const { code, result } = run(["check", "--files", "scripts/gated.test.mjs"], { root });
  const step = result.steps.find((s) => s.id === "scripts");
  assert.equal(step.status, "skipped");
  assert.deepEqual(step.skipped, [
    { name: "needs a database", gate: "FIXTURE_DATABASE_URL is unset", reason: "FIXTURE_DATABASE_URL is unset", allowed: false },
  ]);
  assert.equal(result.status, "skipped");
  assert.equal(code, 4);
});

test("Rust checks without cargo are blocked, not passed", (t) => {
  const root = fixture(t, []);
  // A PATH holding only what the tool needs besides cargo.
  const bin = mkdtempSync(path.join(tmpdir(), "verify-bin-"));
  t.after(() => rmSync(bin, { recursive: true, force: true }));
  for (const tool of ["git", "bash", "sh"]) {
    symlinkSync(execFileSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).trim(), path.join(bin, tool));
  }
  const { code, result } = run(["check", "--files", "crates/sealantd/src/main.rs"], { root, env: { PATH: bin } });
  assert.deepEqual(
    result.steps.map((s) => [s.id, s.status]),
    ["fmt", "clippy", "nextest", "doctests"].map((id) => [id, "blocked_by_prerequisite"]),
  );
  assert.equal(code, 3);
});

test("only an allowed skip with the same gate keeps a step passing", () => {
  const allowed = [{ test: "sealantd::run_as_user *", gate: "SEALANTD_REQUIRE_ROOT_TESTS", reason: "needs root" }];
  const judged = judgeSkips(
    [
      { name: "sealantd::run_as_user a_person_runs", gate: "SEALANTD_REQUIRE_ROOT_TESTS" },
      { name: "sealantd::run_as_user a_person_runs", gate: "SEALANTD_REQUIRE_DOTFILES_TOOLS" },
      { name: "sealantd::other a_test", gate: "SEALANTD_REQUIRE_ROOT_TESTS" },
    ],
    allowed,
  );
  assert.deepEqual(judged.map((s) => s.allowed), [true, false, false]);
});

test("nextest output yields ignored tests and passing tests that said they skipped", () => {
  const output = [
    "        SKIP [         ] (─/─) sealant-capture::restore_measure measures_a_restore",
    "        PASS [   0.008s] (3/5) sealantd::boot_privilege_posture a_boot_sets_it",
    "  stdout ───",
    "    test a_boot_sets_it ... ok",
    "  stderr ───",
    "    SEALANTD_REQUIRE_ROOT_TESTS is not 1: boot posture tests skipped",
    "",
    "        PASS [   0.010s] (4/5) sealantd boot::dotfiles::tests::stow_applies",
    "  stderr ───",
    "    SKIPPED: stow is not on PATH; the real stow apply was not exercised",
    "        PASS [   1.200s] (5/7) sealant-capture::owner_map captures_record_no_owner",
    "  stderr ───",
    "    not root: ownership tests skipped",
    "        PASS [   2.100s] (6/7) sealant-capture::delta head_over_base_writes_only_the_delta",
    "  stderr ───",
    "    base fresh: files written 426 (1717496 bytes), skipped 0 (0 bytes), removed 0",
    "        PASS [   0.010s] (7/7) sealantd boot::dotfiles::tests::skip_worktree_is_kept",
    "  stdout ───",
    "    test boot::dotfiles::tests::skip_worktree_is_kept ... ok",
  ].join("\n");
  assert.deepEqual(
    nextestSkips(output, GATES).skipped.map(({ name, gate }) => [name, gate]),
    [
      ["sealant-capture::restore_measure measures_a_restore", "#[ignore]"],
      ["sealantd::boot_privilege_posture a_boot_sets_it", "SEALANTD_REQUIRE_ROOT_TESTS"],
      ["sealantd boot::dotfiles::tests::stow_applies", "SEALANTD_REQUIRE_DOTFILES_TOOLS"],
      ["sealant-capture::owner_map captures_record_no_owner", "SEALANTD_REQUIRE_ROOT_TESTS"],
    ],
  );
});

test("node's spec and TAP reporters both yield their skips", () => {
  const spec = "✔ runs (0.4ms)\n﹣ gated (0.07ms) # needs FOO_URL\n✔ later (0.05ms) # TODO\n";
  const tap = "ok 1 - runs\nok 2 - gated # SKIP needs FOO_URL\n";
  for (const out of [spec, tap]) assert.deepEqual(nodeSkips(out), [{ name: "gated", gate: "needs FOO_URL", reason: "needs FOO_URL" }]);
});

test("globs: `**` crosses directories, `*` does not", () => {
  assert.ok(globToRegExp("crates/*/src/**").test("crates/sealantd/src/boot/mod.rs"));
  assert.ok(!globToRegExp("crates/*/src/**").test("crates/sealantd/tests/run_as_user.rs"));
  assert.ok(globToRegExp("packages/**").test("packages/runtime-client/package.json"));
  assert.ok(!globToRegExp("crates/*/Cargo.toml").test("crates/a/b/Cargo.toml"));
});

test("the map names what a change owes", () => {
  const owed = (...files) => obligationsFor(repo, loadMap(), files).map((o) => o.id);
  assert.deepEqual(owed("crates/sealant-protocol/src/convert.rs"), [
    "pre-pr-checks",
    "daemon-behaviour",
    "fuzz-decode-client",
    "fuzz-decode-server",
    "fuzz-decode-event",
  ]);
  assert.deepEqual(owed("fuzz/fuzz_targets/decode_event.rs"), ["pre-pr-checks", "fuzz-decode-event"]);
  assert.deepEqual(owed("crates/sealant-process/src/identity.rs"), ["pre-pr-checks", "daemon-behaviour", "root-only-tests"]);
  assert.deepEqual(owed("crates/sealant-protocol/proto/sealant.proto").includes("protocol-generated-typescript"), true);
  assert.deepEqual(owed("README.md", "AGENTS.md"), []);
  assert.deepEqual(owed(), []);
});

// The map does not copy CI's scoping: it runs CI's script. This holds the script's two inputs (a
// pull request's diff, and the file list `verify plan` passes) to one answer.
test("CI's scoping gives the same answer for a diff and for its file list", (t) => {
  const root = fixture(t, []);
  write(root, "docs/read.md", "# read\n");
  write(root, "crates/x/tests/doc.rs", 'const DOC: &str = "docs/read.md";\n');
  git(root, "add", "-A");
  git(root, "commit", "-qm", "docs");
  const base = git(root, "rev-parse", "HEAD");
  for (const files of [["README.md"], ["docs/read.md"], ["docs/new.md", "AGENTS.md"], ["crates/x/src/lib.rs"]]) {
    git(root, "checkout", "-q", "--detach", base);
    for (const f of files) write(root, f, `${f} changed\n`);
    git(root, "add", "-A");
    git(root, "commit", "-qm", files.join(" "));
    const diff = execFileSync("bash", ["scripts/ci-docs-only.sh"], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, EVENT: "pull_request", BASE: base, HEAD: git(root, "rev-parse", "HEAD") },
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    assert.equal(`code=${ciSaysCode(root, "scripts/ci-docs-only.sh", files)}`, diff, files.join(" "));
  }
  const { result } = run(["plan", "--files", "README.md"], { root });
  assert.deepEqual(result.ciJobs, ["changes"]);
  assert.deepEqual(run(["plan", "--files", "crates/x/src/lib.rs"], { root }).result.ciJobs, ["changes", "node"]);
});

test("a crate's change checks the crates that depend on it", () => {
  const packages = [
    { name: "proto", dir: "crates/proto", deps: [] },
    { name: "core", dir: "crates/core", deps: ["proto"] },
    { name: "daemon", dir: "crates/daemon", deps: ["core"] },
    { name: "fs", dir: "crates/fs", deps: [] },
  ];
  assert.deepEqual(rustScope(["crates/proto/src/lib.rs"], packages, false), ["core", "daemon", "proto"]);
  assert.deepEqual(rustScope(["crates/fs/src/lib.rs", "README.md"], packages, false), ["fs"]);
  assert.equal(rustScope(["Cargo.lock"], packages, false), "workspace");
  assert.equal(rustScope([], packages, true), "workspace");
});

test("status discharges an obligation only with a passing result for this commit on a clean tree", () => {
  const sha = "a".repeat(40);
  const owed = [{ id: "pre-pr-checks", kind: "tests", why: "w", status: "owed", command: "pnpm verify check" }];
  const result = (over) => ({ verb: "check", status: "passed", startedAt: "2026-11-14T22:00:00.000Z", head: { sha, dirty: false }, ...over });
  const statusOf = (latest, head = { sha, dirty: false }) => resolve(owed, new Map(latest ? [["check", latest]] : []), head);

  const done = statusOf(result());
  assert.equal(done.obligations[0].status, "discharged");
  assert.equal(done.obligations[0].evidence, ".verify/results/check-2026-11-14T22-00-00-000Z.json");
  assert.equal(done.steps[0].status, "passed");
  assert.equal(statusOf(result({ head: { sha: "b".repeat(40), dirty: false } })).obligations[0].status, "stale");
  assert.equal(statusOf(result({ head: { sha, dirty: true } })).obligations[0].status, "stale");
  assert.equal(statusOf(result(), { sha, dirty: true }).obligations[0].status, "stale");
  assert.equal(statusOf(result({ status: "failed" })).steps[0].status, "failed");
  assert.equal(statusOf(null).steps[0].status, "skipped");
});
