import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Evaluator, Lexer, Parser, data } from "@actions/expressions";
import { truthy } from "@actions/expressions/result";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "ci-docs-only.sh");
const workflow = readFileSync(path.join(here, "../.github/workflows/ci.yml"), "utf8");

const git = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" }).trim();

const write = (root, file, content) => {
  mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  writeFileSync(path.join(root, file), content);
};

// A repository shaped like this one: a document code reads (as round_trip.rs reads ADR 0015), one
// it does not, and the files that sit beside them.
const fixture = (t) => {
  const root = mkdtempSync(path.join(tmpdir(), "ci-docs-only-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "user.name", "ci-docs-only test");
  git(root, "config", "user.email", "ci-docs-only@localhost");
  write(root, "docs/adr/0015-capture.md", "# ADR 0015\n");
  write(root, "docs/runtime/architecture.md", "# Architecture\n");
  write(root, "README.md", "# sealantd\n");
  write(root, ".changeset/config.json", "{}\n");
  write(root, "crates/capture/tests/adr.rs", 'const ADR: &str = "../../docs/adr/0015-capture.md";\n');
  git(root, "add", "-A");
  git(root, "commit", "-qm", "base");
  return { root, base: git(root, "rev-parse", "HEAD") };
};

const change = ({ root, base }, files) => {
  git(root, "checkout", "-q", "--detach", base);
  for (const file of files) write(root, file, `${file} changed\n`);
  git(root, "add", "-A");
  git(root, "commit", "-qm", files.join(" "));
  return git(root, "rev-parse", "HEAD");
};

// A git whose grep fails as an unreadable object or a broken index would (exit 128).
const failingGrep = (t) => {
  const bin = mkdtempSync(path.join(tmpdir(), "ci-docs-only-git-"));
  t.after(() => rmSync(bin, { recursive: true, force: true }));
  const real = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  writeFileSync(
    path.join(bin, "git"),
    `#!/bin/sh\nif [ "$1" = grep ]; then echo "fatal: injected" >&2; exit 128; fi\nexec ${real} "$@"\n`,
  );
  chmodSync(path.join(bin, "git"), 0o755);
  return `${bin}${path.delimiter}${process.env.PATH}`;
};

const scope = (root, env) => {
  const result = spawnSync("bash", [script], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, EVENT: "pull_request", ...env },
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};

test("documentation alone skips the Rust and Node jobs", (t) => {
  const repo = fixture(t);
  for (const files of [
    ["docs/runtime/architecture.md"],
    ["docs/runtime/new.md"],
    ["README.md", "AGENTS.md", ".changeset/a-note.md", "docs/runtime/architecture.md"],
  ]) {
    const head = change(repo, files);
    assert.equal(scope(repo.root, { BASE: repo.base, HEAD: head }), "code=false", files.join(" "));
  }
});

test("anything it cannot prove runs everything", (t) => {
  const repo = fixture(t);
  for (const files of [
    ["docs/adr/0015-capture.md"],
    ["docs/runtime/architecture.md", "crates/capture/src/lib.rs"],
    [".changeset/config.json"],
    ["plan.html"],
  ]) {
    const head = change(repo, files);
    assert.equal(scope(repo.root, { BASE: repo.base, HEAD: head }), "code=true", files.join(" "));
  }
  const head = change(repo, ["docs/runtime/architecture.md"]);
  assert.equal(scope(repo.root, { EVENT: "push", BASE: "", HEAD: head }), "code=true");
  assert.equal(scope(repo.root, { BASE: "a".repeat(40), HEAD: head }), "code=true");
  assert.equal(scope(repo.root, { BASE: repo.base, HEAD: repo.base }), "code=true");
});

test("a git grep that fails runs everything, not only one that finds the path", (t) => {
  const repo = fixture(t);
  const PATH = failingGrep(t);
  for (const files of [["docs/adr/0015-capture.md"], ["docs/runtime/architecture.md"]]) {
    const head = change(repo, files);
    assert.equal(scope(repo.root, { BASE: repo.base, HEAD: head, PATH }), "code=true", files[0]);
  }
});

// Each gated job's `if`, evaluated by GitHub's own expression library against the `changes` job's
// result and outputs. GitHub keeps a job's outputs when a later step fails, so only a `changes`
// job that succeeded may skip the others.
test("only a successful changes job can skip the Rust and Node jobs", () => {
  const value = (v) => {
    if (typeof v === "string") return new data.StringData(v);
    const dictionary = new data.Dictionary();
    for (const [key, entry] of Object.entries(v)) dictionary.add(key, value(entry));
    return dictionary;
  };
  const runs = (expression, { result, code, cancelled = false }) => {
    const functions = new Map([
      [
        "cancelled",
        { name: "cancelled", minArgs: 0, maxArgs: 0, call: () => new data.BooleanData(cancelled) },
      ],
    ]);
    const tree = new Parser(new Lexer(expression).lex().tokens, ["needs"], [...functions.values()]).parse();
    const context = value({ needs: { changes: { result, outputs: { code } } } });
    return truthy(new Evaluator(tree, context, functions).evaluate());
  };
  for (const job of ["rust", "rust-arm64", "node"]) {
    const match = workflow.match(new RegExp(`\\n  ${job}:\\n    needs: changes\\n    if: \\$\\{\\{ (.+) \\}\\}\\n`));
    assert.ok(match, `${job} needs changes and has an if`);
    const expression = match[1];
    assert.equal(runs(expression, { result: "success", code: "false" }), false, `${job}: docs only`);
    assert.equal(runs(expression, { result: "success", code: "true" }), true, `${job}: code`);
    assert.equal(runs(expression, { result: "success", code: "" }), true, `${job}: no output`);
    assert.equal(runs(expression, { result: "failure", code: "false" }), true, `${job}: failed, kept false`);
    assert.equal(runs(expression, { result: "failure", code: "" }), true, `${job}: failed, no output`);
    assert.equal(
      runs(expression, { result: "cancelled", code: "true", cancelled: true }),
      false,
      `${job}: cancelled`,
    );
  }
});
