// next.yml's "Tag the multi-arch image" step, run as written, against a stand-in docker that keeps
// a one-tag registry in a file. The step may create the version tag only when the registry said
// exactly "not found", and the read after the create decides.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

/** The step's `run:` script, dedented, from next.yml as it is in this checkout. */
const step = (() => {
  const text = readFileSync(new URL("../.github/workflows/next.yml", import.meta.url), "utf8");
  const lines = text.split("\n");
  const name = lines.findIndex((line) => /^\s*- name: Tag the multi-arch image$/.test(line));
  assert.ok(name >= 0, "next.yml has the tag step");
  const run = lines.findIndex((line, index) => index > name && /^\s*run: \|$/.test(line));
  const indent = /^ */.exec(lines[run])[0].length;
  const body = [];
  for (const line of lines.slice(run + 1)) {
    if (line.trim() !== "" && /^ */.exec(line)[0].length <= indent) break;
    body.push(line.slice(indent + 2));
  }
  return body.join("\n");
})();

const REPOSITORY = "example.test/sealantd-next";
const VERSION = "1.2.3-next.4";
const REF = `${REPOSITORY}:${VERSION}`;
const SOURCES = ["b".repeat(64), "c".repeat(64)];
const FOREIGN = `sha256:${"a".repeat(64)}`;
const NOT_FOUND = `ERROR: ${REF}: not found`;

// Reads `inspect` answers from `$STATE/reads` (one JSON per read, in order; past the end, from the
// registry), and `create` behaves as `$STATE/create` says: "ok", "ok-other-metadata",
// "error-landed" or "error-absent".
const DOCKER = `#!/usr/bin/env node
const fs = require("node:fs");
const crypto = require("node:crypto");
const state = process.env.STATE;
const args = process.argv.slice(2);
fs.appendFileSync(state + "/commands", JSON.stringify(args) + "\\n");
const registry = () => JSON.parse(fs.readFileSync(state + "/registry", "utf8"));
const option = (name) => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
const index = (sources) => JSON.stringify({ schemaVersion: 2,
  mediaType: "application/vnd.oci.image.index.v1+json",
  manifests: sources.map((s) => ({ digest: s.split("@")[1] })) }, null, 2);
if (args[0] !== "buildx" || args[1] !== "imagetools") process.exit(99);
if (args[2] === "create") {
  const skip = new Set(["--tag", "--metadata-file"]);
  const sources = args.slice(3).filter((a, i, all) => !a.startsWith("--") && !skip.has(all[i - 1]));
  const bytes = index(sources);
  if (args.includes("--dry-run")) { process.stdout.write(bytes + "\\n"); process.exit(0); }
  const digest = "sha256:" + crypto.createHash("sha256").update(bytes).digest("hex");
  const mode = fs.readFileSync(state + "/create", "utf8");
  if (mode !== "error-absent") {
    const tags = registry(); tags[option("--tag")] = digest;
    fs.writeFileSync(state + "/registry", JSON.stringify(tags));
  }
  if (mode === "ok" || mode === "ok-other-metadata") {
    const reported = mode === "ok" ? digest : "sha256:" + "d".repeat(64);
    fs.writeFileSync(option("--metadata-file"), JSON.stringify({ "containerimage.descriptor": { digest: reported } }));
    process.exit(0);
  }
  console.error("ERROR: failed to push: unexpected status 502 Bad Gateway");
  process.exit(1);
}
if (args[2] === "inspect") {
  const reads = JSON.parse(fs.readFileSync(state + "/reads", "utf8"));
  const count = Number(fs.existsSync(state + "/read-count") ? fs.readFileSync(state + "/read-count", "utf8") : 0);
  fs.writeFileSync(state + "/read-count", String(count + 1));
  const scripted = reads[count];
  if (scripted !== undefined) {
    process.stdout.write(scripted.stdout ?? "");
    process.stderr.write(scripted.stderr ?? "");
    process.exit(scripted.status ?? 0);
  }
  const digest = registry()[args[3]];
  if (digest === undefined) { console.error("ERROR: " + args[3] + ": not found"); process.exit(1); }
  console.log(JSON.stringify({ schemaVersion: 2, digest }));
  process.exit(0);
}
process.exit(99);
`;

/** The index digest the stand-in creates from SOURCES, as the step computes it from the dry run. */
const INDEX = `sha256:${createHash("sha256")
  .update(
    JSON.stringify(
      {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: SOURCES.map((source) => ({ digest: `sha256:${source}` })),
      },
      null,
      2,
    ),
  )
  .digest("hex")}`;

/** Runs the step with the registry holding `tags`, scripted `reads`, and a `create` behaviour. */
const runStep = (t, { tags = {}, reads = [], create = "ok" } = {}) => {
  const dir = mkdtempSync(path.join(tmpdir(), "next-tag-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const sub of ["bin", "digests", "state", "temp"]) mkdirSync(path.join(dir, sub));
  for (const source of SOURCES) writeFileSync(path.join(dir, "digests", source), "");
  const state = path.join(dir, "state");
  writeFileSync(path.join(state, "registry"), JSON.stringify(tags));
  writeFileSync(path.join(state, "reads"), JSON.stringify(reads));
  writeFileSync(path.join(state, "create"), create);
  writeFileSync(path.join(dir, "bin", "docker"), DOCKER, { mode: 0o755 });
  const output = path.join(dir, "output");
  writeFileSync(output, "");
  const result = spawnSync("bash", ["--noprofile", "--norc", "-e", "-c", step], {
    cwd: path.join(dir, "digests"),
    encoding: "utf8",
    env: {
      PATH: `${path.join(dir, "bin")}:${process.env.PATH}`,
      STATE: state,
      REPOSITORY,
      VERSION,
      RUNNER_TEMP: path.join(dir, "temp"),
      GITHUB_OUTPUT: output,
    },
  });
  const commands = readFileSync(path.join(state, "commands"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  return {
    status: result.status,
    log: result.stdout + result.stderr,
    registry: JSON.parse(readFileSync(path.join(state, "registry"), "utf8")),
    creates: commands.filter((args) => args[2] === "create" && !args.includes("--dry-run")),
    output: existsSync(output) ? readFileSync(output, "utf8") : "",
  };
};

const failed = (stderr) => ({ status: 1, stderr });

test("the step extracted is the whole tag step", () => {
  assert.match(step, /^set -euo pipefail\n/);
  assert.match(step, /echo "digest=\$index" >>"\$GITHUB_OUTPUT"\s*$/);
});

test("exact not-found creates the tag from this run's index", (t) => {
  const run = runStep(t);
  assert.equal(run.status, 0, run.log);
  assert.equal(run.creates.length, 1);
  assert.deepEqual(run.creates[0].slice(-2), SOURCES.map((s) => `${REPOSITORY}@sha256:${s}`));
  assert.deepEqual(run.registry, { [REF]: INDEX });
  assert.equal(run.output, `digest=${INDEX}\n`);
});

test("not-found with extra trailing newlines is still absent", (t) => {
  const run = runStep(t, { reads: [failed(`${NOT_FOUND}\n\n\n`)] });
  assert.equal(run.status, 0, run.log);
  assert.equal(run.creates.length, 1);
  assert.deepEqual(run.registry, { [REF]: INDEX });
});

test("a tag already at this run's digest is done: no create", (t) => {
  const run = runStep(t, { tags: { [REF]: INDEX } });
  assert.equal(run.status, 0, run.log);
  assert.equal(run.creates.length, 0);
  assert.match(run.log, /is already this run's/);
  assert.equal(run.output, `digest=${INDEX}\n`);
});

test("a tag at another digest is refused: no create, nothing moves", (t) => {
  const run = runStep(t, { tags: { [REF]: FOREIGN } });
  assert.notEqual(run.status, 0);
  assert.equal(run.creates.length, 0);
  assert.deepEqual(run.registry, { [REF]: FOREIGN });
  assert.match(run.log, /exists at sha256:a{64}, not sha256:[0-9a-f]{64}.*spent/);
  assert.equal(run.output, "");
});

test("an authorization error fails: no create, the existing version stays", (t) => {
  const run = runStep(t, {
    tags: { [REF]: FOREIGN },
    reads: [failed("ERROR: failed to authorize: registry unavailable\n")],
  });
  assert.notEqual(run.status, 0);
  assert.equal(run.creates.length, 0);
  assert.deepEqual(run.registry, { [REF]: FOREIGN });
  assert.match(run.log, /failed to authorize/);
  assert.match(run.log, /unreadable; nothing was written/);
});

test("not-found beside another error line fails: no create", (t) => {
  for (const stderr of [
    `${NOT_FOUND}\nERROR: failed to authorize\n`,
    `WARNING: retrying\n${NOT_FOUND}\n`,
  ]) {
    const run = runStep(t, { reads: [failed(stderr)] });
    assert.notEqual(run.status, 0, stderr);
    assert.equal(run.creates.length, 0, stderr);
    assert.deepEqual(run.registry, {});
  }
});

test("a changed not-found format fails: no create", (t) => {
  for (const stderr of [
    `error: ${REF}: not found\n`,
    `ERROR: ${REF}: manifest unknown\n`,
    `ERROR: not found: ${REF}\n`,
    `ERROR: ${REPOSITORY}:other: not found\n`,
    ` ${NOT_FOUND}\n`,
    `${NOT_FOUND} `,
  ]) {
    const run = runStep(t, { reads: [failed(stderr)] });
    assert.notEqual(run.status, 0, stderr);
    assert.equal(run.creates.length, 0, stderr);
  }
});

test("not-found with something on stdout fails: no create", (t) => {
  const run = runStep(t, { reads: [{ status: 1, stdout: "{}\n", stderr: `${NOT_FOUND}\n` }] });
  assert.notEqual(run.status, 0);
  assert.equal(run.creates.length, 0);
});

test("a read that succeeds without a digest fails: no create", (t) => {
  for (const stdout of ["", "not json\n", "{}\n", '{"digest":"sha256:short"}\n']) {
    const run = runStep(t, { reads: [{ status: 0, stdout }] });
    assert.notEqual(run.status, 0, stdout);
    assert.equal(run.creates.length, 0, stdout);
    assert.match(run.log, /answered without a digest/);
  }
});

test("a create that errors but lands this run's digest passes with a warning", (t) => {
  const run = runStep(t, { create: "error-landed" });
  assert.equal(run.status, 0, run.log);
  assert.equal(run.creates.length, 1);
  assert.deepEqual(run.registry, { [REF]: INDEX });
  assert.match(run.log, /::warning::The create reported exit 1, but .* resolves to sha256:/);
  assert.equal(run.output, `digest=${INDEX}\n`);
});

test("a create that errors and leaves the tag absent fails", (t) => {
  const run = runStep(t, { create: "error-absent" });
  assert.notEqual(run.status, 0);
  assert.equal(run.creates.length, 1);
  assert.match(run.log, /does not exist after the create \(exit 1\)/);
  assert.equal(run.output, "");
});

test("a tag unreadable after the create fails", (t) => {
  const run = runStep(t, {
    reads: [failed(`${NOT_FOUND}\n`), failed("ERROR: 503 Service Unavailable\n")],
  });
  assert.notEqual(run.status, 0);
  assert.match(run.log, /unreadable after the create/);
  assert.equal(run.output, "");
});

test("a tag at another digest after the create fails", (t) => {
  const run = runStep(t, {
    reads: [failed(`${NOT_FOUND}\n`), { status: 0, stdout: JSON.stringify({ digest: FOREIGN }) }],
  });
  assert.notEqual(run.status, 0);
  assert.match(run.log, /resolves to sha256:a{64} after the create/);
  assert.equal(run.output, "");
});

test("a create that reports another digest than its dry run fails", (t) => {
  const run = runStep(t, { create: "ok-other-metadata" });
  assert.notEqual(run.status, 0);
  assert.match(run.log, /imagetools create reported 'sha256:d{64}', not sha256:/);
  assert.equal(run.output, "");
});
