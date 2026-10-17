// release.yml's steps that decide what a stable release writes, run as written against stand-in
// docker commands and a stub GitHub API; and the job graph they sit in. Ported from sealant-sh/sealant
// tooling/scripts/release-publication.test.mjs (itself from sealant-sh/mend), for sealantd's one
// image, its identity checks and its ci check.
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { parse } from "yaml";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
const releaseText = readFileSync(path.join(root, ".github/workflows/release.yml"), "utf8");
const releaseDocument = parse(releaseText);
const releaseJobs = releaseDocument.jobs;

/** The `run:` of the named step in the named job, as GitHub hands it to bash. */
const stepRun = (job, name) => {
  const step = releaseJobs[job].steps.find((entry) => entry.name === name);
  assert.equal(typeof step?.run, "string", `release.yml ${job} has the step "${name}"`);
  return step.run;
};

const scratch = (t, prefix) => {
  const directory = mkdtempSync(path.join(tmpdir(), prefix));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};
const readCalls = (file) =>
  readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
const bashStep = (run, options) =>
  spawnSync("bash", ["--noprofile", "--norc", "-e", "-c", run], { encoding: "utf8", ...options });

const REPOSITORY = "ghcr.io/sealant-ci/sealantd";
const COMMIT = "f".repeat(40);
const PLATFORMS = {
  amd64: `sha256:${createHash("sha256").update("sealantd/amd64").digest("hex")}`,
  arm64: `sha256:${createHash("sha256").update("sealantd/arm64").digest("hex")}`,
};
/** An index's descriptor of `digest` for linux/<architecture>[/<variant>]. */
const child = (digest, architecture, variant) => ({
  mediaType: "application/vnd.oci.image.manifest.v1+json",
  digest,
  size: 1,
  platform: { os: "linux", architecture, ...(variant === undefined ? {} : { variant }) },
});
/** An index of `children`, as the registry serves it: its bytes and the digest it is read by. */
const indexDocument = (children) => {
  const bytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      manifests: children,
    }),
  );
  return { bytes, digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
};
/** The index merge staged: each arch's platform names that arch's build. */
const STAGED = indexDocument([child(PLATFORMS.amd64, "amd64"), child(PLATFORMS.arm64, "arm64")]);
const INDEX = STAGED.digest;
const manifestJson = (version, extra = {}) =>
  JSON.stringify({
    version,
    commit: COMMIT,
    images: { sealantd: { index: INDEX, platforms: PLATFORMS } },
    ...extra,
  });

// --- merge ---

test("merge stages the index under this run's own tag, never :<version>", (t) => {
  // Each build's digest arrives in a directory named for its arch, never merged into one, so the
  // index can be bound to the build each arch's job made; identity reads its own arch's the same way.
  const downloads = releaseJobs.merge.steps.filter((entry) =>
    entry.uses?.startsWith("actions/download-artifact@"),
  );
  assert.deepEqual(
    downloads.map((entry) => entry.with),
    [{ path: "/tmp/digests", pattern: "digests-sealantd--*" }],
  );
  assert.ok(
    releaseJobs.identity.steps.some(
      (entry) =>
        entry.uses?.startsWith("actions/download-artifact@") &&
        entry.with?.name === "digests-sealantd--${{ matrix.platform.arch }}",
    ),
  );
  const directory = scratch(t, "sealantd-merge-");
  const digests = path.join(directory, "digests");
  for (const name of ["bin", "digests", "tmp"]) mkdirSync(path.join(directory, name));
  const platforms = ["a1".repeat(32), "b2".repeat(32)];
  // One directory per build, named for its arch, as download-artifact lays them out.
  for (const [at, arch] of ["amd64", "arm64"].entries()) {
    mkdirSync(path.join(digests, `digests-sealantd--${arch}`));
    writeFileSync(path.join(digests, `digests-sealantd--${arch}`, platforms[at]), "");
  }
  const calls = path.join(directory, "calls.jsonl");
  writeFileSync(calls, "");
  writeFileSync(
    path.join(directory, "bin", "docker"),
    `#!${process.execPath}
const { appendFileSync, writeFileSync } = require("node:fs");
const args = process.argv.slice(2);
appendFileSync(${JSON.stringify(calls)}, JSON.stringify(args) + "\\n");
if (args[2] === "create" && args[3] === "--metadata-file") {
  if (process.env.FAIL_CREATE) process.exit(73);
  writeFileSync(args[4], "{}");
}
process.exit(args[2] === "inspect" && process.env.FAIL_INSPECT ? 74 : 0);
`,
  );
  chmodSync(path.join(directory, "bin", "docker"), 0o755);
  const run = (environment = {}) => {
    writeFileSync(calls, "");
    const step = stepRun("merge", "Stage the multi-arch index under this run's tag");
    const result = bashStep(step.replaceAll("/tmp/digests", digests), {
      env: {
        PATH: `${path.join(directory, "bin")}:${process.env.PATH}`,
        RUNNER_TEMP: path.join(directory, "tmp"),
        REPOSITORY,
        GITHUB_RUN_ID: "38923041738",
        GITHUB_RUN_ATTEMPT: "2",
        ...environment,
      },
    });
    return { ...result, calls: readCalls(calls) };
  };
  const staged = run();
  assert.equal(staged.status, 0, staged.stderr);
  assert.deepEqual(staged.calls, [
    [
      "buildx",
      "imagetools",
      "create",
      "--metadata-file",
      path.join(directory, "tmp", "index", "create.json"),
      "--tag",
      `${REPOSITORY}:staging-38923041738-2`,
      ...platforms.map((digest) => `${REPOSITORY}@sha256:${digest}`),
    ],
    ["buildx", "imagetools", "inspect", `${REPOSITORY}:staging-38923041738-2`],
  ]);
  for (const failure of [{ FAIL_CREATE: "1" }, { FAIL_INSPECT: "1" }])
    assert.notEqual(run(failure).status, 0, JSON.stringify(failure));
  // The sources go to create amd64 first, each from the artifact named for its arch; a stray or
  // missing file in either is refused before anything is pushed.
  writeFileSync(path.join(digests, "digests-sealantd--arm64", "latest"), "");
  const stray = run();
  assert.equal(stray.status, 1);
  assert.match(stray.stdout, /The arm64 digests artifact holds '.*latest.*', not one image digest/);
  assert.deepEqual(stray.calls, []);
  rmSync(path.join(digests, "digests-sealantd--arm64"), { recursive: true });
  const missing = run();
  assert.equal(missing.status, 1);
  assert.match(missing.stdout, /The arm64 digests artifact holds '\*', not one image digest/);
  assert.deepEqual(missing.calls, []);
});

// --- finalize-images ---

/**
 * finalize-images' step as written, against a stand-in docker over a registry held in a JSON file:
 * `tags` maps a reference to its digest, `unreadable` lists references whose read fails for a
 * reason other than not found, and `onCreate` says what a create does: `land` (the tag gets the
 * source's digest), `other` (another digest lands), `vanish` (the tag becomes unreadable), with an
 * optional exit code. `answers` replaces a reference's read with exact stdout, stderr and exit
 * (only its first read, with `once`).
 */
const finalize = (
  t,
  { tags = {}, unreadable = [], onCreate, manifest = {}, answers = {} } = {},
) => {
  const directory = scratch(t, "sealantd-finalize-");
  const bin = path.join(directory, "bin");
  mkdirSync(bin);
  const calls = path.join(directory, "calls.jsonl");
  const state = path.join(directory, "registry.json");
  writeFileSync(calls, "");
  writeFileSync(
    state,
    JSON.stringify({ tags, unreadable, onCreate: onCreate ?? { land: true }, answers }),
  );
  writeFileSync(
    path.join(bin, "docker"),
    `#!${process.execPath}
const { appendFileSync, readFileSync, writeFileSync } = require("node:fs");
const args = process.argv.slice(2);
appendFileSync(${JSON.stringify(calls)}, JSON.stringify(args) + "\\n");
const registry = JSON.parse(readFileSync(${JSON.stringify(state)}, "utf8"));
const save = () => writeFileSync(${JSON.stringify(state)}, JSON.stringify(registry));
if (args.slice(0, 3).join(" ") === "buildx imagetools inspect" && args[4] === "--format") {
  const ref = args[3];
  const answer = registry.answers[ref];
  if (answer !== undefined) {
    if (answer.once) {
      delete registry.answers[ref];
      save();
    }
    process.stdout.write(answer.stdout ?? "");
    process.stderr.write(answer.stderr ?? "");
    process.exit(answer.exit ?? 1);
  }
  if (registry.unreadable.includes(ref)) {
    console.error("ERROR: failed to do request: Head \\"https://ghcr.io/v2/x\\": unauthorized");
    process.exit(1);
  }
  if (!(ref in registry.tags)) { console.error("ERROR: " + ref + ": not found"); process.exit(1); }
  console.log(JSON.stringify({ mediaType: "application/vnd.oci.image.index.v1+json", digest: registry.tags[ref] }));
  process.exit(0);
}
if (args.slice(0, 4).join(" ") === "buildx imagetools create --tag" && args.length === 6) {
  const [target, source] = args.slice(4);
  const effect = registry.onCreate;
  if (effect.land) registry.tags[target] = source.split("@")[1];
  if (effect.other) registry.tags[target] = "sha256:" + "e".repeat(64);
  if (effect.vanish) registry.unreadable.push(target);
  save();
  process.exit(effect.exit ?? 0);
}
process.exit(79);
`,
  );
  chmodSync(path.join(bin, "docker"), 0o755);
  const file = path.join(directory, "release-manifest.json");
  writeFileSync(file, manifestJson("1.2.3", manifest));
  const result = bashStep(stepRun("finalize-images", "Publish the checked index as its version"), {
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      RUNNER_TEMP: directory,
      GITHUB_SHA: COMMIT,
      GITHUB_STEP_SUMMARY: path.join(directory, "summary.md"),
      REPOSITORY,
      MANIFEST: file,
      VERSION: "1.2.3",
    },
  });
  return {
    ...result,
    output: result.stdout + result.stderr,
    registry: JSON.parse(readFileSync(state, "utf8")),
    calls: readCalls(calls),
  };
};
const FINAL = `${REPOSITORY}:1.2.3`;
const FOREIGN = `sha256:${"e".repeat(64)}`;
const creates = (result) => result.calls.filter((args) => args[2] === "create");
const CREATE = ["buildx", "imagetools", "create", "--tag", FINAL, `${REPOSITORY}@${INDEX}`];

test("finalize reads :<version>, then creates it from the checked index when absent", (t) => {
  const result = finalize(t);
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(result.calls, [
    ["buildx", "imagetools", "inspect", FINAL, "--format", "{{json .Manifest}}"],
    CREATE,
    ["buildx", "imagetools", "inspect", FINAL, "--format", "{{json .Manifest}}"],
  ]);
  assert.deepEqual(result.registry.tags, { [FINAL]: INDEX });
});

test("finalize is done when :<version> already names this run's index: a rerun of failed jobs", (t) => {
  const result = finalize(t, { tags: { [FINAL]: INDEX } });
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(creates(result), []);
  assert.match(result.output, /is already this run's sha256:/);
});

test("finalize refuses a version that exists at another digest, writing nothing", (t) => {
  const result = finalize(t, { tags: { [FINAL]: FOREIGN } });
  assert.equal(result.status, 1);
  assert.match(
    result.output,
    /::error::.*sealantd:1\.2\.3 exists at sha256:e{64}.*is spent: cut a new one/,
  );
  assert.deepEqual(creates(result), []);
  assert.deepEqual(result.registry.tags, { [FINAL]: FOREIGN });
});

test("finalize fails without writing on a read that is not a not-found", (t) => {
  const result = finalize(t, { tags: { [FINAL]: FOREIGN }, unreadable: [FINAL] });
  assert.equal(result.status, 1);
  assert.match(result.output, /::error::Could not read .*sealantd:1\.2\.3; nothing was written/);
  assert.deepEqual(creates(result), []);
});

test("finalize reads absent only from buildx's sole not-found line, and fails on anything else", (t) => {
  for (const [label, answer] of [
    [
      "mixed lines",
      { stderr: `ERROR: ${FINAL}: not found\nERROR: unauthorized: authentication required\n` },
    ],
    ["an error before it", { stderr: `WARNING: retrying\nERROR: ${FINAL}: not found\n` }],
    ["a changed format", { stderr: `error: ${FINAL}: not found\n` }],
    ["another reference", { stderr: `ERROR: ${FINAL}-other: not found\n` }],
    ["leading space", { stderr: ` ERROR: ${FINAL}: not found\n` }],
    ["output beside it", { stdout: "{}\n", stderr: `ERROR: ${FINAL}: not found\n` }],
    ["a digest that is not one", { stdout: '{"digest":"latest"}\n', exit: 0 }],
    ["not JSON", { stdout: "not json\n", exit: 0 }],
  ]) {
    const result = finalize(t, { answers: { [FINAL]: answer } });
    assert.equal(result.status, 1, label);
    assert.match(
      result.output,
      /answered without a digest|Could not read .*sealantd:1\.2\.3; nothing was written/,
      label,
    );
    assert.deepEqual(creates(result), [], label);
  }
  // The exact sole line, however many trailing newlines, is absent: the tag is created.
  const result = finalize(t, {
    answers: { [FINAL]: { stderr: `ERROR: ${FINAL}: not found\n\n`, once: true } },
  });
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(creates(result), [CREATE]);
});

test("finalize: a create that reported an error but left this run's digest is a success", (t) => {
  const result = finalize(t, { onCreate: { land: true, exit: 1 } });
  assert.equal(result.status, 0, result.output);
  assert.match(
    result.output,
    /::warning::The create reported exit 1, but .*sealantd:1\.2\.3 resolves to sha256:/,
  );
  assert.deepEqual(result.registry.tags, { [FINAL]: INDEX });
});

test("finalize refuses when the tag shows another digest after its create", (t) => {
  const result = finalize(t, { onCreate: { other: true } });
  assert.equal(result.status, 1);
  assert.match(
    result.output,
    /sealantd:1\.2\.3 resolves to sha256:e{64} after the create.*is spent/,
  );
});

test("finalize fails when the tag is unreadable, or still absent, after its create", (t) => {
  const vanished = finalize(t, { onCreate: { vanish: true } });
  assert.equal(vanished.status, 1);
  assert.match(vanished.output, /sealantd:1\.2\.3 is unreadable after the create/);
  const missing = finalize(t, { onCreate: { exit: 1 } });
  assert.equal(missing.status, 1);
  assert.match(missing.output, /sealantd:1\.2\.3 does not exist after the create \(exit 1\)/);
});

test("finalize refuses another release's manifest or a missing index, writing nothing", (t) => {
  for (const manifest of [{ version: "1.2.2" }, { commit: "a".repeat(40) }, { images: {} }]) {
    const result = finalize(t, { manifest });
    assert.equal(result.status, 1, JSON.stringify(manifest));
    assert.deepEqual(result.calls, [], JSON.stringify(manifest));
  }
});

// --- identity ---

/**
 * The identity step as written, in a checkout holding `cargo` as Cargo.toml's workspace version,
 * against a stand-in docker. The registry serves `index` (the staged index by default) by its
 * digest, which the manifest records as the run's index; this arch's build job recorded `build`
 * (the manifest's platform digest by default). The pull of the digest the index maps this arch to
 * gives `id`; every later read must name that ID. The image answers `platform` and `labels`; a container of it runs `running` (by
 * default the image it was created from) and prints `reported`, exiting `exit`.
 */
const identity = (t, fixture = {}) => {
  const directory = scratch(t, "sealantd-identity-");
  const checkout = path.join(directory, "checkout");
  const bin = path.join(directory, "bin");
  for (const dir of [bin, path.join(checkout, "scripts")]) mkdirSync(dir, { recursive: true });
  copyFileSync(
    path.join(root, "scripts/release-manifest.mjs"),
    path.join(checkout, "scripts/release-manifest.mjs"),
  );
  const version = fixture.version ?? "1.2.3";
  writeFileSync(
    path.join(checkout, "Cargo.toml"),
    `[workspace]\nmembers = ["crates/*"]\n\n[workspace.package]\nversion = "${fixture.cargo ?? "0.0.0"}"\nedition = "2024"\n\n[workspace.lints.rust]\n`,
  );
  const arch = fixture.arch ?? "amd64";
  const id = fixture.id ?? `sha256:${"1".repeat(64)}`;
  const index = fixture.index ?? STAGED;
  const build = fixture.build ?? PLATFORMS[arch];
  const built = path.join(directory, "built");
  mkdirSync(built);
  writeFileSync(path.join(built, build.slice("sha256:".length)), "");
  writeFileSync(path.join(directory, "staged-index"), index.bytes);
  const state = {
    indexRef: `${REPOSITORY}@${index.digest}`,
    unreadableIndex: false,
    pulled: `${REPOSITORY}@${PLATFORMS[arch]}`,
    id,
    platform: `linux/${arch}`,
    labels: {
      "org.opencontainers.image.source": "https://github.com/sealant-sh/sealantd",
      "org.opencontainers.image.revision": COMMIT,
      "org.opencontainers.image.version": version,
    },
    reported: `sealantd ${fixture.cargo ?? "0.0.0"}`,
    exit: 0,
    ...fixture.docker,
  };
  const calls = path.join(directory, "calls.jsonl");
  writeFileSync(calls, "");
  writeFileSync(path.join(directory, "state.json"), JSON.stringify(state));
  writeFileSync(
    path.join(bin, "docker"),
    `#!${process.execPath}
const fs = require("node:fs");
const state = JSON.parse(fs.readFileSync(${JSON.stringify(path.join(directory, "state.json"))}, "utf8"));
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify(args) + "\\n");
const answer = (text) => { process.stdout.write(text + "\\n"); process.exit(0); };
if (args.slice(0, 3).join(" ") === "buildx imagetools inspect" && args[4] === "--raw") {
  if (args[3] !== state.indexRef || state.unreadableIndex) { console.error("ERROR: " + args[3] + ": not found"); process.exit(1); }
  process.stdout.write(fs.readFileSync(${JSON.stringify(path.join(directory, "staged-index"))}));
  process.exit(0);
}
if (args[0] === "pull") process.exit(args[1] === state.pulled ? 0 : 1);
if (args[0] === "image" && args[1] === "inspect" && args[3] === "--format") {
  if (args[4] === "{{.Id}}" && args[2] === state.pulled) answer(state.id);
  if (args[2] !== state.id) { console.error("Error: No such image: " + args[2]); process.exit(1); }
  if (args[4] === "{{.Os}}/{{.Architecture}}") answer(state.platform);
  if (args[4] === "{{json .Config.Labels}}") answer(JSON.stringify(state.labels));
}
if (args[0] === "create" && args[2] === "--version") {
  fs.writeFileSync(${JSON.stringify(path.join(directory, "container"))}, state.running ?? args[1]);
  answer("c0ntainer");
}
if (args[0] === "inspect" && args[1] === "c0ntainer" && args[3] === "{{.Image}}")
  answer(fs.readFileSync(${JSON.stringify(path.join(directory, "container"))}, "utf8"));
if (args[0] === "start" && args[1] === "--attach" && args[2] === "c0ntainer") {
  process.stdout.write(state.reported + "\\n");
  process.exit(state.exit);
}
if (args[0] === "rm" && args[1] === "c0ntainer") process.exit(0);
process.exit(79);
`,
  );
  chmodSync(path.join(bin, "docker"), 0o755);
  const file = path.join(directory, "release-manifest.json");
  writeFileSync(
    file,
    manifestJson(version, {
      images: { sealantd: { index: index.digest, platforms: PLATFORMS } },
    }),
  );
  const result = bashStep(stepRun("identity", "Check this arch's image is this release's"), {
    cwd: checkout,
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      RUNNER_ARCH: fixture.runner ?? (arch === "amd64" ? "X64" : "ARM64"),
      GITHUB_SHA: COMMIT,
      GITHUB_REPOSITORY: "sealant-sh/sealantd",
      REPOSITORY,
      MANIFEST: file,
      BUILT: built,
      RUNNER_TEMP: directory,
      VERSION: version,
      ARCH: arch,
    },
  });
  return { ...result, output: result.stdout + result.stderr, calls: readCalls(calls) };
};

test("identity pulls its own arch's digest from the manifest and runs exactly the ID it pulled", (t) => {
  for (const arch of ["amd64", "arm64"]) {
    const result = identity(t, { arch });
    assert.equal(result.status, 0, result.output);
    const id = `sha256:${"1".repeat(64)}`;
    assert.deepEqual(result.calls, [
      ["buildx", "imagetools", "inspect", `${REPOSITORY}@${INDEX}`, "--raw"],
      ["pull", `${REPOSITORY}@${PLATFORMS[arch]}`],
      ["image", "inspect", `${REPOSITORY}@${PLATFORMS[arch]}`, "--format", "{{.Id}}"],
      ["image", "inspect", id, "--format", "{{.Os}}/{{.Architecture}}"],
      ["image", "inspect", id, "--format", "{{json .Config.Labels}}"],
      ["create", id, "--version"],
      ["inspect", "c0ntainer", "--format", "{{.Image}}"],
      ["start", "--attach", "c0ntainer"],
      ["rm", "c0ntainer"],
    ]);
    assert.match(
      result.output,
      new RegExp(
        `${arch}: ${id} is 1\\.2\\.3 from f{40}, and its daemon reports 'sealantd 0\\.0\\.0'`,
      ),
    );
  }
  // Once the release flow stamps Cargo.toml with the version, the daemon must report it.
  const stamped = identity(t, { cargo: "1.2.3" });
  assert.equal(stamped.status, 0, stamped.output);
  assert.match(stamped.output, /reports 'sealantd 1\.2\.3'/);
});

test("identity resolves its arch through the index, and refuses an index that maps it to another build", (t) => {
  // Astra's round 1: the receipt records a swapped index whose amd64 and arm64 labels are
  // exchanged. No checkIndex runs here, as if it had been stubbed to pass; identity alone refuses.
  const swapped = indexDocument([child(PLATFORMS.amd64, "arm64"), child(PLATFORMS.arm64, "amd64")]);
  for (const arch of ["amd64", "arm64"]) {
    const result = identity(t, { arch, index: swapped });
    assert.equal(result.status, 1, `${arch}: ${result.output}`);
    const other = PLATFORMS[arch === "amd64" ? "arm64" : "amd64"];
    assert.match(
      result.output,
      new RegExp(
        `The index ${swapped.digest} maps linux/${arch} to ${other}; this arch's build is ${PLATFORMS[arch]}`,
      ),
    );
    // Nothing is pulled from a swapped index.
    assert.deepEqual(result.calls, [
      ["buildx", "imagetools", "inspect", `${REPOSITORY}@${swapped.digest}`, "--raw"],
    ]);
  }
  const other = `sha256:${"9".repeat(64)}`;
  for (const [label, fixture, problem] of [
    [
      "a build job that recorded another digest",
      { build: other },
      new RegExp(`maps linux/amd64 to ${PLATFORMS.amd64}; this arch's build is ${other}`),
    ],
    [
      "an index that maps the arch to another digest",
      { index: indexDocument([child(other, "amd64"), child(PLATFORMS.arm64, "arm64")]) },
      new RegExp(`maps linux/amd64 to ${other}; this arch's build is ${PLATFORMS.amd64}`),
    ],
    [
      "a duplicated platform",
      {
        index: indexDocument([
          child(PLATFORMS.amd64, "amd64"),
          child(PLATFORMS.arm64, "amd64"),
          child(PLATFORMS.arm64, "arm64"),
        ]),
      },
      /has 2 linux\/amd64 entries, not one/,
    ],
    [
      "a descriptor of the wrong variant",
      {
        arch: "arm64",
        index: indexDocument([
          child(PLATFORMS.amd64, "amd64"),
          child(PLATFORMS.arm64, "arm64", "v7"),
        ]),
      },
      /holds linux\/arm64\/v7/,
    ],
    ["an index the registry does not serve", { docker: { unreadableIndex: true } }, /not found/],
  ]) {
    const result = identity(t, fixture);
    assert.equal(result.status, 1, `${label}: ${result.output}`);
    assert.match(result.output, problem, label);
    assert.ok(
      result.calls.every(([command]) => command !== "pull"),
      `${label} pulls nothing`,
    );
  }
  // An index BuildKit wrote with arm64's v8 variant resolves.
  const v8 = indexDocument([
    child(PLATFORMS.amd64, "amd64"),
    child(PLATFORMS.arm64, "arm64", "v8"),
  ]);
  const resolved = identity(t, { arch: "arm64", index: v8 });
  assert.equal(resolved.status, 0, resolved.output);
});

test("identity refuses a wrong image ID, label, platform or --version, naming what it saw", (t) => {
  const other = `sha256:${"2".repeat(64)}`;
  for (const [label, fixture, problem] of [
    [
      "a container running another image",
      { docker: { running: other } },
      /The container runs sha256:2{64}, not sha256:1{64}, the image pulled by digest/,
    ],
    [
      "an ID that is not one",
      { docker: { id: "sealantd:latest" } },
      /pulled as 'sealantd:latest', not an image ID/,
    ],
    [
      "another version label",
      {
        docker: {
          labels: {
            "org.opencontainers.image.source": "https://github.com/sealant-sh/sealantd",
            "org.opencontainers.image.revision": COMMIT,
            "org.opencontainers.image.version": "1.2.2",
          },
        },
      },
      /its version label is '1\.2\.2', not 1\.2\.3/,
    ],
    [
      "no labels",
      { docker: { labels: null } },
      /its version label is '', not 1\.2\.3; its revision label is '', not f{40}; its source label is ''/,
    ],
    [
      "another commit",
      {
        docker: {
          labels: {
            "org.opencontainers.image.source": "https://github.com/sealant-sh/sealantd",
            "org.opencontainers.image.revision": "a".repeat(40),
            "org.opencontainers.image.version": "1.2.3",
          },
        },
      },
      /its revision label is 'a{40}', not f{40}/,
    ],
    [
      "another source",
      {
        docker: {
          labels: {
            "org.opencontainers.image.source": "https://github.com/someone/sealantd",
            "org.opencontainers.image.revision": COMMIT,
            "org.opencontainers.image.version": "1.2.3",
          },
        },
      },
      /its source label is 'https:\/\/github\.com\/someone\/sealantd'/,
    ],
    [
      "the other platform",
      { docker: { platform: "linux/arm64" } },
      /it is built for linux\/arm64, not linux\/amd64/,
    ],
    [
      "another --version",
      { docker: { reported: "sealantd 0.19.0" } },
      /exited 0 and reported 'sealantd 0\.19\.0', not 'sealantd 0\.0\.0'/,
    ],
    [
      "a --version that fails",
      { docker: { reported: "", exit: 127 } },
      /exited 127 and reported ''/,
    ],
    [
      "a stamped version the daemon does not report",
      { cargo: "1.2.3", docker: { reported: "sealantd 0.0.0" } },
      /reported 'sealantd 0\.0\.0', not 'sealantd 1\.2\.3'/,
    ],
    [
      "Cargo.toml stamped with another version",
      { cargo: "1.2.2" },
      /workspace version is '1\.2\.2', neither 0\.0\.0 nor 1\.2\.3/,
    ],
    [
      "a runner of the other arch",
      { runner: "ARM64" },
      /This arm64 runner was asked to check amd64/,
    ],
  ]) {
    const result = identity(t, fixture);
    assert.equal(result.status, 1, `${label}: ${result.output}`);
    assert.match(result.output, problem, label);
    assert.doesNotMatch(result.output, /and its daemon reports/, label);
  }
});

// --- the ci check ---

/** A GitHub API answering the ci runs list from `answers`, one per request (the last repeats). */
const githubRuns = async (t, answers) => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({ url: request.url, authorization: request.headers.authorization });
    const answer = answers[Math.min(requests.length, answers.length) - 1];
    response.writeHead(answer.status ?? 200, { "content-type": "application/json" });
    response.end(typeof answer.body === "string" ? answer.body : JSON.stringify(answer.body));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  return { url: `http://127.0.0.1:${server.address().port}`, requests };
};
const ciRun = (change = {}) => ({
  id: 4242,
  head_sha: COMMIT,
  event: "push",
  head_branch: "main",
  path: ".github/workflows/ci.yml",
  repository: { full_name: "sealant-sh/sealantd" },
  head_repository: { full_name: "sealant-sh/sealantd" },
  status: "completed",
  conclusion: "success",
  ...change,
});
const ciCheck = async (t, answers, environment = {}) => {
  const api = await githubRuns(t, answers);
  const child = spawn(
    "bash",
    [
      "--noprofile",
      "--norc",
      "-e",
      "-c",
      stepRun("stable-tag", "Refuse a commit whose ci did not pass on main"),
    ],
    {
      env: {
        PATH: process.env.PATH,
        GITHUB_API_URL: api.url,
        GITHUB_REPOSITORY: "sealant-sh/sealantd",
        GITHUB_SHA: COMMIT,
        GH_TOKEN: "test-token",
        RELEASE_TEST_RETRY_MS: "1",
        ...environment,
      },
    },
  );
  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));
  const status = await new Promise((done) => child.on("close", done));
  return { status, output, requests: api.requests };
};

test("the ci check passes a commit whose ci push run on main succeeded", async (t) => {
  const result = await ciCheck(t, [
    { body: { workflow_runs: [ciRun({ conclusion: "failure", id: 1 }), ciRun()] } },
  ]);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /ci run 4242 passed on main for f{40}/);
  assert.equal(result.requests.length, 1);
  const url = new URL(result.requests[0].url, "http://x");
  assert.equal(url.pathname, "/repos/sealant-sh/sealantd/actions/workflows/ci.yml/runs");
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    head_sha: COMMIT,
    event: "push",
    branch: "main",
    per_page: "100",
  });
  assert.equal(result.requests[0].authorization, "Bearer test-token");
});

test("the ci check refuses a commit with no passed ci push run on main", async (t) => {
  for (const [label, runs] of [
    ["no run", []],
    ["a failed run", [ciRun({ conclusion: "failure" })]],
    ["a cancelled run", [ciRun({ conclusion: "cancelled" })]],
    ["a run still going", [ciRun({ status: "in_progress", conclusion: null })]],
    ["a pull request's run", [ciRun({ event: "pull_request" })]],
    ["a run on another branch", [ciRun({ head_branch: "release-fix" })]],
    ["a fork's main", [ciRun({ head_repository: { full_name: "someone/sealantd" } })]],
    ["another workflow's run", [ciRun({ path: ".github/workflows/next.yml" })]],
    ["another commit's run", [ciRun({ head_sha: "a".repeat(40) })]],
  ]) {
    const result = await ciCheck(t, [{ body: { workflow_runs: runs } }]);
    assert.equal(result.status, 1, label);
    assert.match(result.output, /::error::No ci push run on main passed for f{40}/, label);
  }
});

test("the ci check retries a failed read, then fails: an unreadable answer is never no run", async (t) => {
  const recovered = await ciCheck(t, [
    { status: 502, body: {} },
    { body: { workflow_runs: [ciRun()] } },
  ]);
  assert.equal(recovered.status, 0, recovered.output);
  assert.equal(recovered.requests.length, 2);
  const down = await ciCheck(t, [{ status: 500, body: {} }]);
  assert.equal(down.status, 1);
  assert.match(down.output, /::error::GitHub answered 500 for the ci runs of f{40}/);
  assert.equal(down.requests.length, 4);
  for (const [label, body, problem] of [
    ["not JSON", "<html>", /not JSON/],
    ["no list", { total_count: 0 }, /no workflow_runs list/],
    ["a list that is not one", { workflow_runs: "none" }, /no workflow_runs list/],
  ]) {
    const result = await ciCheck(t, [{ body }]);
    assert.equal(result.status, 1, label);
    assert.match(result.output, problem, label);
  }
});

// --- the retry delays (sealant-sh/mend #1033) ---

const RETRY_MS = 1500;
const delaySteps = () => ({
  "ci check": stepRun("stable-tag", "Refuse a commit whose ci did not pass on main"),
});
const occurrences = (text, pattern) => text.match(new RegExp(pattern, "g"))?.length ?? 0;
const preambleOf = (run) => run.slice(0, run.indexOf("# shellcheck disable"));
const runPreamble = (run, environment) =>
  spawnSync("bash", ["--noprofile", "--norc", "-e", "-c", preambleOf(run)], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...environment },
  });

// release-overrides.test.mjs keeps every workflow from setting the override.
test("every retry waits the production delay by default", () => {
  const retry = `setTimeout(resolve, attempt * Number(process.env.RELEASE_TEST_RETRY_MS || ${RETRY_MS}))`;
  assert.equal(
    occurrences(releaseText, retry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    occurrences(releaseText, "setTimeout\\("),
  );
  assert.ok(occurrences(releaseText, "setTimeout\\(") >= 1);
  for (const run of Object.values(delaySteps()))
    assert.ok(run.includes(`echo "retry backoff: production (${RETRY_MS} ms × attempt)"`));
});

test("each step with retried reads logs the delay it runs with, once, before anything else", () => {
  for (const [name, run] of Object.entries(delaySteps())) {
    const production = runPreamble(run, {});
    assert.equal(production.status, 0, `${name}: ${production.stderr}`);
    assert.match(production.stdout, /^retry backoff: production \(1500 ms × attempt\)$/m, name);
    assert.equal(occurrences(production.stdout, "retry backoff"), 1, name);
    const overridden = runPreamble(run, { RELEASE_TEST_RETRY_MS: "7" });
    assert.equal(overridden.status, 0, `${name}: ${overridden.stderr}`);
    assert.match(overridden.stdout, /^retry backoff: overridden to 7 ms × attempt$/m, name);
    // A value that is not a number of milliseconds fails the step, and is not echoed.
    const garbage = runPreamble(run, { RELEASE_TEST_RETRY_MS: "1500; secret-token" });
    assert.notEqual(garbage.status, 0, name);
    assert.match(
      garbage.stdout,
      /RELEASE_TEST_RETRY_MS is not a whole number of milliseconds/,
      name,
    );
    assert.doesNotMatch(garbage.stdout + garbage.stderr, /secret-token/, name);
  }
});

test("the ci check, run whole, logs the production delay when no test overrides it", async (t) => {
  const result = await ciCheck(t, [{ body: { workflow_runs: [ciRun()] } }], {
    RELEASE_TEST_RETRY_MS: "",
  });
  assert.equal(result.status, 0, result.output);
  assert.equal(occurrences(result.output, "retry backoff: production \\(1500 ms × attempt\\)"), 1);
  assert.doesNotMatch(result.output, /overridden/);
});

// --- the graph ---

/** A job that publishes or writes: an environment, or any write permission. */
const writes = (definition) =>
  definition.environment !== undefined ||
  Object.values(definition.permissions ?? {}).some((level) => level === "write");
const CHANNEL = { group: "sealantd-release-channel", "cancel-in-progress": false, queue: "max" };
const CHANNEL_WRITERS = ["finalize-images", "npm"];

test("every channel writer queues on one release channel lock; nothing else holds it", () => {
  for (const [name, definition] of Object.entries(releaseJobs)) {
    if (CHANNEL_WRITERS.includes(name)) assert.deepEqual(definition.concurrency, CHANNEL, name);
    else assert.equal(definition.concurrency, undefined, name);
  }
  assert.equal(releaseDocument.concurrency, undefined, "the lock is per job, not per run");
  // Every job that writes is a channel writer, or a build or merge that writes only by digest or
  // to this run's staging tag.
  assert.deepEqual(
    Object.entries(releaseJobs)
      .filter(([, definition]) => writes(definition))
      .map(([name]) => name)
      .toSorted(),
    ["build", "finalize-images", "merge", "npm"],
  );
  assert.deepEqual(releaseDocument.permissions, { contents: "read" });
  // actionlint does not know `queue` yet: the ignore covers this file.
  assert.match(
    readFileSync(path.join(root, ".github/actionlint.yaml"), "utf8"),
    /\.github\/workflows\/release\.yml:\n\s+ignore:\n(?:\s+#.*\n)*\s+- 'unexpected key "queue" for "concurrency" section'/,
  );
});

test("only finalize writes :<version>, and nothing writes :latest or :X.Y", () => {
  const registryWrites = [];
  for (const [name, definition] of Object.entries(releaseJobs))
    for (const entry of definition.steps ?? []) {
      for (const line of (entry.run ?? "").replace(/\\\n\s*/g, " ").split("\n"))
        if (
          /imagetools create|docker push|docker tag|skopeo copy|crane |oras /.test(line) &&
          !/^\s*echo /.test(line)
        )
          registryWrites.push({ at: name, line: line.trim() });
      if (/push=true/.test(entry.with?.outputs ?? ""))
        registryWrites.push({ at: name, line: entry.with.outputs });
      // No metadata-action, which tagged :<version>, :X.Y and :latest together before any check.
      assert.doesNotMatch(entry.uses ?? "", /metadata-action/, name);
      assert.equal(entry.with?.tags, undefined, `${name} tags an image through an action`);
    }
  const tagged = (pattern) =>
    registryWrites.filter(({ line }) => pattern.test(line)).map(({ at }) => at);
  assert.deepEqual(tagged(/:\$VERSION"|\$ref"/), ["finalize-images"]);
  assert.deepEqual(tagged(/:\$tag"/), ["merge"]);
  assert.deepEqual(tagged(/latest|\$\{?(major|minor)|:\$\{?VERSION%/i), []);
  for (const { line } of registryWrites.filter(({ at }) => at === "build"))
    assert.match(line, /push-by-digest=true/);
  assert.deepEqual(registryWrites.map(({ at }) => at).toSorted(), [
    "build",
    "finalize-images",
    "merge",
  ]);
  // finalize's one target is $REPOSITORY:$VERSION.
  assert.match(
    stepRun("finalize-images", "Publish the checked index as its version"),
    /^ref=\$REPOSITORY:\$VERSION$/m,
  );
  // No step, environment or action input anywhere in the file names a :latest or :X.Y tag.
  const code = releaseText.replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(code, /:latest\b|type=raw,value=latest|major\}\}\.\{\{minor|pattern=\{\{/);
});

test("finalize waits for the identity checks on both arches, and npm for finalize", () => {
  const above = (name, seen = new Set()) => {
    for (const need of [releaseJobs[name].needs ?? []].flat())
      if (!seen.has(need)) above(need, seen.add(need));
    return seen;
  };
  assert.ok(releaseJobs["finalize-images"].needs.includes("identity"));
  for (const job of ["identity", "release-manifest", "merge", "build", "stable-tag"])
    assert.ok(above("finalize-images").has(job), job);
  assert.ok(releaseJobs.npm.needs.includes("finalize-images"));
  assert.ok(above("npm").has("identity"));
  // Both arches, each on its own native hosted runner.
  for (const name of ["build", "identity"])
    assert.deepEqual(releaseJobs[name].strategy.matrix.platform, [
      { arch: "amd64", runner: "ubuntu-24.04" },
      { arch: "arm64", runner: "ubuntu-24.04-arm" },
    ]);
  assert.equal(releaseJobs.identity.strategy["fail-fast"], false);
  // No job's `if` lets a publisher run after a job above it failed or was skipped.
  for (const name of ["finalize-images", "npm"])
    assert.equal(releaseJobs[name].if, undefined, name);
  // The ci check runs before anything builds, with the one extra permission it needs.
  assert.deepEqual(releaseJobs["stable-tag"].permissions, { contents: "read", actions: "read" });
  assert.deepEqual(releaseJobs.build.needs, "stable-tag");
  // Identity reads only: it pulls anonymously and logs in nowhere.
  assert.deepEqual(releaseJobs.identity.permissions, { contents: "read" });
  for (const entry of releaseJobs.identity.steps)
    assert.doesNotMatch(entry.uses ?? "", /login-action/);
});
