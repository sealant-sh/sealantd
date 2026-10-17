// release.yml's steps that decide what a stable release writes, run as written against stand-in
// docker commands and a stub GitHub API; and the job graph they sit in, push and dry run. Ported from
// sealant-sh/sealant tooling/scripts/release-publication.test.mjs (itself from sealant-sh/mend), for
// sealantd's one image, its identity checks and its ci check. npm's step is release-npm.test.mjs's.
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
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
/** `descriptor` annotated as BuildKit annotates an attestation, whatever its platform says. */
const annotated = (descriptor) => ({
  ...descriptor,
  annotations: {
    "vnd.docker.reference.digest": descriptor.digest,
    "vnd.docker.reference.type": "attestation-manifest",
  },
});
/** A real BuildKit attestation of `digest`: annotated, and for unknown/unknown. */
const attestation = (digest) =>
  annotated({
    ...child(
      `sha256:${createHash("sha256").update(`attestation of ${digest}`).digest("hex")}`,
      "unknown",
    ),
    platform: { os: "unknown", architecture: "unknown" },
  });
/** Astra's round 2, and its variants: an attestation annotation on a runnable platform. */
const annotatedRunnable = () => {
  const astra = annotated(child(PLATFORMS.arm64, "amd64"));
  const plain = [child(PLATFORMS.amd64, "amd64"), child(PLATFORMS.arm64, "arm64")];
  return [
    ["Astra's annotated amd64 descriptor first", indexDocument([astra, ...plain])],
    ["the same descriptor last", indexDocument([...plain, astra])],
    [
      "an annotated descriptor of a runnable variant",
      indexDocument([...plain, annotated(child(`sha256:${"7".repeat(64)}`, "arm64", "v8"))]),
    ],
  ];
};
/** The index merge staged: each arch's platform names that arch's build. */
const STAGED = indexDocument([child(PLATFORMS.amd64, "amd64"), child(PLATFORMS.arm64, "arm64")]);
const INDEX = STAGED.digest;
const tarballRecord = (name, version) => {
  const digest = createHash("sha512").update(name).digest();
  return {
    file: `${name.slice(1).replace("/", "-")}-${version}.tgz`,
    sha512: digest.toString("hex"),
    integrity: `sha512-${digest.toString("base64")}`,
  };
};
const manifestJson = (version, extra = {}) =>
  JSON.stringify({
    version,
    commit: COMMIT,
    images: { sealantd: { index: INDEX, platforms: PLATFORMS } },
    packages: Object.fromEntries(
      ["@sealant/runtime-protocol", "@sealant/runtime-client"].map((name) => [
        name,
        tarballRecord(name, version),
      ]),
    ),
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
 * (only its first read, with `once`). The registry serves `index` (the staged index by default)
 * by its digest, which the manifest records as the run's index.
 */
const finalize = (
  t,
  { tags = {}, unreadable = [], onCreate, manifest = {}, answers = {}, index = STAGED } = {},
) => {
  const directory = scratch(t, "sealantd-finalize-");
  writeFileSync(path.join(directory, "staged-index"), index.bytes);
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
if (args.slice(0, 3).join(" ") === "buildx imagetools inspect" && args[4] === "--raw") {
  if (args[3] !== ${JSON.stringify(`${REPOSITORY}@`)} + ${JSON.stringify(index.digest)}) { console.error("ERROR: " + args[3] + ": not found"); process.exit(1); }
  process.stdout.write(readFileSync(${JSON.stringify(path.join(directory, "staged-index"))}));
  process.exit(0);
}
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
  writeFileSync(
    file,
    manifestJson("1.2.3", {
      images: { sealantd: { index: index.digest, platforms: PLATFORMS } },
      ...manifest,
    }),
  );
  const result = bashStep(stepRun("finalize-images", "Publish the checked index as its version"), {
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      GITHUB_WORKSPACE: root,
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
    ["buildx", "imagetools", "inspect", `${REPOSITORY}@${INDEX}`, "--raw"],
    ["buildx", "imagetools", "inspect", FINAL, "--format", "{{json .Manifest}}"],
    CREATE,
    ["buildx", "imagetools", "inspect", FINAL, "--format", "{{json .Manifest}}"],
  ]);
  assert.deepEqual(result.registry.tags, { [FINAL]: INDEX });
});

test("finalize binds the index's platforms again, and writes nothing for a swapped, duplicated or wrong-variant one", (t) => {
  // Each reaches finalize as if checkIndex and identity had been stubbed to pass: the manifest
  // records the bad index, and nothing before this step looked at it.
  for (const [label, index, problem] of [
    [
      "Astra's swapped labels",
      indexDocument([child(PLATFORMS.amd64, "arm64"), child(PLATFORMS.arm64, "amd64")]),
      new RegExp(`maps linux/amd64 to ${PLATFORMS.arm64}, not ${PLATFORMS.amd64}, the amd64 build`),
    ],
    [
      "a duplicated platform",
      indexDocument([
        child(PLATFORMS.amd64, "amd64"),
        child(PLATFORMS.arm64, "arm64"),
        child(FOREIGN, "amd64"),
      ]),
      /has 2 linux\/amd64 entries, not one/,
    ],
    [
      "a descriptor of the wrong variant",
      indexDocument([child(PLATFORMS.amd64, "amd64"), child(PLATFORMS.arm64, "arm64", "v7")]),
      /holds linux\/arm64\/v7/,
    ],
    [
      "another build under one platform",
      indexDocument([child(FOREIGN, "amd64"), child(PLATFORMS.arm64, "arm64")]),
      new RegExp(`maps linux/amd64 to ${FOREIGN}, not ${PLATFORMS.amd64}`),
    ],
    [
      "another build under arm64 alone",
      indexDocument([child(PLATFORMS.amd64, "amd64"), child(FOREIGN, "arm64")]),
      new RegExp(`maps linux/arm64 to ${FOREIGN}, not ${PLATFORMS.arm64}`),
    ],
  ]) {
    const result = finalize(t, { index });
    assert.equal(result.status, 1, `${label}: ${result.output}`);
    assert.match(result.output, problem, label);
    // Read, never written: not even :<version> is read before the binding passes.
    assert.deepEqual(
      result.calls,
      [["buildx", "imagetools", "inspect", `${REPOSITORY}@${index.digest}`, "--raw"]],
      label,
    );
    assert.deepEqual(result.registry.tags, {}, label);
  }
  // An index the registry cannot serve by the recorded digest writes nothing either.
  const unserved = finalize(t, {
    manifest: { images: { sealantd: { index: FOREIGN, platforms: PLATFORMS } } },
  });
  assert.equal(unserved.status, 1);
  assert.deepEqual(creates(unserved), []);
  // Astra's round 2: an attestation annotation on a runnable platform, first or last or a v8.
  for (const [label, index] of annotatedRunnable()) {
    const result = finalize(t, { index });
    assert.equal(result.status, 1, `${label}: ${result.output}`);
    assert.match(result.output, /annotated as an attestation for linux\//, label);
    assert.deepEqual(creates(result), [], label);
    assert.deepEqual(result.registry.tags, {}, label);
  }
  // A real BuildKit index, with its unknown/unknown attestations, is bound and tagged.
  const attested = indexDocument([
    child(PLATFORMS.amd64, "amd64"),
    attestation(PLATFORMS.amd64),
    child(PLATFORMS.arm64, "arm64"),
    attestation(PLATFORMS.arm64),
  ]);
  const withAttestations = finalize(t, { index: attested });
  assert.equal(withAttestations.status, 0, withAttestations.output);
  assert.deepEqual(withAttestations.registry.tags, { [FINAL]: attested.digest });
  // An arm64 build BuildKit labelled v8 is bound and tagged.
  const v8 = indexDocument([
    child(PLATFORMS.amd64, "amd64"),
    child(PLATFORMS.arm64, "arm64", "v8"),
  ]);
  const tagged = finalize(t, { index: v8 });
  assert.equal(tagged.status, 0, tagged.output);
  assert.deepEqual(tagged.registry.tags, { [FINAL]: v8.digest });
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
 * The identity job's pull and check steps as written, one after the other as the runner runs them,
 * in a checkout holding `cargo` as Cargo.toml's workspace version, against a stand-in docker. The
 * registry serves `index` (the staged index by default) by its digest, which the manifest records
 * as the run's index; this arch's build job recorded `build` (the manifest's platform digest by
 * default). The pull of the digest the index maps this arch to gives `id` (`recorded` replaces what
 * the pull wrote, as a load would); every later read must name that ID. A pull step that refuses
 * ends the job there, as on the runner. The image answers `platform` and `labels`; a container of it runs `running` (by
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
  const env = {
    PATH: `${bin}:${process.env.PATH}`,
    RUNNER_ARCH: fixture.runner ?? (arch === "amd64" ? "X64" : "ARM64"),
    RUNNER_TEMP: directory,
    GITHUB_SHA: COMMIT,
    GITHUB_REPOSITORY: "sealant-sh/sealantd",
    REPOSITORY,
    MANIFEST: file,
    BUILT: built,
    VERSION: version,
    ARCH: arch,
  };
  const pulled = bashStep(stepRun("identity", "Pull this run's image by digest"), {
    cwd: checkout,
    env,
  });
  if (pulled.status !== 0)
    return { ...pulled, output: pulled.stdout + pulled.stderr, calls: readCalls(calls) };
  if (fixture.recorded !== undefined)
    writeFileSync(path.join(directory, "image-id"), fixture.recorded);
  const result = bashStep(stepRun("identity", "Check this arch's image is this release's"), {
    cwd: checkout,
    env,
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
  // A dry run's label is its whole version; the daemon reports the X.Y.Z it stamps.
  const dry = identity(t, { version: "1.2.3-dryrun.9.1", cargo: "1.2.3" });
  assert.equal(dry.status, 0, dry.output);
  assert.match(
    dry.output,
    /is 1\.2\.3-dryrun\.9\.1 from f{40}, and its daemon reports 'sealantd 1\.2\.3'/,
  );
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
          child(FOREIGN, "amd64"),
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
  // An attestation annotation never hides a runnable descriptor from the binding.
  for (const [label, index] of annotatedRunnable())
    for (const arch of ["amd64", "arm64"]) {
      const result = identity(t, { arch, index });
      assert.equal(result.status, 1, `${label} ${arch}: ${result.output}`);
      assert.match(result.output, /annotated as an attestation for linux\//, `${label} ${arch}`);
      assert.ok(
        result.calls.every(([command]) => command !== "pull"),
        `${label} pulls nothing`,
      );
    }
  // A real BuildKit index, its attestations annotated and for unknown/unknown, resolves.
  const attested = indexDocument([
    child(PLATFORMS.amd64, "amd64"),
    attestation(PLATFORMS.amd64),
    child(PLATFORMS.arm64, "arm64"),
    attestation(PLATFORMS.arm64),
  ]);
  for (const arch of ["amd64", "arm64"]) {
    const result = identity(t, { arch, index: attested });
    assert.equal(result.status, 0, `${arch}: ${result.output}`);
  }
});

test("identity refuses a wrong image ID, label, platform or --version, naming what it saw", (t) => {
  const other = `sha256:${"2".repeat(64)}`;
  for (const [label, fixture, problem] of [
    [
      "a container running another image",
      { docker: { running: other } },
      /The container runs sha256:2{64}, not sha256:1{64}, the image pulled or loaded/,
    ],
    [
      "an ID that is not one",
      { docker: { id: "sealantd:latest" } },
      /This job pulled or loaded 'sealantd:latest', not an image ID/,
    ],
    [
      "an ID recorded with something after it",
      { recorded: `sha256:${"1".repeat(64)} sha256:${"2".repeat(64)}\n` },
      /not an image ID/,
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
  const summary = path.join(scratch(t, "sealantd-ci-check-"), "summary.md");
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
        GITHUB_EVENT_NAME: "push",
        VERSION: "1.2.3",
        TARGET: "ghcr",
        GITHUB_STEP_SUMMARY: summary,
        ...environment,
      },
    },
  );
  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));
  const status = await new Promise((done) => child.on("close", done));
  return {
    status,
    output,
    requests: api.requests,
    summary: existsSync(summary) ? readFileSync(summary, "utf8") : "",
  };
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

// --- the ci check in a dry run ---

test("a dry run reports a commit without a passed ci run, and still fails on a read that fails", async (t) => {
  const dry = {
    GITHUB_EVENT_NAME: "workflow_dispatch",
    VERSION: "1.2.3-dryrun.38700000001.1",
    TARGET: "archive",
  };
  const reported = await ciCheck(
    t,
    [{ body: { workflow_runs: [ciRun({ conclusion: "failure" })] } }],
    dry,
  );
  assert.equal(reported.status, 0, reported.output);
  assert.match(reported.output, /^::warning::No ci push run on main passed for f{40}/m);
  assert.doesNotMatch(reported.output, /::error::/);
  assert.match(reported.summary, /^A release would refuse:$/m);
  // A passed run is reported as passed, with no warning.
  const passed = await ciCheck(t, [{ body: { workflow_runs: [ciRun()] } }], dry);
  assert.equal(passed.status, 0, passed.output);
  assert.doesNotMatch(passed.output, /::warning::/);
  assert.equal(passed.summary, "");
  // A read that fails gives no verdict to report: the dry run fails too.
  const down = await ciCheck(t, [{ status: 500, body: {} }], dry);
  assert.equal(down.status, 1);
  assert.match(down.output, /::error::GitHub answered 500/);
  // Only a dispatch building to archives with a derived dry-run version reports.
  for (const [label, change] of [
    ["to GHCR", { TARGET: "ghcr" }],
    ["a release version", { VERSION: "1.2.3" }],
    ["a dry-run version of run 0", { VERSION: "1.2.3-dryrun.0.1" }],
    ["a dry-run version without its attempt", { VERSION: "1.2.3-dryrun.9" }],
    ["a prerelease", { VERSION: "1.2.3-next.4" }],
  ]) {
    const refused = await ciCheck(t, [{ body: { workflow_runs: [] } }], { ...dry, ...change });
    assert.equal(refused.status, 1, label);
    assert.match(refused.output, /::error::A dispatch is a dry run/, label);
    assert.equal(refused.requests.length, 0, label);
  }
  // A push never reports, whatever its target or version say.
  const push = await ciCheck(t, [{ body: { workflow_runs: [] } }], {
    TARGET: "archive",
    VERSION: "1.2.3-dryrun.9.1",
  });
  assert.equal(push.status, 1);
  assert.match(push.output, /::error::No ci push run on main passed/);
  assert.equal(push.summary, "");
  // The step reads the resolved version and target, and is the only route to a report.
  const step = releaseJobs["stable-tag"].steps.find(
    (entry) => entry.name === "Refuse a commit whose ci did not pass on main",
  );
  assert.equal(step.env.VERSION, "${{ steps.resolve.outputs.version }}");
  assert.equal(step.env.TARGET, "${{ steps.resolve.outputs.target }}");
  assert.equal(releaseText.match(/verdict=report/g).length, 1);
});

// --- the retry delays (sealant-sh/mend #1033) ---

const RETRY_MS = 1500;
/** Each step with retried reads, and the text its delay preamble ends before. */
const delaySteps = () => ({
  "ci check": [
    stepRun("stable-tag", "Refuse a commit whose ci did not pass on main"),
    "verdict=refuse",
  ],
  npm: [stepRun("npm", "Publish to npm"), "# --- floor ---"],
});
const occurrences = (text, pattern) => text.match(new RegExp(pattern, "g"))?.length ?? 0;
const runPreamble = ([run, end], environment) =>
  spawnSync("bash", ["--noprofile", "--norc", "-e", "-c", run.slice(0, run.indexOf(end))], {
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
  assert.ok(occurrences(releaseText, "setTimeout\\(") >= 2);
  for (const [run] of Object.values(delaySteps()))
    assert.ok(run.includes(`echo "retry backoff: production (${RETRY_MS} ms × attempt)"`));
});

test("each step with retried reads logs the delay it runs with, once, before anything else", () => {
  for (const [name, step] of Object.entries(delaySteps())) {
    const production = runPreamble(step, {});
    assert.equal(production.status, 0, `${name}: ${production.stderr}`);
    assert.match(production.stdout, /^retry backoff: production \(1500 ms × attempt\)$/m, name);
    assert.equal(occurrences(production.stdout, "retry backoff"), 1, name);
    const overridden = runPreamble(step, { RELEASE_TEST_RETRY_MS: "7" });
    assert.equal(overridden.status, 0, `${name}: ${overridden.stderr}`);
    assert.match(overridden.stdout, /^retry backoff: overridden to 7 ms × attempt$/m, name);
    // A value that is not a number of milliseconds fails the step, and is not echoed.
    const garbage = runPreamble(step, { RELEASE_TEST_RETRY_MS: "1500; secret-token" });
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
const PUBLISHERS = ["finalize-images", "npm"];

test("every channel writer queues on one release channel lock; nothing else holds it", () => {
  for (const [name, definition] of Object.entries(releaseJobs)) {
    if (PUBLISHERS.includes(name)) assert.deepEqual(definition.concurrency, CHANNEL, name);
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

test("only finalize writes :<version> to GHCR, and nothing writes :latest or :X.Y", () => {
  const registryWrites = [];
  for (const [name, definition] of Object.entries(releaseJobs))
    for (const entry of definition.steps ?? []) {
      for (const line of (entry.run ?? "").replace(/\\\n\s*/g, " ").split("\n"))
        if (
          /imagetools create|docker push|docker tag|skopeo copy|crane |oras /.test(line) &&
          !/^\s*echo /.test(line)
        )
          registryWrites.push({ at: name, line: line.trim(), entry });
      if (/push=true/.test(entry.with?.outputs ?? ""))
        registryWrites.push({ at: name, line: entry.with.outputs });
      // No metadata-action, which tagged :<version>, :X.Y and :latest together before any check.
      assert.doesNotMatch(entry.uses ?? "", /metadata-action/, name);
      assert.equal(entry.with?.tags, undefined, `${name} tags an image through an action`);
    }
  // archive-merge writes only to the registry it starts on loopback, inside the job.
  const loopback = registryWrites.filter(({ at }) => at === "archive-merge");
  assert.ok(loopback.length >= 2);
  for (const { entry } of loopback) assert.equal(entry.env.REPOSITORY, "127.0.0.1:5000/sealantd");
  for (const name of ["archive-build", "archive-merge"]) {
    assert.deepEqual(releaseJobs[name].permissions, { contents: "read" }, name);
    for (const step of releaseJobs[name].steps)
      assert.doesNotMatch(step.uses ?? "", /login-action/, name);
  }
  assert.match(
    releaseJobs["archive-build"].steps.find((step) => step.id === "build").with.outputs,
    /^type=docker,dest=/,
  );
  const ghcr = registryWrites.filter(({ at }) => at !== "archive-merge");
  const tagged = (pattern) => ghcr.filter(({ line }) => pattern.test(line)).map(({ at }) => at);
  assert.deepEqual(tagged(/:\$VERSION"|\$ref"/), ["finalize-images"]);
  assert.deepEqual(tagged(/:\$tag"/), ["merge"]);
  assert.deepEqual(tagged(/latest|\$\{?(major|minor)|:\$\{?VERSION%/i), []);
  for (const { line } of ghcr.filter(({ at }) => at === "build"))
    assert.match(line, /push-by-digest=true/);
  assert.deepEqual(ghcr.map(({ at }) => at).toSorted(), ["build", "finalize-images", "merge"]);
  // finalize's one target is $REPOSITORY:$VERSION.
  assert.match(
    stepRun("finalize-images", "Publish the checked index as its version"),
    /^ref=\$REPOSITORY:\$VERSION$/m,
  );
  // No step, environment or action input anywhere in the file names a :latest or :X.Y tag.
  const code = releaseText.replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(code, /:latest\b|type=raw,value=latest|major\}\}\.\{\{minor|pattern=\{\{/);
});

// --- every image a publishing workflow runs, by digest ---

/** A reference pinned by its sha256 digest, with or without a tag (a registry port is allowed). */
const PINNED = /^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$/;
/** A word shaped like an image reference that names a registry path or a tag (so `:` or `/`). */
const IMAGE_LIKE =
  /^(?=.*[:/])[a-z0-9][a-z0-9._-]*(:[0-9]+)?(\/[a-z0-9][a-z0-9._-]*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$/;

// docker's options, from the Docker CLI's own help, client 29.8.1 (API 1.56): `docker --help`
// (Global Options), `docker run --help`, `docker create --help` and `docker pull --help`; `docker
// container run`, `docker container create` and `docker image pull` are their aliases and print the
// same options (https://docs.docker.com/reference/cli/docker/container/run/,
// …/container/create/, …/image/pull/). An option shown with a type (`--stop-timeout int`) takes a
// value; one without is a flag. Options the help hides (`--net`, deprecated ones) are not here, so
// they fail the scan as unknown rather than be guessed at. Regenerate from a newer CLI's help.
const DOCKER_OPTIONS = {
  global: {
    flags: new Set(["-D", "--debug", "--tls", "--tlsverify", "-v", "--version"]),
    values: new Set([
      "--config",
      "-c",
      "--context",
      "-H",
      "--host",
      "-l",
      "--log-level",
      "--tlscacert",
      "--tlscert",
      "--tlskey",
    ]),
  },
  run: {
    flags: new Set([
      "-d",
      "--detach",
      "--help",
      "--init",
      "-i",
      "--interactive",
      "--no-healthcheck",
      "--oom-kill-disable",
      "--privileged",
      "-P",
      "--publish-all",
      "-q",
      "--quiet",
      "--read-only",
      "--rm",
      "--sig-proxy",
      "-t",
      "--tty",
      "--use-api-socket",
    ]),
    values: new Set([
      "--add-host",
      "--annotation",
      "-a",
      "--attach",
      "--blkio-weight",
      "--blkio-weight-device",
      "--cap-add",
      "--cap-drop",
      "--cgroup-parent",
      "--cgroupns",
      "--cidfile",
      "--cpu-period",
      "--cpu-quota",
      "--cpu-rt-period",
      "--cpu-rt-runtime",
      "-c",
      "--cpu-shares",
      "--cpus",
      "--cpuset-cpus",
      "--cpuset-mems",
      "--detach-keys",
      "--device",
      "--device-cgroup-rule",
      "--device-read-bps",
      "--device-read-iops",
      "--device-write-bps",
      "--device-write-iops",
      "--dns",
      "--dns-option",
      "--dns-search",
      "--domainname",
      "--entrypoint",
      "-e",
      "--env",
      "--env-file",
      "--expose",
      "--gpus",
      "--group-add",
      "--health-cmd",
      "--health-interval",
      "--health-retries",
      "--health-start-interval",
      "--health-start-period",
      "--health-timeout",
      "-h",
      "--hostname",
      "--ip",
      "--ip6",
      "--ipc",
      "--isolation",
      "-l",
      "--label",
      "--label-file",
      "--link",
      "--link-local-ip",
      "--log-driver",
      "--log-opt",
      "--mac-address",
      "-m",
      "--memory",
      "--memory-reservation",
      "--memory-swap",
      "--memory-swappiness",
      "--mount",
      "--name",
      "--network",
      "--network-alias",
      "--oom-score-adj",
      "--pid",
      "--pids-limit",
      "--platform",
      "-p",
      "--publish",
      "--pull",
      "--restart",
      "--runtime",
      "--security-opt",
      "--shm-size",
      "--stop-signal",
      "--stop-timeout",
      "--storage-opt",
      "--sysctl",
      "--tmpfs",
      "--ulimit",
      "--umask",
      "-u",
      "--user",
      "--userns",
      "--uts",
      "-v",
      "--volume",
      "--volume-driver",
      "--volumes-from",
      "-w",
      "--workdir",
    ]),
  },
  create: {
    flags: new Set([
      "--help",
      "--init",
      "-i",
      "--interactive",
      "--no-healthcheck",
      "--oom-kill-disable",
      "--privileged",
      "-P",
      "--publish-all",
      "-q",
      "--quiet",
      "--read-only",
      "--rm",
      "-t",
      "--tty",
      "--use-api-socket",
    ]),
    values: new Set([
      "--add-host",
      "--annotation",
      "-a",
      "--attach",
      "--blkio-weight",
      "--blkio-weight-device",
      "--cap-add",
      "--cap-drop",
      "--cgroup-parent",
      "--cgroupns",
      "--cidfile",
      "--cpu-period",
      "--cpu-quota",
      "--cpu-rt-period",
      "--cpu-rt-runtime",
      "-c",
      "--cpu-shares",
      "--cpus",
      "--cpuset-cpus",
      "--cpuset-mems",
      "--device",
      "--device-cgroup-rule",
      "--device-read-bps",
      "--device-read-iops",
      "--device-write-bps",
      "--device-write-iops",
      "--dns",
      "--dns-option",
      "--dns-search",
      "--domainname",
      "--entrypoint",
      "-e",
      "--env",
      "--env-file",
      "--expose",
      "--gpus",
      "--group-add",
      "--health-cmd",
      "--health-interval",
      "--health-retries",
      "--health-start-interval",
      "--health-start-period",
      "--health-timeout",
      "-h",
      "--hostname",
      "--ip",
      "--ip6",
      "--ipc",
      "--isolation",
      "-l",
      "--label",
      "--label-file",
      "--link",
      "--link-local-ip",
      "--log-driver",
      "--log-opt",
      "--mac-address",
      "-m",
      "--memory",
      "--memory-reservation",
      "--memory-swap",
      "--memory-swappiness",
      "--mount",
      "--name",
      "--network",
      "--network-alias",
      "--oom-score-adj",
      "--pid",
      "--pids-limit",
      "--platform",
      "-p",
      "--publish",
      "--pull",
      "--restart",
      "--runtime",
      "--security-opt",
      "--shm-size",
      "--stop-signal",
      "--stop-timeout",
      "--storage-opt",
      "--sysctl",
      "--tmpfs",
      "--ulimit",
      "--umask",
      "-u",
      "--user",
      "--userns",
      "--uts",
      "-v",
      "--volume",
      "--volume-driver",
      "--volumes-from",
      "-w",
      "--workdir",
    ]),
  },
  pull: { flags: new Set(["-a", "--all-tags", "-q", "--quiet"]), values: new Set(["--platform"]) },
};
/** The docker subcommands that start or fetch an image, by the words that name them. */
const IMAGE_COMMANDS = [
  [["container", "run"], "run"],
  [["container", "create"], "create"],
  [["image", "pull"], "pull"],
  [["run"], "run"],
  [["create"], "create"],
  [["pull"], "pull"],
];

/**
 * A run: block lexed as Bash would split it into commands of words, enough to find docker's
 * arguments: single quotes, double quotes (a `$VAR` inside stays part of its word) and backslash
 * escapes never split a word; a backslash-newline joins lines; `#` at a word's start comments to the
 * line's end; newlines, `;`, `&`, `|`, `(`, `)`, `<` and `>` end a command. Each word is {text,
 * dynamic}: dynamic when the shell expands something in it (`$`, `$(…)`, backticks). The body of each
 * command substitution is lexed too, as its own commands.
 */
const lexShell = (source) => {
  const commands = [[]];
  let word = null;
  const add = (text, dynamic = false) => {
    word ??= { text: "", dynamic: false };
    word.text += text;
    word.dynamic ||= dynamic;
  };
  const endWord = () => {
    if (word !== null) commands.at(-1).push(word);
    word = null;
  };
  const endCommand = () => {
    endWord();
    if (commands.at(-1).length > 0) commands.push([]);
  };
  /** The body of the `$(` whose body starts at `from`, and the index past its `)`. */
  const substitution = (from) => {
    let depth = 1;
    let quote = null;
    for (let at = from; at < source.length; at += 1) {
      const c = source[at];
      if (quote === "'") {
        if (c === "'") quote = null;
      } else if (c === "\\") at += 1;
      else if (quote === '"') {
        if (c === '"') quote = null;
      } else if (c === "'" || c === '"') quote = c;
      else if (c === "(") depth += 1;
      else if (c === ")" && (depth -= 1) === 0) return [source.slice(from, at), at + 1];
    }
    throw new Error(`an unclosed $( in: ${source.slice(from - 2, from + 60)}`);
  };
  const nested = [];
  /** Reads an expansion at `at` (`$(…)`, `` `…` `` or `$`) into the word; the index past it. */
  const expansion = (at) => {
    if (source.startsWith("$(", at)) {
      const [body, next] = substitution(at + 2);
      nested.push(body);
      add("$(…)", true);
      return next;
    }
    if (source[at] === "`") {
      const close = source.indexOf("`", at + 1);
      if (close < 0) throw new Error("an unclosed backtick");
      nested.push(source.slice(at + 1, close));
      add("`…`", true);
      return close + 1;
    }
    add("$", true);
    return at + 1;
  };
  let at = 0;
  while (at < source.length) {
    const c = source[at];
    if (c === "\\") {
      if (source[at + 1] !== "\n") add(source[at + 1] ?? "");
      at += 2;
    } else if (c === "'") {
      const close = source.indexOf("'", at + 1);
      if (close < 0) throw new Error(`an unclosed ' in: ${source.slice(at, at + 60)}`);
      add(source.slice(at + 1, close));
      at = close + 1;
    } else if (c === '"') {
      add("");
      at += 1;
      while (source[at] !== '"') {
        if (at >= source.length) throw new Error('an unclosed "');
        if (source[at] === "\\" && '$`"\\\n'.includes(source[at + 1])) {
          if (source[at + 1] !== "\n") add(source[at + 1]);
          at += 2;
        } else if (source[at] === "$" || source[at] === "`") at = expansion(at);
        else add(source[at++]);
      }
      at += 1;
    } else if (c === "$" || c === "`") at = expansion(at);
    else if (c === "#" && word === null) {
      const newline = source.indexOf("\n", at);
      at = newline < 0 ? source.length : newline;
    } else if (c === "\n" || ";&|()<>".includes(c)) {
      endCommand();
      at += 1;
    } else if (/\s/.test(c)) {
      endWord();
      at += 1;
    } else add(source[at++]);
  }
  endCommand();
  return [...commands.filter((command) => command.length > 0), ...nested.flatMap(lexShell)];
};

/**
 * Moves past the options at `words[at]` by `table` (getopt-style: `--name value`, `--name=value`,
 * `-e value`, `-evalue`, and flag clusters such as `-dit`); the index of the first operand, or -1
 * after reporting an option the table does not know, or one the shell builds, in `problems`.
 */
const pastOptions = (words, at, table, what, problems) => {
  while (at < words.length && words[at].text.startsWith("-") && words[at].text !== "-") {
    const { text, dynamic } = words[at];
    if (text === "--") return at + 1;
    if (text.startsWith("--")) {
      const [name] = text.split("=", 1);
      const inline = text.includes("=");
      if (!inline && dynamic) {
        problems.push(`${what} ${text}: an option the shell builds`);
        return -1;
      }
      if (table.values.has(name)) at += inline ? 1 : 2;
      else if (table.flags.has(name) && !inline) at += 1;
      else {
        problems.push(`${what} ${name}: an option this scan does not know`);
        return -1;
      }
      continue;
    }
    let consumed = 1;
    for (let k = 1; k < text.length; k += 1) {
      const option = `-${text[k]}`;
      if (table.flags.has(option)) continue;
      if (table.values.has(option)) {
        if (k === text.length - 1) consumed = 2;
        break;
      }
      problems.push(`${what} ${text}: an option this scan does not know`);
      return -1;
    }
    at += consumed;
  }
  return at;
};

/**
 * Every image a run: block hands docker to start or fetch. Each command's `docker` word (or
 * `…/docker`) is read past docker's global options to its subcommand; for run, create, pull,
 * container run/create and image pull, past that subcommand's options to the first operand, the
 * image. Returns {command, image, literal} for each, and {problem} for what the scan refuses to
 * guess at: an option the tables do not know or the shell builds, a subcommand with no image, and a
 * literal image-like word (a `:` or a `/`, not an option, no digest) anywhere after an image the
 * shell builds, so an ordinary option value the tables missed can never pass as the image and
 * exempt the real one.
 *
 * What it cannot check: an image name the shell builds from variables at run time (literal false:
 * a release job pulls one by the digest its run's release manifest records, which other tests hold);
 * an image a script or an action the job calls starts; docker reached under another name (an
 * alias, a function, a variable holding its path); and options a newer CLI adds until the tables
 * are regenerated, which fail the scan instead.
 */
const dockerImages = (run) => {
  const found = [];
  const problems = [];
  for (const words of lexShell(run))
    for (let start = 0; start < words.length; start += 1) {
      if (words[start].dynamic || !/(^|\/)docker$/.test(words[start].text)) continue;
      let at = pastOptions(words, start + 1, DOCKER_OPTIONS.global, "docker", problems);
      if (at < 0) continue;
      const match = IMAGE_COMMANDS.find(([names]) =>
        names.every((name, k) => words[at + k]?.text === name && !words[at + k].dynamic),
      );
      if (match === undefined) continue;
      const [names, options] = match;
      const command = `docker ${names.join(" ")}`;
      at = pastOptions(words, at + names.length, DOCKER_OPTIONS[options], command, problems);
      if (at < 0) continue;
      const operand = words[at];
      if (operand === undefined) {
        problems.push(`${command} names no image`);
        continue;
      }
      found.push({ command, image: operand.text, literal: !operand.dynamic });
      if (!operand.dynamic) continue;
      for (const later of words.slice(at + 1))
        if (
          !later.dynamic &&
          !later.text.startsWith("-") &&
          IMAGE_LIKE.test(later.text) &&
          !later.text.includes("@sha256:")
        )
          problems.push(
            `${command}: ${later.text} follows the image the shell builds (${operand.text}) and is not pinned by digest`,
          );
    }
  return [...found, ...problems.map((problem) => ({ problem }))];
};

/** Every image a workflow names in YAML: a step's `uses: docker://…`, a job's container, its services. */
const yamlImages = (document) => {
  const found = [];
  for (const [name, job] of Object.entries(document.jobs ?? {})) {
    if (job.container !== undefined)
      found.push({
        at: `${name} container`,
        image: typeof job.container === "string" ? job.container : job.container?.image,
      });
    for (const [service, definition] of Object.entries(job.services ?? {}))
      found.push({
        at: `${name} services.${service}`,
        image: typeof definition === "string" ? definition : definition?.image,
      });
    for (const step of job.steps ?? [])
      if (String(step.uses ?? "").startsWith("docker://"))
        found.push({
          at: `${name} ${step.name ?? step.uses}`,
          image: step.uses.slice("docker://".length),
        });
  }
  return found;
};

/** release.yml, every workflow it calls through `uses: ./.github/workflows/…`, and next.yml. */
const publishingWorkflows = () => {
  const files = new Set();
  for (const pending = ["release.yml", "next.yml"]; pending.length > 0;) {
    const file = pending.pop();
    if (files.has(file)) continue;
    files.add(file);
    for (const job of Object.values(workflow(file).jobs ?? {})) {
      const called = /^\.\/\.github\/workflows\/([^/]+)$/.exec(job?.uses ?? "");
      if (called) pending.push(called[1]);
    }
  }
  return [...files].toSorted();
};

/** Every image `document` (a parsed workflow) runs, starts or pulls, and every problem reading it. */
const workflowImages = (document) => {
  const images = [];
  const problems = [];
  for (const [name, job] of Object.entries(document.jobs ?? {}))
    for (const step of job.steps ?? []) {
      const where = `${name} ${step.name ?? step.uses ?? step.run?.slice(0, 40)}`;
      for (const found of dockerImages(step.run ?? ""))
        if (found.problem !== undefined) problems.push(`${where}: ${found.problem}`);
        else images.push({ at: where, ...found });
      // BuildKit runs privileged, and performs the push.
      if (String(step.uses ?? "").startsWith("docker/setup-buildx-action@")) {
        const driver = /(?:^|,)image=([^,\s]+)/.exec(step.with?.["driver-opts"] ?? "");
        images.push({
          at: where,
          image: driver?.[1] ?? "<the action's default BuildKit>",
          literal: true,
        });
      }
    }
  for (const found of yamlImages(document))
    images.push({ ...found, image: String(found.image), literal: true });
  return { images, problems };
};
/** The images a workflow names that are not pinned by digest, and its reading problems. */
const unpinned = (document) => {
  const { images, problems } = workflowImages(document);
  return [
    ...problems,
    ...images
      .filter(({ image, literal }) => literal && !PINNED.test(image))
      .map(({ at, image }) => `${at}: ${image} is not pinned by digest`),
  ];
};

test("every image a publishing workflow starts, pulls or runs as a container is pinned by digest", () => {
  const files = publishingWorkflows();
  assert.deepEqual(files, ["next.yml", "release.yml"]);
  for (const file of files) assert.deepEqual(unpinned(workflow(file)), [], file);
  // The lexer reads every run: block of every workflow without refusing one.
  for (const file of workflowFiles())
    for (const job of Object.values(workflow(file).jobs ?? {}))
      for (const step of job.steps ?? []) assert.doesNotThrow(() => lexShell(step.run ?? ""), file);
});

// A new image in the release, pinned or built at run time, fails here until someone has looked.
test("the images release.yml starts today, by name or as the shell builds them", () => {
  // The dry run's loopback registry is the one image started by name; the identity check's pull
  // and create name the image the shell built from the manifest.
  const { images } = workflowImages(workflow("release.yml"));
  assert.deepEqual(
    images
      .filter(({ at }) => !/setup-buildx/.test(at))
      .map(({ at, command, image, literal }) => [at.split(" ")[0], command, image, literal]),
    [
      [
        "archive-merge",
        "docker run",
        "registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373",
        true,
      ],
      ["identity", "docker pull", "$REPOSITORY@$digest", false],
      ["identity", "docker create", "$id", false],
    ],
  );
});

test("the shell lexer keeps quoted words whole and finds commands inside substitutions", () => {
  const words = (source) =>
    lexShell(source).map((command) =>
      command.map(({ text, dynamic }) => (dynamic ? `${text}*` : text)),
    );
  assert.deepEqual(words(`docker run --env "BANNER=hello $BUILD_LABEL" -e FOO="a b" x`), [
    ["docker", "run", "--env", "BANNER=hello $BUILD_LABEL*", "-e", "FOO=a b", "x"],
  ]);
  assert.deepEqual(words("a 'x=y z' b\\ c \\\n  d # e f\ng;h|i&&j"), [
    ["a", "x=y z", "b c", "d"],
    ["g"],
    ["h"],
    ["i"],
    ["j"],
  ]);
  assert.deepEqual(words('out="$(docker run "a b" "$(echo c)")"; `docker pull d`'), [
    ["out=$(…)*"],
    ["`…`*"],
    ["docker", "run", "a b", "$(…)*"],
    ["echo", "c"],
    ["docker", "pull", "d"],
  ]);
  assert.deepEqual(words(`x=\${y:-$(npm root -g)/p} '$(not run)' "\\$z"`), [
    ["x=${y:-$(…)/p}*", "$(not run)", "$z"],
    ["npm", "root", "-g"],
  ]);
});

test("the image scan reads docker's options, quotes, continuations and subcommand forms", () => {
  const PIN = `@sha256:${"a".repeat(64)}`;
  const images = (run) =>
    dockerImages(run).map((found) => found.problem ?? [found.command, found.image, found.literal]);
  const unpinnedAlpine = [["docker run", "alpine:3.22", true]];
  for (const [label, run, expected] of [
    ["plain", "docker run --rm alpine:3.22 true", unpinnedAlpine],
    [
      "a global option with a value",
      "docker --context default run --rm alpine:3.22 true",
      unpinnedAlpine,
    ],
    [
      "global options in every form",
      "docker -H unix:///x --config=/c --debug -l info run -d --name x -p 1:1 alpine:3.22",
      unpinnedAlpine,
    ],
    [
      "a continuation that leaves two spaces",
      "docker \\\n  run --rm alpine:3.22 true",
      unpinnedAlpine,
    ],
    [
      "a continuation between options",
      "docker run --rm \\\n    --name x \\\n    alpine:3.22 true",
      unpinnedAlpine,
    ],
    // Astra's round 2: an option value the scan took for a dynamic image.
    [
      "a value option an old table lacked",
      'docker run --rm --stop-timeout "$STOP_TIMEOUT" alpine:3.22 true',
      unpinnedAlpine,
    ],
    [
      "a quoted value with a space and a variable",
      'docker run --rm --env "BANNER=hello $BUILD_LABEL" alpine:3.22 true',
      unpinnedAlpine,
    ],
    ["a value quoted mid-word", 'docker run -e FOO="a b" alpine:3.22', unpinnedAlpine],
    [
      "a single-quoted value",
      "docker run --label 'x=y z' alpine",
      [["docker run", "alpine", true]],
    ],
    [
      "a value attached to its short option",
      "docker run -eFOO=1 -p8080:80 alpine:3.22",
      unpinnedAlpine,
    ],
    ["a flag cluster", "docker run -dit alpine:3.22 sh", unpinnedAlpine],
    [
      "a flag cluster ending in a value option",
      "docker run -ite FOO=1 alpine:3.22",
      unpinnedAlpine,
    ],
    [
      "docker container run",
      "docker container run alpine:3.22",
      [["docker container run", "alpine:3.22", true]],
    ],
    [
      "docker container create",
      "docker container create --stop-timeout 5 alpine:3.22",
      [["docker container create", "alpine:3.22", true]],
    ],
    [
      "docker create, inside a quoted $()",
      'id="$(docker create "alpine:3.22" --version)"',
      [["docker create", "alpine:3.22", true]],
    ],
    [
      "docker pull with a platform",
      "docker pull --platform linux/arm64 alpine:3.22",
      [["docker pull", "alpine:3.22", true]],
    ],
    [
      "docker image pull",
      "docker image pull -q alpine:3.22",
      [["docker image pull", "alpine:3.22", true]],
    ],
    ["an option=value", "docker run --name=x alpine:3.22", unpinnedAlpine],
    ["after a pipe", "true | docker run -i alpine:3.22 cat", [["docker run", "alpine:3.22", true]]],
    ["by path", "/usr/bin/docker run alpine:3.22", unpinnedAlpine],
    [
      "pinned",
      `docker run --rm alpine:3.22${PIN} true`,
      [["docker run", `alpine:3.22${PIN}`, true]],
    ],
    // An image the shell builds is exempt only with nothing image-like after it.
    ["built at run time", 'docker run --rm "$IMAGE" true', [["docker run", "$IMAGE", false]]],
    [
      "a real dynamic pull",
      'docker pull "$X/$y@$digest"',
      [["docker pull", "$X/$y@$digest", false]],
    ],
    [
      "a literal image after one the shell builds",
      'docker run --rm "$IMAGE" alpine:3.22 true',
      [
        ["docker run", "$IMAGE", false],
        "docker run: alpine:3.22 follows the image the shell builds ($IMAGE) and is not pinned by digest",
      ],
    ],
    [
      "a pinned word after one the shell builds",
      `docker run --rm "$IMAGE" alpine${PIN}`,
      [["docker run", "$IMAGE", false]],
    ],
    [
      "an option the scan does not know, then a variable",
      "docker run --frobnicate $X alpine:3.22",
      ["docker run --frobnicate: an option this scan does not know"],
    ],
    [
      "a hidden alias the help does not list",
      "docker run --net host alpine:3.22",
      ["docker run --net: an option this scan does not know"],
    ],
    [
      "a global option the scan does not know",
      "docker -Z run alpine:3.22",
      ["docker -Z: an option this scan does not know"],
    ],
    [
      "an option the shell builds",
      'docker run "$FLAGS" alpine:3.22',
      [
        ["docker run", "$FLAGS", false],
        "docker run: alpine:3.22 follows the image the shell builds ($FLAGS) and is not pinned by digest",
      ],
    ],
    [
      "a long option the shell builds",
      "docker run --$OPT alpine:3.22",
      ["docker run --$OPT: an option the shell builds"],
    ],
    ["no image", "docker run --rm", ["docker run names no image"]],
    ["a comment", "# docker run alpine:3.22", []],
    ["a quoted mention", 'echo "docker run alpine:3.22"', []],
    [
      "commands that start nothing",
      'docker buildx imagetools create --tag x y\ndocker image inspect "$id"',
      [],
    ],
  ])
    assert.deepEqual(images(run), expected, label);
  // The YAML forms.
  const yaml = (jobs) => unpinned({ jobs });
  assert.deepEqual(yaml({ a: { container: "alpine:3.22", steps: [] } }), [
    "a container: alpine:3.22 is not pinned by digest",
  ]);
  assert.deepEqual(yaml({ a: { container: { image: "alpine:3.22" }, steps: [] } }), [
    "a container: alpine:3.22 is not pinned by digest",
  ]);
  assert.deepEqual(yaml({ a: { services: { cache: { image: "redis:7" } }, steps: [] } }), [
    "a services.cache: redis:7 is not pinned by digest",
  ]);
  assert.deepEqual(yaml({ a: { steps: [{ name: "s", uses: "docker://alpine:3.22" }] } }), [
    "a s: alpine:3.22 is not pinned by digest",
  ]);
  // An expression is not a pin either.
  assert.deepEqual(yaml({ a: { container: "${{ matrix.image }}", steps: [] } }), [
    "a container: ${{ matrix.image }} is not pinned by digest",
  ]);
  assert.deepEqual(
    yaml({
      a: {
        container: `alpine:3.22${PIN}`,
        services: { cache: `redis:7${PIN}` },
        steps: [{ name: "s", uses: `docker://alpine${PIN}` }, { run: `docker run alpine${PIN}` }],
      },
    }),
    [],
  );
  for (const image of ["registry:2", "registry", "registry:2@sha256:abc", "moby/buildkit:v0.33.1"])
    assert.doesNotMatch(image, PINNED, image);
});

test("finalize waits for the identity checks on both arches, and npm for finalize and pack", () => {
  const above = (name, seen = new Set()) => {
    for (const need of [releaseJobs[name].needs ?? []].flat())
      if (!seen.has(need)) above(need, seen.add(need));
    return seen;
  };
  assert.ok(releaseJobs["finalize-images"].needs.includes("identity"));
  for (const job of ["identity", "release-manifest", "merge", "build", "stable-tag"])
    assert.ok(above("finalize-images").has(job), job);
  for (const job of ["finalize-images", "pack"])
    assert.ok(releaseJobs.npm.needs.includes(job), job);
  assert.ok(above("npm").has("identity"));
  assert.ok(above("release-manifest").has("pack"));
  // Both arches, each on its own native hosted runner.
  for (const name of ["build", "archive-build", "identity"])
    assert.deepEqual(releaseJobs[name].strategy.matrix.platform, [
      { arch: "amd64", runner: "ubuntu-24.04" },
      { arch: "arm64", runner: "ubuntu-24.04-arm" },
    ]);
  assert.equal(releaseJobs.identity.strategy["fail-fast"], false);
  // The ci check runs before anything builds, with the one extra permission it needs.
  assert.deepEqual(releaseJobs["stable-tag"].permissions, { contents: "read", actions: "read" });
  // Identity reads only: it pulls anonymously and logs in nowhere.
  assert.deepEqual(releaseJobs.identity.permissions, { contents: "read" });
  for (const entry of releaseJobs.identity.steps)
    assert.doesNotMatch(entry.uses ?? "", /login-action/);
});

/** Actions a job holding an id-token may use: none checks out or runs repository code. */
const CREDENTIAL_ACTIONS = /^actions\/(setup-node|download-artifact)@[0-9a-f]{40}$/;
/** Commands that install dependencies, run a build tool or run a repository file. */
const BUILDS =
  /\b(pnpm|npx|yarn|corepack|tsgo|tsc|tsx|turbo|esbuild|vite|make|cargo|buf)\b|\bnpm (install|ci|i|run|exec|rebuild|test|start|pack|version)\b|\bnode (?!-e\b)\S|\bdocker (build|buildx build)\b/;
const workflowFiles = () =>
  readdirSync(path.join(root, ".github/workflows")).filter((name) => /\.ya?ml$/.test(name));
const workflow = (file) =>
  parse(readFileSync(path.join(root, ".github/workflows", file), "utf8")) ?? {};

test("no job holding an id-token checks out, installs dependencies or runs a build tool", () => {
  let holders = 0;
  for (const file of workflowFiles()) {
    const { jobs = {}, permissions = {} } = workflow(file);
    assert.notEqual(permissions["id-token"], "write", `${file} grants an id-token to every job`);
    for (const [name, definition] of Object.entries(jobs)) {
      if (definition.permissions?.["id-token"] !== "write") continue;
      holders += 1;
      for (const step of definition.steps ?? []) {
        if (step.uses !== undefined) assert.match(step.uses, CREDENTIAL_ACTIONS, `${file} ${name}`);
        // Comments aside, which name what the job does not do.
        const code = (step.run ?? "").replace(/^\s*(#|echo ).*$/gm, "");
        // next.yml's republish block repacks with `npm pack --ignore-scripts`, which runs no package
        // code; release.yml's never repacks.
        const allowed = file === "next.yml" ? code.replace(/npm pack --ignore-scripts/g, "") : code;
        assert.doesNotMatch(allowed, BUILDS, `${file} ${name} ${step.name ?? step.uses}`);
      }
    }
  }
  assert.equal(holders, 2, "next.yml's publish and release.yml's npm hold the only id-tokens");
  // The guard itself catches what the old stable npm job did.
  for (const line of [
    "pnpm install --frozen-lockfile --ignore-scripts",
    "pnpm -r build",
    "pnpm -r publish --access public --no-git-checks --provenance",
    "corepack enable",
    "npm ci",
    'npm version "$VERSION" --no-git-tag-version',
    "node scripts/release-manifest.mjs digest",
    "npx tsc",
    "docker build -f docker/Dockerfile .",
  ])
    assert.match(line, BUILDS, line);
  for (const line of [
    "npm publish x.tgz --tag latest",
    "npm view a dist.integrity",
    "node -e 'x'",
    "npm config get registry",
  ])
    assert.doesNotMatch(line, BUILDS, line);
  const npm = stepRun("npm", "Publish to npm");
  assert.match(npm, /npm publish "\$tarball" --tag latest --access public --ignore-scripts "\$@"/);
  assert.doesNotMatch(npm, /npm pack|writeFileSync|rebuild_tarball|publish_rebuilt/);
  assert.deepEqual(
    releaseJobs.npm.steps
      .filter((step) => step.uses?.startsWith("actions/download-artifact@"))
      .map((step) => step.with),
    [
      { name: "npm-tarballs", path: "npm" },
      { name: "release-manifest", path: "release" },
    ],
  );
  assert.deepEqual(releaseJobs.npm.permissions, { "id-token": "write" });
  assert.equal(releaseJobs.npm.environment, "release");
  // pack builds with no credential at all.
  assert.deepEqual(releaseJobs.pack.permissions, { contents: "read" });
  assert.equal(
    releaseJobs.pack.steps.find((step) => step.uses?.startsWith("actions/checkout@")).with[
      "persist-credentials"
    ],
    false,
  );
});

// GitHub's rule: a job whose `if` names no status function runs only if every job above it, however
// far up, succeeded; a skipped job counts as not succeeded. `fail` names jobs that fail when they run.
const callsStatusFunction = (condition) =>
  /\b(always|cancelled|success|failure)\s*\(\s*\)/.test(
    String(condition ?? "").replace(/'(?:[^']|'')*'/g, "''"),
  );
const simulateRun = ({ graph = releaseJobs, event = "push", fail = [] } = {}) => {
  const needsOf = (name) => [graph[name].needs ?? []].flat();
  const ancestors = (name, seen = new Set()) => {
    for (const need of needsOf(name)) if (!seen.has(need)) ancestors(need, seen.add(need));
    return seen;
  };
  const result = {};
  const pending = new Set(Object.keys(graph));
  while (pending.size > 0) {
    const ready = [...pending].filter((name) => needsOf(name).every((need) => need in result));
    assert.ok(ready.length > 0, "the workflow's needs form a cycle");
    for (const name of ready) {
      let expression = (graph[name].if ?? "").replace(/^\$\{\{\s*|\s*\}\}$/g, "").trim();
      if (!callsStatusFunction(expression))
        expression = expression === "" ? "success()" : `success() && (${expression})`;
      const allAbove = [...ancestors(name)].every((job) => result[job] === "success");
      const script = expression
        .replace(/!cancelled\(\)/g, "true")
        .replace(/always\(\)/g, "true")
        .replace(/success\(\)/g, String(allAbove))
        .replace(
          /failure\(\)/g,
          String([...ancestors(name)].some((job) => result[job] === "failure")),
        )
        .replace(/inputs\.dry_run/g, JSON.stringify(event === "workflow_dispatch"))
        .replace(/github\.event_name/g, JSON.stringify(event))
        .replace(/github\.repository/g, JSON.stringify("sealant-sh/sealantd"))
        .replace(/needs\.([\w-]+)\.outputs\.([\w-]+)/g, (_, need, output) =>
          JSON.stringify(simulatedOutput(need, output, event)),
        )
        .replace(/needs\.([\w-]+)\.result/g, (_, need) => JSON.stringify(result[need]))
        .replace(/!=/g, "!==")
        .replace(/(?<![!=])==/g, "===");
      const runs = Function(`"use strict"; return (${script});`)();
      if (!runs) result[name] = "skipped";
      else if (fail.includes(name)) result[name] = "failure";
      else result[name] = "success";
      pending.delete(name);
    }
  }
  return result;
};
/** What a job that ran reports, for the outputs job conditions read. */
const simulatedOutput = (job, output, event) => {
  if (output === "target") return event === "push" ? "ghcr" : "archive";
  return "";
};

test("a tag push runs both publishers after the identity checks; a failure above runs neither", () => {
  const push = simulateRun();
  for (const name of Object.keys(releaseJobs))
    assert.equal(push[name], name.startsWith("archive-") ? "skipped" : "success", name);
  // A commit whose ci did not pass fails stable-tag: nothing builds, nothing publishes.
  for (const failed of ["stable-tag", "build", "merge", "pack", "release-manifest", "identity"]) {
    const run = simulateRun({ fail: [failed] });
    for (const name of PUBLISHERS) assert.equal(run[name], "skipped", `${name} after ${failed}`);
  }
  // npm publishes only after finalize wrote :<version>.
  assert.equal(simulateRun({ fail: ["finalize-images"] }).npm, "skipped");
  const stableTagFailed = simulateRun({ fail: ["stable-tag"] });
  for (const name of Object.keys(releaseJobs).filter((job) => job !== "stable-tag"))
    assert.equal(stableTagFailed[name], "skipped", name);
});

test("a dry-run dispatch builds to archives and checks them, and runs nothing that publishes", () => {
  const dispatch = simulateRun({ event: "workflow_dispatch" });
  for (const name of [
    "stable-tag",
    "archive-build",
    "archive-merge",
    "pack",
    "release-manifest",
    "identity",
  ])
    assert.equal(dispatch[name], "success", name);
  for (const name of ["build", "merge", ...PUBLISHERS])
    assert.equal(dispatch[name], "skipped", name);
  // A failed archive leg stops the identity checks there too.
  const failed = simulateRun({ event: "workflow_dispatch", fail: ["archive-merge"] });
  assert.equal(failed["release-manifest"], "skipped");
  assert.equal(failed.identity, "skipped");
  // Every job that writes, holds an environment or could mint an id-token is skipped on a dispatch.
  const writers = Object.entries(releaseJobs).filter(([, definition]) => writes(definition));
  assert.deepEqual(writers.map(([name]) => name).toSorted(), [
    "build",
    "finalize-images",
    "merge",
    "npm",
  ]);
  for (const [name] of writers) assert.equal(dispatch[name], "skipped", name);
  // And on a push the archive jobs, which hold nothing, never run.
  const push = simulateRun();
  for (const name of ["archive-build", "archive-merge"]) assert.equal(push[name], "skipped", name);
  // Nothing in this workflow can delete or rewrite artifacts or runs.
  for (const [name, definition] of Object.entries(releaseJobs))
    assert.notEqual(definition.permissions?.actions, "write", name);
});

test("every job that publishes runs only on a tag push, building only to GHCR", () => {
  for (const name of ["build", "merge"])
    assert.equal(releaseJobs[name].if, "needs.stable-tag.outputs.target == 'ghcr'", name);
  for (const name of ["archive-build", "archive-merge"])
    assert.equal(releaseJobs[name].if, "needs.stable-tag.outputs.target == 'archive'", name);
  for (const name of PUBLISHERS)
    assert.match(
      releaseJobs[name].if,
      /^\$\{\{ !cancelled\(\) && github\.event_name == 'push' && /,
      name,
    );
});

// The same rule across every workflow. A job whose `if` names no status function is skipped when
// any job above it was. Each such job below a job that can be skipped is listed here with why that
// skip is also this job's; a new one fails until someone has looked.
const SKIPPED_TOGETHER = new Map([
  ["release.yml merge", "same target as build above it"],
  ["release.yml archive-merge", "same target as archive-build above it"],
  // next.yml: plan skips only outside sealant-sh/sealantd or for a ci run that did not pass, and the
  // rest only when it decides not to publish.
  ["next.yml image", "plan skips only on a fork or a failed ci; publish is plan's decision"],
  ["next.yml image-tag", "skipped exactly when plan decided not to publish"],
  ["next.yml pack", "skipped exactly when plan decided not to publish"],
  ["next.yml publish", "skipped exactly when plan decided not to publish"],
]);

test("no workflow job is skipped behind a job its own path expected to skip, unless reviewed", () => {
  const exposed = [];
  for (const file of workflowFiles()) {
    const { jobs: all = {} } = workflow(file);
    const needsOf = (name) => [all[name]?.needs ?? []].flat();
    const ancestors = (name, seen = new Set()) => {
      for (const need of needsOf(name)) if (!seen.has(need)) ancestors(need, seen.add(need));
      return seen;
    };
    for (const [name, job] of Object.entries(all)) {
      if (callsStatusFunction(job.if)) continue;
      if ([...ancestors(name)].some((above) => all[above]?.if !== undefined))
        exposed.push(`${file} ${name}`);
    }
  }
  assert.deepEqual(exposed.toSorted(), [...SKIPPED_TOGETHER.keys()].toSorted());
  assert.equal(callsStatusFunction("inputs.dry_run && 'always()' != ''"), false);
  assert.equal(callsStatusFunction("${{ !cancelled() && github.event_name == 'push' }}"), true);
  assert.equal(callsStatusFunction(undefined), false);
});

// --- the dry run ---

const resolveStep = releaseJobs["stable-tag"].steps.find((step) => step.id === "resolve");
/** The resolve step as written, in a checkout whose packages/runtime-client is at `client`. */
const resolve = (t, environment, client = "0.19.0") => {
  const directory = scratch(t, "sealantd-release-resolve-");
  mkdirSync(path.join(directory, "packages/runtime-client"), { recursive: true });
  writeFileSync(
    path.join(directory, "packages/runtime-client/package.json"),
    JSON.stringify({ name: "@sealant/runtime-client", version: client }),
  );
  const output = path.join(directory, "output");
  writeFileSync(output, "");
  const result = bashStep(resolveStep.run, {
    cwd: directory,
    env: {
      PATH: process.env.PATH,
      GITHUB_RUN_ID: "38700000001",
      GITHUB_RUN_ATTEMPT: "2",
      GITHUB_OUTPUT: output,
      ...environment,
    },
  });
  const values = Object.fromEntries(
    readFileSync(output, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => line.split("=")),
  );
  return { status: result.status, output: result.stdout + result.stderr, ...values };
};

test("a dispatch is a dry run or nothing, and its version is always derived from the run", (t) => {
  assert.deepEqual(releaseDocument.on.workflow_dispatch.inputs, {
    dry_run: {
      description: "Build, check and pack a release without publishing anything",
      required: true,
      type: "boolean",
    },
  });
  assert.equal(resolveStep.env.DRY_RUN, "${{ inputs.dry_run }}");
  const dispatch = {
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REF: "refs/heads/feature",
    GITHUB_REF_NAME: "feature",
  };
  const dry = resolve(t, { ...dispatch, DRY_RUN: "true" });
  assert.equal(dry.status, 0, dry.output);
  assert.equal(dry.version, "0.19.0-dryrun.38700000001.2");
  assert.equal(dry.target, "archive");
  // Nothing the dispatcher controls names the version: not the ref, not a tag-shaped ref name.
  assert.equal(
    resolve(t, {
      ...dispatch,
      DRY_RUN: "true",
      GITHUB_REF: "refs/tags/v0.20.0",
      GITHUB_REF_NAME: "v0.20.0",
      VERSION: "0.20.0",
    }).version,
    "0.19.0-dryrun.38700000001.2",
  );
  // A runtime-client version that is not X.Y.Z gives no version at all.
  for (const client of ["0.20.0-next.4", "", "0.20"]) {
    const refused = resolve(t, { ...dispatch, DRY_RUN: "true" }, client);
    assert.equal(refused.status, 1, client);
    assert.equal(refused.version, undefined, client);
  }
  for (const value of ["false", "", "1"]) {
    const refused = resolve(t, { ...dispatch, DRY_RUN: value });
    assert.equal(refused.status, 1, value);
    assert.match(refused.output, /only dry-runs a release/);
    assert.equal(refused.version, undefined);
  }
  const tag = resolve(t, {
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF: "refs/tags/v0.20.0",
    GITHUB_REF_NAME: "v0.20.0",
  });
  assert.deepEqual([tag.status, tag.version, tag.target], [0, "0.20.0", "ghcr"]);
  for (const name of ["v0.20.0-next.4", "v0.20", "v1234567890.0.0", "v01.0.0"]) {
    const prerelease = resolve(t, {
      GITHUB_EVENT_NAME: "push",
      GITHUB_REF: `refs/tags/${name}`,
      GITHUB_REF_NAME: name,
    });
    assert.equal(prerelease.status, 1, name);
    assert.match(prerelease.output, /is not a stable vX\.Y\.Z tag/, name);
  }
  assert.equal(
    resolve(t, {
      GITHUB_EVENT_NAME: "push",
      GITHUB_REF: "refs/heads/main",
      GITHUB_REF_NAME: "main",
    }).status,
    1,
  );
  assert.equal(resolve(t, { GITHUB_EVENT_NAME: "schedule" }).status, 1);
});

test("a dry-run-shaped tag is refused before anything builds; a push only ever builds to GHCR", (t) => {
  for (const name of [
    "v0.19.0-dryrun.38700000001.1",
    "v0.0.0-dryrun.9.1",
    "v0.20.0-next.4.dryrun.1.1",
  ]) {
    const pushed = resolve(t, {
      GITHUB_EVENT_NAME: "push",
      GITHUB_REF: `refs/tags/${name}`,
      GITHUB_REF_NAME: name,
    });
    assert.equal(pushed.status, 1, name);
    assert.match(pushed.output, /is a dry-run version; a dry run is a dispatch, never a tag/);
    assert.equal(pushed.version, undefined);
    assert.equal(pushed.target, undefined);
  }
  assert.match(resolveStep.run, /push\/ghcr \| workflow_dispatch\/archive\) ;;/);
  // Every job below takes the version and target from stable-tag, and nowhere else.
  assert.doesNotMatch(releaseText, /inputs\.version/);
  for (const [name, definition] of Object.entries(releaseJobs)) {
    if (name === "stable-tag") continue;
    assert.ok([definition.needs].flat().includes("stable-tag"), `${name} needs stable-tag`);
    for (const entry of definition.steps ?? [])
      assert.doesNotMatch(entry.run ?? "", /GITHUB_REF_NAME#/, name);
  }
  assert.deepEqual(simulateRun({ fail: ["stable-tag"] }).build, "skipped");
});

const REFUSE = "Refuse a version that is not this tag's release";

test("every job that publishes first refuses a dry-run version, from the input or from the tag", () => {
  const writers = Object.entries(releaseJobs).filter(([, definition]) => writes(definition));
  for (const [name, definition] of writers) {
    assert.equal(definition.steps[0].name, REFUSE, name);
    assert.deepEqual(
      definition.steps[0].env,
      { VERSION: "${{ needs.stable-tag.outputs.version }}" },
      name,
    );
    assert.ok(definition.needs.includes("stable-tag"), name);
  }
  const run = (GITHUB_EVENT_NAME, GITHUB_REF_NAME, VERSION) =>
    bashStep(releaseJobs.npm.steps[0].run, {
      env: { PATH: process.env.PATH, GITHUB_EVENT_NAME, GITHUB_REF_NAME, VERSION },
    });
  assert.equal(run("push", "v0.20.0", "0.20.0").status, 0);
  for (const [event, ref, version] of [
    // A dry run's version, however it arrived: derived on a dispatch, or from a pushed tag.
    ["workflow_dispatch", "main", "0.19.0-dryrun.38700000001.1"],
    ["push", "v0.19.0-dryrun.38700000001.1", "0.19.0-dryrun.38700000001.1"],
    // A plain version that is not this run's tag, or a release version on a dispatch.
    ["push", "v0.20.0", "0.19.0-dryrun.38700000001.1"],
    ["workflow_dispatch", "v0.20.0", "0.20.0"],
    ["push", "v0.20.1", "0.20.0"],
    ["push", "v0.20.0-next.4", "0.20.0-next.4"],
    ["push", "v1234567890.0.0", "1234567890.0.0"],
    ["push", "v", ""],
  ]) {
    const refused = run(event, ref, version);
    assert.equal(refused.status, 1, `${event} ${ref} ${version}`);
    assert.match(refused.stdout, /not a plain X\.Y\.Z release of its own tag/);
  }
  // Every copy of the step is the same.
  for (const [name, definition] of writers)
    assert.equal(definition.steps[0].run, releaseJobs.npm.steps[0].run, name);
});

test("the stray check reads the X.Y.Z a dry run stamps", () => {
  const step = releaseJobs["stable-tag"].steps.find(
    (entry) => entry.name === "Refuse a release that leaves out one of its next builds",
  );
  assert.match(step.run, /--stray "v\$\{VERSION%%-\*\}"/);
  assert.equal(step.env.VERSION, "${{ steps.resolve.outputs.version }}");
  // Nothing in stable-tag carries on past a failure.
  for (const entry of releaseJobs["stable-tag"].steps)
    assert.equal(entry["continue-on-error"], undefined, entry.name);
});
