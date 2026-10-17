// The release manifest release.yml writes, and the jobs that write and read it: run as written where
// they are shell, against stand-in commands. Ported from sealant-sh/sealant
// tooling/scripts/release-manifest.test.mjs, for sealantd's one image.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import {
  ARCHES,
  IMAGES,
  buildManifest,
  checkIndex,
  selectPlatform,
  validateManifest,
} from "./release-manifest.mjs";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
const script = fileURLToPath(new URL("./release-manifest.mjs", import.meta.url));
const { jobs } = parse(readFileSync(path.join(root, ".github/workflows/release.yml"), "utf8"));
const step = (job, name) => {
  const found = jobs[job].steps.find((entry) => entry.name === name);
  assert.ok(found, `release.yml ${job} has the step "${name}"`);
  return found;
};

const scratch = (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "sealantd-release-manifest-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};
const hex = (seed) => createHash("sha256").update(seed).digest("hex");
const sha256 = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const COMMIT = "f".repeat(40);

/** The records one run's jobs upload, laid out as download-artifact lays out a pattern. */
const records = (directory) => {
  const digests = path.join(directory, "digests");
  const indexes = path.join(directory, "indexes");
  for (const name of IMAGES) {
    for (const arch of ARCHES) {
      const dir = path.join(digests, `digests-${name}--${arch}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(path.join(dir, hex(`${name}/${arch}`)), "");
    }
    mkdirSync(path.join(indexes, `index-${name}`), { recursive: true });
    writeFileSync(path.join(indexes, `index-${name}`, "digest"), `sha256:${hex(name)}\n`);
  }
  return { digests, indexes };
};

test("the manifest holds the image's index and platform digests, and the run's identity", (t) => {
  const manifest = buildManifest({ version: "1.2.3", commit: COMMIT, ...records(scratch(t)) });
  assert.deepEqual(manifest, {
    version: "1.2.3",
    commit: COMMIT,
    images: {
      sealantd: {
        index: `sha256:${hex("sealantd")}`,
        platforms: {
          amd64: `sha256:${hex("sealantd/amd64")}`,
          arm64: `sha256:${hex("sealantd/arm64")}`,
        },
      },
    },
  });
});

test("a run missing a record, or holding a stray one, writes no manifest", (t) => {
  const directory = scratch(t);
  const { digests, indexes } = records(directory);
  const base = { version: "1.2.3", commit: COMMIT, digests, indexes };
  writeFileSync(path.join(digests, "digests-sealantd--arm64", hex("second")), "");
  assert.throws(() => buildManifest(base), /exactly one file/);
  rmSync(path.join(digests, "digests-sealantd--arm64"), { recursive: true });
  assert.throws(() => buildManifest(base), /ENOENT/);
  const valid = buildManifest({ version: "1.2.3", commit: COMMIT, ...records(scratch(t)) });
  const entry = valid.images.sealantd;
  for (const broken of [
    { ...valid, commit: "abc" },
    { ...valid, version: "1.2" },
    { ...valid, version: "1.2.3-next.4" },
    { ...valid, version: "1234567890.0.0" },
    { ...valid, images: { sealantd: { ...entry, index: "latest" } } },
    { ...valid, images: { sealantd: { ...entry, platforms: { amd64: entry.platforms.amd64 } } } },
    { ...valid, images: { ...valid.images, "sealantd-next": entry } },
    { ...valid, images: {} },
  ])
    assert.throws(() => validateManifest(broken));
});

test("digest prints the image's platform digest for one arch, and nothing else", (t) => {
  const directory = scratch(t);
  const manifest = buildManifest({ version: "1.2.3", commit: COMMIT, ...records(directory) });
  const file = path.join(directory, "release-manifest.json");
  writeFileSync(file, JSON.stringify(manifest));
  const digest = (...args) =>
    spawnSync(process.execPath, [script, "digest", file, ...args], { encoding: "utf8" });
  for (const arch of ARCHES)
    assert.equal(digest("sealantd", arch).stdout, `sha256:${hex(`sealantd/${arch}`)}\n`);
  for (const args of [
    ["sealantd", "riscv64"],
    ["sealantd-next", "amd64"],
  ]) {
    const refused = digest(...args);
    assert.equal(refused.status, 1);
    assert.equal(refused.stdout, "");
  }
});

test("the manifest job writes from this run's records and keeps them 90 days", (t) => {
  const job = jobs["release-manifest"];
  assert.ok(job.needs.includes("merge"));
  const write = step("release-manifest", "Write release-manifest.json");
  assert.equal(write.env.COMMIT, "${{ github.sha }}");
  const directory = scratch(t);
  const { digests, indexes } = records(directory);
  const run = spawnSync("bash", ["--noprofile", "--norc", "-e", "-c", write.run], {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      RUNNER_TEMP: directory,
      VERSION: "1.2.3",
      COMMIT,
      DIGESTS: digests,
      INDEXES: indexes,
    },
  });
  assert.equal(run.status, 0, run.stderr);
  const written = JSON.parse(
    readFileSync(path.join(directory, "manifest/release-manifest.json"), "utf8"),
  );
  assert.equal(written.images.sealantd.index, `sha256:${hex("sealantd")}`);
  const upload = job.steps.find((entry) => entry.with?.name === "release-manifest");
  assert.equal(upload.with["retention-days"], 90);
});

// --- the index imagetools create pushed ---

const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX = "application/vnd.oci.image.index.v1+json";
/** A registry document: its bytes and the digest it is read by. */
const doc = (value) => {
  const bytes = Buffer.from(JSON.stringify(value));
  return { bytes, digest: sha256(bytes), value };
};
const imageManifest = (arch) =>
  doc({
    schemaVersion: 2,
    mediaType: OCI_MANIFEST,
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: `sha256:${hex(arch)}`,
      size: 1,
    },
    layers: [],
  });
const childOf = (manifest, os, architecture, variant) => ({
  mediaType: OCI_MANIFEST,
  digest: manifest.digest,
  size: manifest.bytes.length,
  platform: { os, architecture, ...(variant ? { variant } : {}) },
});
/** BuildKit's attestation entry for `manifest`. */
const attestationOf = (manifest) => ({
  mediaType: OCI_MANIFEST,
  digest: `sha256:${hex(`attestation of ${manifest.digest}`)}`,
  size: 1,
  platform: { os: "unknown", architecture: "unknown" },
  annotations: {
    "vnd.docker.reference.digest": manifest.digest,
    "vnd.docker.reference.type": "attestation-manifest",
  },
});
const indexOf = (manifests) => doc({ schemaVersion: 2, mediaType: OCI_INDEX, manifests });
const created = (index) => ({
  "containerimage.descriptor": { mediaType: OCI_INDEX, digest: index.digest },
});
const amd64 = imageManifest("amd64");
const arm64 = imageManifest("arm64");
const plainChildren = [childOf(amd64, "linux", "amd64"), childOf(arm64, "linux", "arm64")];

/** `descriptor` annotated as BuildKit annotates an attestation, whatever its platform says. */
const annotated = (descriptor) => ({
  ...descriptor,
  annotations: {
    "vnd.docker.reference.digest": descriptor.digest,
    "vnd.docker.reference.type": "attestation-manifest",
  },
});
/** Astra's round 2: an attestation-annotated linux/amd64 descriptor of the arm64 build. */
const ANNOTATED_AMD64 = annotated(childOf(arm64, "linux", "amd64"));
/** Each way an annotated descriptor can claim a runnable platform, and where it sits. */
const annotatedRunnable = () => [
  ["Astra's annotated amd64 descriptor first", [ANNOTATED_AMD64, ...plainChildren]],
  ["the same descriptor last", [...plainChildren, ANNOTATED_AMD64]],
  [
    "an annotated descriptor of a runnable variant",
    [...plainChildren, annotated(childOf(imageManifest("arm64 v8"), "linux", "arm64", "v8"))],
  ],
  [
    "an annotated descriptor of another digest",
    [annotated(childOf(imageManifest("other amd64"), "linux", "amd64")), ...plainChildren],
  ],
];

/** A source as merge names it: the build job's arch, and its manifest (or attested index). */
const built = (arch, document) => ({ arch, ...document });
const builds = [built("amd64", amd64), built("arm64", arm64)];

test("an index made from two plain image manifests is the one create reported", () => {
  const index = indexOf(plainChildren);
  assert.equal(checkIndex(created(index), index.bytes, builds), index.digest);
  assert.equal(
    checkIndex({ ...created(index), "containerimage.digest": index.digest }, index.bytes, builds),
    index.digest,
  );
  assert.throws(
    () =>
      checkIndex({ ...created(index), "containerimage.digest": amd64.digest }, index.bytes, builds),
    /two different ones/,
  );
  assert.throws(() => checkIndex({}, index.bytes, builds), /no index digest/);
  // BuildKit's arm64 builds may carry the v8 variant.
  const v8 = indexOf([plainChildren[0], childOf(arm64, "linux", "arm64", "v8")]);
  assert.equal(checkIndex(created(v8), v8.bytes, builds), v8.digest);
});

test("an index made from attested single-platform indexes holds each source's children", () => {
  const sources = [amd64, arm64].map((manifest, at) =>
    built(ARCHES[at], indexOf([plainChildren[at], attestationOf(manifest)])),
  );
  const index = indexOf(sources.flatMap((source) => source.value.manifests));
  assert.equal(checkIndex(created(index), index.bytes, sources), index.digest);
  const partial = indexOf([...plainChildren, attestationOf(amd64)]);
  assert.throws(() => checkIndex(created(partial), partial.bytes, sources), /lacks sha256:/);
  const both = indexOf(plainChildren);
  assert.throws(
    () => checkIndex(created(both), both.bytes, [built("amd64", both), built("arm64", arm64)]),
    /more than one platform/,
  );
  // An attested source's build is still bound to its arch's platform.
  const swapped = indexOf([
    childOf(amd64, "linux", "arm64"),
    childOf(arm64, "linux", "amd64"),
    ...sources.map((source) => source.value.manifests[1]),
  ]);
  assert.throws(
    () => checkIndex(created(swapped), swapped.bytes, sources),
    new RegExp(`maps linux/amd64 to ${arm64.digest}, not ${amd64.digest}, the amd64 build`),
  );
});

test("each arch's platform must name that arch's build: a swap, a duplicate, a wrong variant or a missing entry is refused", () => {
  const refused = (children, problem, sources = builds) => {
    const index = indexOf(children);
    assert.throws(() => checkIndex(created(index), index.bytes, sources), problem);
  };
  // Astra's round 1: both sources present, both platforms present, the labels exchanged.
  refused(
    [childOf(amd64, "linux", "arm64"), childOf(arm64, "linux", "amd64")],
    new RegExp(`maps linux/amd64 to ${arm64.digest}, not ${amd64.digest}, the amd64 build`),
  );
  // The same index with the sources named for the other arch is refused the same way.
  refused(plainChildren, /maps linux\/amd64 to sha256:[0-9a-f]{64}, not sha256:[0-9a-f]{64}/, [
    built("amd64", arm64),
    built("arm64", amd64),
  ]);
  refused(
    [childOf(amd64, "linux", "amd64"), childOf(arm64, "linux", "amd64")],
    /has 2 linux\/amd64 entries/,
  );
  refused(
    [...plainChildren, childOf(imageManifest("another arm64"), "linux", "arm64")],
    /has 2 linux\/arm64 entries/,
  );
  // Counted per descriptor, never through a set: a digest listed twice is refused.
  refused(
    [...plainChildren, { ...plainChildren[1], digest: amd64.digest }],
    new RegExp(`lists ${amd64.digest} 2 times`),
  );
  refused([plainChildren[0]], /has 0 linux\/arm64 entries \(none\), not one/);
  refused(
    [plainChildren[0], childOf(arm64, "linux", "arm64", "v7")],
    /holds linux\/arm64\/v7 \(sha256:[0-9a-f]{64}\), not linux\/amd64 or linux\/arm64/,
  );
  refused([childOf(amd64, "linux", "amd64", "v2"), plainChildren[1]], /holds linux\/amd64\/v2 /);
  refused([childOf(amd64, "windows", "amd64"), plainChildren[1]], /holds windows\/amd64 /);
  refused([{ ...plainChildren[0], platform: undefined }, plainChildren[1]], /holds no platform /);
  // An attestation annotation never takes a descriptor out of its runnable platform: containerd
  // ignores the annotation and selects the first match.
  for (const [label, children] of annotatedRunnable())
    refused(
      children,
      /annotated as an attestation for linux\/(amd64|arm64\/v8), a platform a consumer can select/,
    );
  // A real attestation, annotated and for unknown/unknown, is still one.
  const attested = indexOf([...plainChildren, attestationOf(amd64), attestationOf(arm64)]);
  assert.throws(
    () => checkIndex(created(attested), attested.bytes, builds),
    /from no source/,
    "excluded from the platforms, the attestations are only children no plain source names",
  );
  // One source per arch, no more and no fewer.
  for (const sources of [[builds[0]], [builds[0], built("amd64", arm64)], [...builds, builds[1]]])
    refused(plainChildren, /exactly one source per arch/, sources);
});

test("an index missing a source, holding another, or holding more is refused", () => {
  const other = imageManifest("someone else's arm64");
  const foreign = indexOf([plainChildren[0], childOf(other, "linux", "arm64")]);
  assert.throws(
    () => checkIndex(created(foreign), foreign.bytes, builds),
    new RegExp(`maps linux/arm64 to ${other.digest}, not ${arm64.digest}`),
  );
  const extra = indexOf([...plainChildren, attestationOf(imageManifest("extra"))]);
  assert.throws(() => checkIndex(created(extra), extra.bytes, builds), /from no source/);
  const riscv = indexOf([...plainChildren, childOf(imageManifest("extra"), "linux", "riscv64")]);
  assert.throws(() => checkIndex(created(riscv), riscv.bytes, builds), /holds linux\/riscv64/);
  // A lone manifest reported as created, or bytes read for another digest, are refused too.
  assert.throws(() => checkIndex(created(arm64), arm64.bytes, builds), /not a multi-arch index/);
  assert.throws(
    () => checkIndex(created(indexOf(plainChildren)), arm64.bytes, builds),
    /does not hash to/,
  );
});

test("select resolves an arch through the index as a consumer would, and refuses an ambiguous one", (t) => {
  const index = indexOf(plainChildren);
  for (const [at, arch] of ARCHES.entries())
    assert.equal(selectPlatform(index.bytes, index.digest, arch), plainChildren[at].digest);
  // A swapped index answers the other build: the identity check compares it with this arch's.
  const swapped = indexOf([childOf(amd64, "linux", "arm64"), childOf(arm64, "linux", "amd64")]);
  assert.equal(selectPlatform(swapped.bytes, swapped.digest, "amd64"), arm64.digest);
  const attested = indexOf([...plainChildren, attestationOf(amd64), attestationOf(arm64)]);
  assert.equal(selectPlatform(attested.bytes, attested.digest, "arm64"), arm64.digest);
  for (const [children, problem] of [
    [
      [childOf(amd64, "linux", "amd64"), childOf(arm64, "linux", "amd64")],
      /2 linux\/amd64 entries/,
    ],
    [[plainChildren[1]], /0 linux\/amd64 entries/],
    [[plainChildren[0], childOf(arm64, "linux", "arm64", "v7")], /holds linux\/arm64\/v7/],
  ]) {
    const bad = indexOf(children);
    assert.throws(() => selectPlatform(bad.bytes, bad.digest, "amd64"), problem);
  }
  // An annotated runnable descriptor, first or last, is refused rather than skipped or selected.
  for (const [label, children] of annotatedRunnable()) {
    const bad = indexOf(children);
    for (const arch of ARCHES)
      assert.throws(
        () => selectPlatform(bad.bytes, bad.digest, arch),
        /annotated as an attestation/,
        `${label} ${arch}`,
      );
  }
  assert.throws(() => selectPlatform(index.bytes, swapped.digest, "amd64"), /does not hash to/);
  assert.throws(() => selectPlatform(amd64.bytes, amd64.digest, "amd64"), /not a multi-arch index/);
  assert.throws(() => selectPlatform(index.bytes, index.digest, "riscv64"), /No build for riscv64/);
  // As the identity step runs it.
  const directory = scratch(t);
  const file = path.join(directory, "index.json");
  writeFileSync(file, index.bytes);
  const select = (...args) =>
    spawnSync(process.execPath, [script, "select", file, ...args], { encoding: "utf8" });
  assert.equal(select(index.digest, "arm64").stdout, `${arm64.digest}\n`);
  const refused = select(swapped.digest, "arm64");
  assert.equal(refused.status, 1);
  assert.equal(refused.stdout, "");
});

test("merge records the index create reported, never the one its tag names now", (t) => {
  const record = step("merge", "Check and record the index digest");
  assert.match(record.run, /check-index create\.json/);
  assert.match(record.run, /inspect "\$REPOSITORY@\$digest" --raw >index\.json/);
  assert.match(record.run, /sources\+=\("\$arch=sha256:\$source=source-\$source\.json"\)/);
  assert.doesNotMatch(record.run, /\$REPOSITORY:\$tag/);
  const directory = scratch(t);
  const digests = path.join(directory, "digests");
  const documents = path.join(directory, "documents");
  const work = path.join(directory, "index");
  for (const dir of [digests, documents, work, path.join(directory, "bin")]) mkdirSync(dir);
  const index = indexOf(plainChildren);
  const swapped = indexOf([childOf(amd64, "linux", "arm64"), childOf(arm64, "linux", "amd64")]);
  for (const entry of [amd64, arm64, index, swapped, indexOf([plainChildren[1]])])
    writeFileSync(path.join(documents, entry.digest), entry.bytes);
  // One directory per build, named for its arch, as download-artifact lays them out.
  const lay = (byArch) => {
    rmSync(digests, { recursive: true, force: true });
    for (const [arch, entry] of Object.entries(byArch)) {
      mkdirSync(path.join(digests, `digests-sealantd--${arch}`), { recursive: true });
      writeFileSync(path.join(digests, `digests-sealantd--${arch}`, entry.digest.slice(7)), "");
    }
  };
  lay({ amd64, arm64 });
  // A docker that answers raw documents by digest only.
  writeFileSync(
    path.join(directory, "bin", "docker"),
    `#!${process.execPath}
const { readFileSync } = require("node:fs");
const args = process.argv.slice(2);
const at = args[3]?.indexOf("@") ?? -1;
if (args.slice(0, 3).join(" ") !== "buildx imagetools inspect" || args[4] !== "--raw" || at < 0) process.exit(79);
process.stdout.write(readFileSync(${JSON.stringify(documents)} + "/" + args[3].slice(at + 1)));
`,
  );
  chmodSync(path.join(directory, "bin", "docker"), 0o755);
  const run = (create) => {
    writeFileSync(path.join(work, "create.json"), JSON.stringify(create));
    rmSync(path.join(work, "digest"), { force: true });
    return spawnSync(
      "bash",
      ["--noprofile", "--norc", "-e", "-c", record.run.replaceAll("/tmp/digests", digests)],
      {
        cwd: work,
        encoding: "utf8",
        env: {
          PATH: `${path.join(directory, "bin")}:${process.env.PATH}`,
          REPOSITORY: "ghcr.invalid/fixture/sealantd",
          GITHUB_WORKSPACE: root,
        },
      },
    );
  };
  const recorded = run(created(index));
  assert.equal(recorded.status, 0, recorded.stderr);
  assert.equal(readFileSync(path.join(work, "digest"), "utf8"), `${index.digest}\n`);
  const lone = run(created(indexOf([plainChildren[1]])));
  assert.equal(lone.status, 1);
  assert.match(lone.stderr, /0 linux\/amd64 entries/);
  assert.equal(readFileSync(path.join(work, "digest"), "utf8"), "");
  // Astra's swapped index, created and reported as it would be, is not recorded.
  const exchanged = run(created(swapped));
  assert.equal(exchanged.status, 1);
  assert.match(exchanged.stderr, /maps linux\/amd64 to .*, the amd64 build/);
  assert.equal(readFileSync(path.join(work, "digest"), "utf8"), "");
  // The builds' artifacts named for the other arch: the arch comes from the artifact, so refused.
  lay({ amd64: arm64, arm64: amd64 });
  const misnamed = run(created(index));
  assert.equal(misnamed.status, 1);
  assert.match(misnamed.stderr, /maps linux\/amd64 to .*, the amd64 build/);
  lay({ amd64, arm64 });
  const nothing = run({});
  assert.equal(nothing.status, 1);
  assert.match(nothing.stdout, /reported no index digest/);
  // A source given without its arch is refused by the script.
  const file = path.join(work, "index.json");
  writeFileSync(file, index.bytes);
  writeFileSync(path.join(work, "a.json"), amd64.bytes);
  const unnamed = spawnSync(
    process.execPath,
    [script, "check-index", path.join(work, "create.json"), file, `${amd64.digest}=a.json`],
    { cwd: work, encoding: "utf8" },
  );
  assert.equal(unnamed.status, 1);
  assert.match(unnamed.stderr, /is not <arch>=<digest>=<file>/);
});
