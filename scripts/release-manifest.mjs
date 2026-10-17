#!/usr/bin/env node
/**
 * The release manifest: what one stable release run (.github/workflows/release.yml) built, by
 * digest. Every job after the build reads it from its own run's `release-manifest` artifact, never
 * from a tag, which another writer can move.
 *
 *   write <out>                    from the run's digests-* and index-* records (env below)
 *   digest <manifest> <image> <arch>
 *                                  prints that image's platform digest for that arch
 *   check-index <metadata> <index> <arch>=<digest>=<source>...
 *                                  refuses the index `imagetools create --metadata-file` reported
 *                                  unless <index> (its raw JSON, read by that digest) holds exactly
 *                                  the given sources, each arch's build under that arch's platform
 *                                  and nowhere else; prints its digest
 *   select <index> <index digest> <arch>
 *                                  prints the digest the index (its raw JSON, read by that digest)
 *                                  maps that arch's platform to, as a consumer of the index would
 *                                  select it, refusing an index that has no or more than one entry
 *                                  for the platform, or one of another variant
 *
 * `write` reads VERSION, COMMIT, DIGESTS (a directory of digests-<image>--<arch>/<hex>, as
 * download-artifact lays them out) and INDEXES (index-<image>/digest).
 *
 * The rules are sealant-sh/mend's and sealant-sh/sealant's scripts/release-manifest.mjs; the one
 * image is sealantd's.
 */
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const IMAGES = ["sealantd"];
export const ARCHES = ["amd64", "arm64"];
const DIGEST = /^sha256:[0-9a-f]{64}$/;
/** A release's X.Y.Z, each part at most 9 digits. */
const RUN_VERSION = /^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$/;
const MANIFEST_TYPES = new Set([
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
]);
const INDEX_TYPES = new Set([
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
]);
/**
 * What each arch's build is, as an index descriptor's platform: os, architecture, and the variants
 * BuildKit writes for it (none for amd64; none or v8 for arm64). Anything else is another platform.
 */
const PLATFORM = {
  amd64: { os: "linux", architecture: "amd64", variants: [undefined] },
  arm64: { os: "linux", architecture: "arm64", variants: [undefined, "v8"] },
};
const platformName = (platform) =>
  [platform?.os, platform?.architecture, platform?.variant].filter(Boolean).join("/") ||
  "no platform";
/** The arch whose build a descriptor's platform names, or undefined for any other platform. */
const archOf = (platform) =>
  ARCHES.find(
    (arch) =>
      platform?.os === PLATFORM[arch].os &&
      platform?.architecture === PLATFORM[arch].architecture &&
      PLATFORM[arch].variants.includes(platform?.variant || undefined),
  );

class Refused extends Error {}

function ensure(condition, message) {
  if (!condition) throw new Refused(message);
}

/** Throws unless `manifest` has the release manifest's shape; returns it. */
export function validateManifest(manifest) {
  ensure(
    RUN_VERSION.test(manifest?.version ?? "") && /^[0-9a-f]{40}$/.test(manifest.commit ?? ""),
    "The release manifest needs an X.Y.Z version and a 40-hex commit",
  );
  ensure(
    manifest.images !== null &&
      typeof manifest.images === "object" &&
      JSON.stringify(Object.keys(manifest.images)) === JSON.stringify(IMAGES),
    `The release manifest must record exactly ${IMAGES.join(", ")}`,
  );
  for (const image of IMAGES) {
    const entry = manifest.images[image];
    ensure(
      DIGEST.test(entry?.index ?? ""),
      `The release manifest has no index digest for ${image}`,
    );
    for (const arch of ARCHES)
      ensure(
        DIGEST.test(entry.platforms?.[arch] ?? ""),
        `The release manifest has no ${arch} digest for ${image}`,
      );
  }
  return manifest;
}

export const readManifest = (file) => validateManifest(JSON.parse(readFileSync(file, "utf8")));

/** The one regular file in `dir`, which must be all it holds. */
function onlyFile(dir, what) {
  const entries = readdirSync(dir, { withFileTypes: true });
  ensure(
    entries.length === 1 && entries[0].isFile(),
    `${what} must hold exactly one file, not ${entries.map((entry) => entry.name).join(", ")}`,
  );
  return entries[0].name;
}

/** The manifest from one run's records. */
export function buildManifest({ version, commit, digests, indexes }) {
  const images = Object.fromEntries(
    IMAGES.map((image) => {
      const platforms = Object.fromEntries(
        ARCHES.map((arch) => {
          const hex = onlyFile(path.join(digests, `digests-${image}--${arch}`), `${image} ${arch}`);
          ensure(/^[0-9a-f]{64}$/.test(hex), `${image} ${arch} records ${hex}, not a digest`);
          return [arch, `sha256:${hex}`];
        }),
      );
      const directory = path.join(indexes, `index-${image}`);
      ensure(onlyFile(directory, `${image}'s index`) === "digest", `${image}'s index record`);
      const index = readFileSync(path.join(directory, "digest"), "utf8").trim();
      return [image, { index, platforms }];
    }),
  );
  return validateManifest({ version, commit, images });
}

const sha256 = (buffer) => `sha256:${createHash("sha256").update(buffer).digest("hex")}`;

/** Annotated as BuildKit annotates the attestation it adds beside a platform manifest. */
const annotatedAttestation = (descriptor) =>
  descriptor.annotations?.["vnd.docker.reference.type"] === "attestation-manifest";
/**
 * An attestation, which no platform resolution selects: annotated as one, and for no runnable
 * platform (BuildKit writes unknown/unknown). The annotation alone excludes nothing: containerd's
 * platform resolver does not read it, and takes the first descriptor whose platform matches.
 */
const isAttestation = (descriptor) =>
  annotatedAttestation(descriptor) &&
  descriptor.platform?.os === "unknown" &&
  descriptor.platform?.architecture === "unknown";

/** A registry document read by digest (`imagetools inspect …@<digest> --raw`): it must hash to it. */
function document(bytes, digest, what) {
  ensure(DIGEST.test(digest), `${what}: ${digest} is not a sha256 digest`);
  ensure(sha256(bytes) === digest, `${what} does not hash to ${digest}`);
  const parsed = JSON.parse(bytes.toString("utf8"));
  const mediaType = parsed.mediaType;
  ensure(
    MANIFEST_TYPES.has(mediaType) || INDEX_TYPES.has(mediaType),
    `${what} is ${mediaType}, not an image manifest or index`,
  );
  return { ...parsed, index: INDEX_TYPES.has(mediaType) };
}

/** The index's runnable descriptor for each arch, refusing any other platform and any duplicate. */
/**
 * Every descriptor that is not an attestation counts toward a platform, whatever its annotations:
 * an attestation annotation on a descriptor for a runnable platform is refused, any platform but
 * the builds' is refused, and so is a digest the index lists twice. Each arch's entries come back in
 * the index's order, so the first is the one containerd would select.
 */
function platformEntries(index, digest) {
  const entries = Object.fromEntries(ARCHES.map((arch) => [arch, []]));
  for (const descriptor of index.manifests)
    ensure(
      isAttestation(descriptor) || !annotatedAttestation(descriptor),
      `The index ${digest} has ${descriptor.digest} annotated as an attestation for ${platformName(descriptor.platform)}, a platform a consumer can select`,
    );
  const counted = new Map();
  for (const descriptor of index.manifests)
    counted.set(descriptor.digest, (counted.get(descriptor.digest) ?? 0) + 1);
  for (const [listed, times] of counted)
    ensure(times === 1, `The index ${digest} lists ${listed} ${times} times`);
  for (const descriptor of index.manifests.filter((entry) => !isAttestation(entry))) {
    const arch = archOf(descriptor.platform);
    ensure(
      arch !== undefined,
      `The index ${digest} holds ${platformName(descriptor.platform)} (${descriptor.digest}), not ${ARCHES.map((name) => `linux/${name}`).join(" or ")}`,
    );
    entries[arch].push(descriptor);
  }
  return entries;
}

/**
 * The digest `imagetools create` reported for the index it pushed, once that index is the one this
 * job asked for. The tag it pushed can move before anything reads it again, so the digest comes
 * from create's own metadata and the index is read by that digest. Each source is one arch's build,
 * named by the arch its build job recorded: a plain image manifest, or a single-platform index (an
 * attested build) whose one runnable child is the build. The index must map each arch's platform to
 * that arch's build and to nothing else, hold every source's children (attestations too), and hold
 * nothing more. A platform label swapped between two descriptors, a platform listed twice or
 * missing, a variant the build does not have, a digest listed twice, and an attestation annotation
 * on a descriptor for a runnable platform are each refused: only an annotated unknown/unknown
 * descriptor is an attestation (isAttestation).
 */
export function checkIndex(metadata, indexBytes, sources) {
  const reported = [
    metadata["containerimage.digest"],
    metadata["containerimage.descriptor"]?.digest,
  ].filter((value) => value !== undefined);
  ensure(
    reported.length > 0 && reported.every((value) => value === reported[0]),
    "imagetools create reported no index digest, or two different ones",
  );
  const [digest] = reported;
  const index = document(indexBytes, digest, "The created index");
  ensure(index.index, `The created ${digest} is a single image manifest, not a multi-arch index`);
  ensure(
    sources.length === ARCHES.length &&
      ARCHES.every((arch) => sources.filter((source) => source.arch === arch).length === 1),
    `check-index needs exactly one source per arch (${ARCHES.join(", ")}), not ${sources.map(({ arch }) => arch).join(", ") || "none"}`,
  );
  const entries = platformEntries(index, digest);
  // platformEntries refused any digest listed twice, so each descriptor is counted once here.
  const children = new Set(index.manifests.map((descriptor) => descriptor.digest));
  const expected = new Set();
  for (const { arch, digest: source, bytes } of sources) {
    const parsed = document(bytes, source, `The ${arch} source ${source}`);
    let build = source;
    if (parsed.index) {
      const runnable = parsed.manifests.filter((descriptor) => !isAttestation(descriptor));
      ensure(
        runnable.length === 1,
        `The ${arch} source ${source} is an index of more than one platform`,
      );
      build = runnable[0].digest;
    }
    ensure(
      entries[arch].length === 1,
      `The created index has ${entries[arch].length} linux/${arch} entries (${entries[arch].map((entry) => entry.digest).join(", ") || "none"}), not one`,
    );
    ensure(
      entries[arch][0].digest === build,
      `The created index maps linux/${arch} to ${entries[arch][0].digest}, not ${build}, the ${arch} build`,
    );
    const wanted = parsed.index
      ? parsed.manifests.map((descriptor) => descriptor.digest)
      : [source];
    for (const child of wanted) {
      ensure(
        children.has(child),
        `The created index lacks ${child}, from the ${arch} source ${source}`,
      );
      expected.add(child);
    }
  }
  const extra = [...children].filter((child) => !expected.has(child));
  ensure(extra.length === 0, `The created index holds ${extra.join(", ")}, from no source`);
  return digest;
}

/**
 * The digest the index <bytes>, read by <digest>, maps <arch>'s platform to: what a consumer pulling
 * the index for that platform gets. containerd takes the first descriptor whose platform matches,
 * annotations aside; exactly one may match (platformEntries refuses the rest), so the first is the
 * only one and it is the one the binding checked.
 */
export function selectPlatform(bytes, digest, arch) {
  ensure(ARCHES.includes(arch), `No build for ${arch}`);
  const index = document(bytes, digest, `The index ${digest}`);
  ensure(index.index, `${digest} is a single image manifest, not a multi-arch index`);
  const entries = platformEntries(index, digest)[arch];
  ensure(
    entries.length === 1,
    `The index ${digest} has ${entries.length} linux/${arch} entries, not one`,
  );
  return entries[0].digest;
}

function main([command, ...args]) {
  const { env } = process;
  switch (`${command}:${args.length}`) {
    case "write:1": {
      const manifest = buildManifest({
        version: env.VERSION,
        commit: env.COMMIT,
        digests: env.DIGESTS,
        indexes: env.INDEXES,
      });
      writeFileSync(args[0], `${JSON.stringify(manifest, null, 2)}\n`);
      return JSON.stringify(manifest);
    }
    case "digest:3": {
      const [file, image, arch] = args;
      ensure(IMAGES.includes(image) && ARCHES.includes(arch), `No ${image} for ${arch}`);
      return readManifest(file).images[image].platforms[arch];
    }
    case "select:3": {
      const [file, digest, arch] = args;
      return selectPlatform(readFileSync(file), digest, arch);
    }
    default:
      if (command === "check-index" && args.length >= 3) {
        const [metadata, index, ...given] = args;
        const sources = given.map((entry) => {
          const [arch, digest, file] = entry.split("=");
          ensure(
            ARCHES.includes(arch) && file !== undefined && entry.split("=").length === 3,
            `${entry} is not <arch>=<digest>=<file>`,
          );
          return { arch, digest, bytes: readFileSync(file) };
        });
        return checkIndex(JSON.parse(readFileSync(metadata, "utf8")), readFileSync(index), sources);
      }
      throw new Refused(
        "usage: release-manifest.mjs write <out> | digest <manifest> <image> <arch> | select <index> <index digest> <arch> | check-index <metadata> <index> <arch>=<digest>=<source>...",
      );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${main(process.argv.slice(2))}\n`);
  } catch (error) {
    console.error(`::error::${error.message}`);
    process.exit(1);
  }
}
