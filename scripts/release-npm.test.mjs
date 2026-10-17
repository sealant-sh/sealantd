// release.yml's npm job, run as written: its floor and republish blocks against a stub npm registry
// on 127.0.0.1, with the tarballs crafted the ways three reviews found to fool a check of the tarball
// as built; and normalize-npm-tarball.mjs, which the pack job runs and whose --check the job carries
// written out. Ported from sealant-sh/sealant tooling/scripts/release-npm.test.mjs (itself from
// sealant-sh/mend scripts/republish.test.mjs), for sealantd's two runtime packages, whose floor is
// npm's `latest` alone. (republish.test.mjs is next.yml's.)
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import { parse } from "yaml";

const root = fileURLToPath(new URL("../", import.meta.url));
const workflow = readFileSync(path.join(root, ".github/workflows/release.yml"), "utf8");
const npmStep = () =>
  parse(workflow).jobs.npm.steps.find((entry) => entry.name === "Publish to npm").run;
// npm's bundled pacote by default; REPUBLISH_TEST_PACOTE runs the same tests against another one.
const PACOTE =
  process.env.REPUBLISH_TEST_PACOTE ??
  path.join(
    execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim(),
    "npm/node_modules/pacote",
  );

/** The `# --- <name> ---` block of the npm step, unindented. */
const section = (text, name) => {
  const begin = text.indexOf(`# --- ${name} ---`);
  const end = text.indexOf(`# --- end ${name} ---`, begin);
  assert.ok(begin >= 0 && end > begin, `the npm step carries the ${name} block`);
  return text.slice(begin, end);
};
/** The floor block (it defines registry_get), then the republish block. */
const block = [section(npmStep(), "floor"), section(npmStep(), "republish")].join("\n");

/** A ustar archive of `entries` (name → text), names as given, so any path trick can be written. */
const tarGz = (entries) => {
  const blocks = [];
  for (const [name, text] of entries) {
    const content = Buffer.from(text);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100);
    header.write("0000644\0", 100);
    header.write("0000000\0", 108);
    header.write("0000000\0", 116);
    header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124);
    header.write("00000000000\0", 136);
    header.write("        ", 148);
    header.write("0", 156);
    header.write("ustar\0", 257);
    header.write("00", 263);
    const sum = [...header].reduce((total, byte) => total + byte, 0);
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
    blocks.push(header, content, Buffer.alloc((512 - (content.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
};

const PROTOCOL = "@sealant/runtime-protocol";
const CLIENT = "@sealant/runtime-client";
const PACKAGES = [PROTOCOL, CLIENT];
const COMMIT = "c0ffee";
const VERSION = "1.3.0";
/** A normalized manifest, as normalize-npm-tarball.mjs writes one; `extra` adds what it would drop. */
const manifest = (name, version, extra = {}) =>
  JSON.stringify({
    name,
    version,
    type: "module",
    exports: { ".": { types: "./dist/index.d.ts", import: "./dist/index.js" } },
    files: ["dist"],
    dependencies: {
      "@bufbuild/protobuf": "^2.12.0",
      ...(name === CLIENT ? { [PROTOCOL]: version } : {}),
    },
    gitHead: COMMIT,
    publishConfig: { access: "public" },
    ...extra,
  });
const goodEntries = (name, version = VERSION, extra = {}) => [
  ["package/package.json", manifest(name, version, extra)],
  ["package/dist/index.js", "export {};\n"],
  ["package/dist/index.d.ts", "export {};\n"],
];
const sha512 = (bytes) => createHash("sha512").update(bytes).digest();
const integrityOf = (bytes) => `sha512-${sha512(bytes).toString("base64")}`;
const tarballName = (name, version) => `${name.slice(1).replace("/", "-")}-${version}.tgz`;

/**
 * A stub registry: GET packument and dist-tags, PUT publish, PUT dist-tag. It keeps each published
 * tarball's bytes; `forgeIntegrity` serves another dist.integrity than the one npm sent, as a
 * registry that changed the bytes would.
 */
const registry = async (t, seed = {}, { forgeIntegrity = false, distTagsStatus } = {}) => {
  const packages = new Map(Object.entries(structuredClone(seed)));
  const log = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      const url = decodeURIComponent(request.url ?? "");
      const tagMatch = /^\/-\/package\/(.+)\/dist-tags\/([^/]+)$/.exec(url);
      if (request.method === "PUT" && tagMatch !== null) {
        packages.get(tagMatch[1])["dist-tags"][tagMatch[2]] = JSON.parse(body);
        log.push({ distTag: tagMatch[2], version: JSON.parse(body) });
        response.writeHead(200).end("{}");
        return;
      }
      const tagsMatch = /^\/-\/package\/(.+)\/dist-tags$/.exec(url);
      if (request.method === "GET" && tagsMatch !== null && distTagsStatus !== undefined) {
        response.writeHead(distTagsStatus).end("{}");
        return;
      }
      if (request.method === "GET" && tagsMatch !== null) {
        const record = packages.get(tagsMatch[1]);
        if (record === undefined) response.writeHead(404).end("{}");
        else
          response
            .writeHead(200, { "content-type": "application/json" })
            .end(JSON.stringify(record["dist-tags"]));
        return;
      }
      const name = url.slice(1);
      if (request.method === "GET") {
        const record = packages.get(name);
        if (record === undefined) response.writeHead(404).end("{}");
        else
          response
            .writeHead(200, { "content-type": "application/json" })
            .end(JSON.stringify(record));
        return;
      }
      if (request.method === "PUT") {
        const published = JSON.parse(body);
        const record = packages.get(name) ?? { name, versions: {}, "dist-tags": {} };
        if (forgeIntegrity)
          for (const entry of Object.values(published.versions))
            entry.dist.integrity = `sha512-${Buffer.alloc(64).toString("base64")}`;
        Object.assign(record.versions, published.versions);
        Object.assign(record["dist-tags"], published["dist-tags"]);
        const [version] = Object.keys(published.versions);
        packages.set(name, record);
        log.push({
          name,
          publish: version,
          distTags: published["dist-tags"],
          manifest: published.versions[version],
          bytes: Buffer.from(Object.values(published["_attachments"])[0].data, "base64"),
        });
        response.writeHead(201).end("{}");
        return;
      }
      response.writeHead(405).end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  return { url: `http://127.0.0.1:${server.address().port}/`, log, packages };
};

/** Both packages at `latest` 1.2.2, plus `versions` (name → {version → record}). */
const seeded = (versions = {}, distTags = { latest: "1.2.2" }) =>
  Object.fromEntries(
    PACKAGES.map((name) => [
      name,
      {
        name,
        versions: { "1.2.2": { gitHead: "older" }, ...versions[name] },
        "dist-tags": { ...distTags },
      },
    ]),
  );

/**
 * This run's artifacts in `directory`: npm/ holding a tarball of each package (`entries` by name
 * replaces one), release/ the manifest recording them (`record` overrides its fields); `tamper`
 * replaces one tarball's bytes after the manifest recorded them; `artifact` adds files to npm/.
 */
const artifacts = (
  directory,
  { version = VERSION, entries = {}, record = {}, tamper = {}, artifact = {} } = {},
) => {
  for (const dir of ["npm", "release"]) mkdirSync(path.join(directory, dir));
  const bytes = {};
  const packages = {};
  for (const name of PACKAGES) {
    bytes[name] = tarGz(entries[name] ?? goodEntries(name, version));
    const digest = sha512(bytes[name]);
    packages[name] = {
      file: tarballName(name, version),
      sha512: digest.toString("hex"),
      integrity: `sha512-${digest.toString("base64")}`,
    };
    writeFileSync(
      path.join(directory, "npm", tarballName(name, version)),
      tamper[name] === undefined ? bytes[name] : tarGz(tamper[name]),
    );
  }
  for (const [file, text] of Object.entries(artifact))
    writeFileSync(path.join(directory, "npm", file), text);
  writeFileSync(
    path.join(directory, "release", "release-manifest.json"),
    JSON.stringify({ version, commit: COMMIT, packages, ...record }),
  );
  return bytes;
};

const npmEnvironment = (directory, stub) => {
  const npmrc = path.join(directory, "npmrc");
  writeFileSync(npmrc, `${stub.url.replace("http:", "")}:_authToken=test\n`);
  return {
    REPUBLISH_TEST_PACOTE: PACOTE,
    REPUBLISH_TEST_WAIT: "0",
    RELEASE_TEST_RETRY_MS: "1",
    NPM_CONFIG_REGISTRY: stub.url,
    NPM_CONFIG_USERCONFIG: npmrc,
  };
};
const collect = async (child) => {
  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));
  const status = await new Promise((resolve) => child.on("close", resolve));
  return { status, output };
};

/** publish_release over this run's artifacts, against the stub; `verify` passes --verify-only. */
const publish = async (t, stub, { verify = false, version = VERSION, ...options } = {}) => {
  const directory = mkdtempSync(path.join(tmpdir(), "sealantd-release-npm-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const bytes = artifacts(directory, { version, ...options });
  const script = `set -euo pipefail\n${block}\npublish_release ${verify ? "--verify-only " : ""}"$@"`;
  const child = spawn(
    "bash",
    ["-c", script, "republish", `${directory}/npm`, `${directory}/release`, version, COMMIT],
    { cwd: directory, env: { ...process.env, ...npmEnvironment(directory, stub) } },
  );
  return { ...(await collect(child)), bytes };
};

test("both tarballs are published under latest as they are, the protocol first, and read back", async (t) => {
  const stub = await registry(t, seeded());
  const { status, output, bytes } = await publish(t, stub);
  assert.equal(status, 0, output);
  assert.deepEqual(
    stub.log.map(({ name, publish: version, distTags }) => [name, version, distTags]),
    [
      [PROTOCOL, VERSION, { latest: VERSION }],
      [CLIENT, VERSION, { latest: VERSION }],
    ],
  );
  // Not repacked: the registry received the bytes the manifest recorded.
  for (const [at, name] of PACKAGES.entries()) {
    assert.deepEqual(stub.log[at].bytes, bytes[name]);
    assert.equal(stub.log[at].manifest.dist.integrity, integrityOf(bytes[name]));
    assert.equal(stub.log[at].manifest.gitHead, COMMIT);
  }
  assert.equal((output.match(/published with the integrity this run packed/g) ?? []).length, 2);
});

test("a tarball whose sha512 is not the manifest's is refused before npm publishes either", async (t) => {
  const stub = await registry(t, seeded());
  const result = await publish(t, stub, {
    tamper: { [CLIENT]: [...goodEntries(CLIENT), ["package/dist/extra.js", "evil();\n"]] },
  });
  assert.notEqual(result.status, 0, result.output);
  assert.match(
    result.output,
    /sealant-runtime-client-1\.3\.0\.tgz has another sha512 than the release manifest records/,
  );
  assert.equal(stub.log.length, 0);
});

test("a release manifest of another version, commit, file or package set is refused before npm runs", async (t) => {
  for (const [record, problem] of [
    [{ version: "1.2.9" }, /is for 1\.2\.9, not 1\.3\.0/],
    [{ commit: "beef" }, /is from beef, not c0ffee/],
    [
      { packages: { [PROTOCOL]: { file: "other.tgz", sha512: "0", integrity: "sha512-x" } } },
      /names other\.tgz for @sealant\/runtime-protocol/,
    ],
    [{ packages: {} }, /names undefined for @sealant\/runtime-protocol/],
  ]) {
    const stub = await registry(t, seeded());
    const result = await publish(t, stub, { record });
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, problem);
    assert.equal(stub.log.length, 0);
  }
});

test("a registry serving another integrity after the publish is an incident", async (t) => {
  const stub = await registry(t, seeded(), { forgeIntegrity: true });
  const result = await publish(t, stub);
  assert.notEqual(result.status, 0, result.output);
  assert.match(
    result.output,
    /::error::INCIDENT: @sealant\/runtime-protocol@1\.3\.0 .*Do not republish: deprecate/,
  );
  // The job stops at the first incident: the client is not published over it.
  assert.deepEqual(
    stub.log.map(({ name }) => name),
    [PROTOCOL],
  );
});

test("a tarball that is not normalized is refused, never rewritten: tag, scripts, publishConfig, .npmrc, binding.gyp", async (t) => {
  for (const [entries, problem] of [
    [goodEntries(CLIENT, VERSION, { tag: "next" }), /it keeps tag/],
    [
      goodEntries(CLIENT, VERSION, { scripts: { prepublishOnly: "pnpm run build" } }),
      /it keeps scripts/,
    ],
    [
      goodEntries(CLIENT, VERSION, { devDependencies: { typescript: "6.0.3" } }),
      /it keeps devDependencies/,
    ],
    [
      goodEntries(CLIENT, VERSION, {
        publishConfig: { access: "public", registry: "https://evil.example/" },
      }),
      /publishConfig holds more than access/,
    ],
    [
      [...goodEntries(CLIENT), ["package/dist/.npmrc", "registry=https://evil.example/\n"]],
      /it holds dist\/\.npmrc/,
    ],
    [[...goodEntries(CLIENT), ["package/binding.gyp", "{ 'targets': [] }"]], /binding\.gyp/],
    [goodEntries(CLIENT, VERSION, { gitHead: "forged" }), /gitHead forged, not c0ffee/],
    [goodEntries(CLIENT, "1.3.1"), /version 1\.3\.1, not 1\.3\.0/],
  ]) {
    const stub = await registry(t, seeded());
    const result = await publish(t, stub, { entries: { [CLIENT]: entries } });
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, problem);
    // Both are checked before either publishes.
    assert.equal(stub.log.length, 0);
  }
});

test("the client depends on the protocol at exactly this version, never a range, alias or workspace", async (t) => {
  for (const spec of ["^1.3.0", "workspace:*", "1.2.2", `npm:${PROTOCOL}-next@1.3.0`]) {
    const stub = await registry(t, seeded());
    const result = await publish(t, stub, {
      entries: { [CLIENT]: goodEntries(CLIENT, VERSION, { dependencies: { [PROTOCOL]: spec } }) },
    });
    assert.notEqual(result.status, 0, spec);
    assert.match(result.output, /@sealant\/runtime-protocol/, spec);
    assert.equal(stub.log.length, 0, spec);
  }
});

test("a dry-run or prerelease version is refused by the publisher", async (t) => {
  for (const version of ["1.3.0-dryrun.38931186422.1", "1.3.0-next.4"]) {
    const stub = await registry(t, seeded());
    const result = await publish(t, stub, {
      version,
      entries: Object.fromEntries(PACKAGES.map((name) => [name, goodEntries(name, version)])),
    });
    assert.notEqual(result.status, 0, version);
    assert.match(result.output, /is not a latest version/, version);
    assert.equal(stub.log.length, 0, version);
  }
});

test("an artifact holding anything but the expected tarballs is refused before npm runs", async (t) => {
  for (const [file, text] of [
    [".npmrc", "https-proxy=http://127.0.0.1:9/\nstrict-ssl=false\n"],
    ["extra.tgz", "x"],
  ]) {
    const stub = await registry(t, seeded());
    const result = await publish(t, stub, { artifact: { [file]: text } });
    assert.notEqual(result.status, 0, file);
    assert.match(result.output, /more than the expected tarballs/);
    assert.equal(stub.log.length, 0);
  }
});

test("a version already published from this commit is done once its integrity checks; from another, refused", async (t) => {
  const bytes = Object.fromEntries(PACKAGES.map((name) => [name, tarGz(goodEntries(name))]));
  const ours = (name) => ({
    [VERSION]: { gitHead: COMMIT, dist: { integrity: integrityOf(bytes[name]) } },
  });
  const done = await registry(t, seeded({ [PROTOCOL]: ours(PROTOCOL), [CLIENT]: ours(CLIENT) }));
  const again = await publish(t, done);
  assert.equal(again.status, 0, again.output);
  assert.equal(done.log.length, 0);
  const other = await registry(t, seeded({ [PROTOCOL]: { [VERSION]: { gitHead: "elsewhere" } } }));
  const refused = await publish(t, other);
  assert.notEqual(refused.status, 0);
  assert.match(refused.output, /@sealant\/runtime-protocol@1\.3\.0 was published from elsewhere/);
  assert.equal(other.log.length, 0);
});

test("a registry failure stops the job instead of being read as nothing published", async (t) => {
  const stub = await registry(t, {});
  const { status, output } = await publish(t, stub);
  assert.notEqual(status, 0);
  assert.match(output, /answered 404/);
  assert.equal(stub.log.length, 0);
});

// --- verify-only, at the floor ---

test("verify-only republishes nothing and moves no dist-tag when npm holds both", async (t) => {
  const bytes = Object.fromEntries(PACKAGES.map((name) => [name, tarGz(goodEntries(name))]));
  const ours = (name) => ({
    [VERSION]: { gitHead: COMMIT, dist: { integrity: integrityOf(bytes[name]) } },
  });
  const stub = await registry(
    t,
    seeded({ [PROTOCOL]: ours(PROTOCOL), [CLIENT]: ours(CLIENT) }, { latest: VERSION }),
  );
  const result = await publish(t, stub, { verify: true });
  assert.equal(result.status, 0, result.output);
  assert.equal((result.output.match(/a same-version retry publishes nothing/g) ?? []).length, 2);
  assert.equal(stub.log.length, 0);
  // Other bytes under the version are the incident.
  const forged = await registry(
    t,
    seeded(
      {
        [PROTOCOL]: ours(PROTOCOL),
        [CLIENT]: { [VERSION]: { gitHead: COMMIT, dist: { integrity: "sha512-other" } } },
      },
      { latest: VERSION },
    ),
  );
  const incident = await publish(t, forged, { verify: true });
  assert.notEqual(incident.status, 0);
  assert.match(incident.output, /::error::INCIDENT: @sealant\/runtime-client@1\.3\.0/);
  assert.equal(forged.log.length, 0);
});

test("verify-only finishes a release that stopped between the two packages, and nothing else", async (t) => {
  const protocol = tarGz(goodEntries(PROTOCOL));
  // An earlier attempt published the protocol from this commit; the client never published.
  const partial = await registry(
    t,
    seeded({
      [PROTOCOL]: { [VERSION]: { gitHead: COMMIT, dist: { integrity: integrityOf(protocol) } } },
    }),
  );
  partial.packages.get(PROTOCOL)["dist-tags"].latest = VERSION;
  const finished = await publish(t, partial, { verify: true });
  assert.equal(finished.status, 0, finished.output);
  assert.match(
    finished.output,
    /@sealant\/runtime-client@1\.3\.0 is not published yet: an earlier attempt stopped/,
  );
  assert.deepEqual(
    partial.log.map(({ name, distTags }) => [name, distTags]),
    [[CLIENT, { latest: VERSION }]],
  );
  // npm holding neither, at the floor, means a marker was moved by hand: nothing publishes.
  const handMoved = await registry(t, seeded());
  const moved = await publish(t, handMoved, { verify: true });
  assert.notEqual(moved.status, 0);
  assert.match(
    moved.output,
    /is the stable floor, but npm does not hold @sealant\/runtime-protocol@1\.3\.0: a marker was moved by hand/,
  );
  assert.equal(handMoved.log.length, 0);
  // The protocol from another commit is not this release's partial publish.
  const foreign = await registry(
    t,
    seeded({ [PROTOCOL]: { [VERSION]: { gitHead: "elsewhere" } } }),
  );
  const refused = await publish(t, foreign, { verify: true });
  assert.notEqual(refused.status, 0);
  assert.match(refused.output, /was published from elsewhere/);
  assert.equal(foreign.log.length, 0);
});

// --- the whole step, with the floor ---

/**
 * The npm job's "Publish to npm" step as written (its --provenance left out: it needs GitHub's
 * OIDC), over this run's artifacts of `version`, against the stub npm registry.
 */
const publishStep = async (t, stub, { version = VERSION, environment = {} } = {}) => {
  const directory = mkdtempSync(path.join(tmpdir(), "sealantd-release-npm-step-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  artifacts(directory, {
    version,
    entries: Object.fromEntries(PACKAGES.map((name) => [name, goodEntries(name, version)])),
  });
  const run = npmStep();
  assert.equal(run.split(" --provenance").length, 2);
  const child = spawn("bash", ["-c", run.replace(" --provenance", "")], {
    env: {
      ...process.env,
      GITHUB_WORKSPACE: directory,
      GITHUB_SHA: COMMIT,
      GITHUB_STEP_SUMMARY: path.join(directory, "summary.md"),
      VERSION: version,
      ...npmEnvironment(directory, stub),
      ...environment,
    },
  });
  return collect(child);
};
/** Sets each package's `latest` in `stub`: one value for both, or by name (undefined: none). */
const setLatest = (stub, latest) => {
  for (const name of PACKAGES) {
    const value = typeof latest === "object" && latest !== null ? latest[name] : latest;
    stub.packages.get(name)["dist-tags"] =
      value === undefined ? { next: "1.4.0-next.9" } : { latest: value, next: "1.4.0-next.9" };
  }
};

test("stable npm: above the floor both tarballs publish; below it, by either package's latest, nothing does", async (t) => {
  const lower = await registry(t, seeded());
  const published = await publishStep(t, lower);
  assert.equal(published.status, 0, published.output);
  assert.match(
    published.output,
    /Stable floor: 1\.2\.2 npm:@sealant\/runtime-protocol@latest; 1\.3\.0 may publish/,
  );
  assert.deepEqual(
    lower.log.map(({ name, distTags }) => [name, distTags]),
    [
      [PROTOCOL, { latest: VERSION }],
      [CLIENT, { latest: VERSION }],
    ],
  );
  for (const [marker, latest, named] of [
    [
      "the protocol's npm latest",
      { [PROTOCOL]: "1.4.0", [CLIENT]: "1.2.2" },
      /npm:@sealant\/runtime-protocol@latest/,
    ],
    [
      "the client's npm latest",
      { [PROTOCOL]: "1.2.2", [CLIENT]: "1.4.0" },
      /npm:@sealant\/runtime-client@latest/,
    ],
  ]) {
    const stub = await registry(t, seeded());
    setLatest(stub, latest);
    const refused = await publishStep(t, stub);
    assert.equal(refused.status, 1, marker);
    assert.match(refused.output, /1\.3\.0 is below the stable floor 1\.4\.0/, marker);
    assert.match(refused.output, named, marker);
    assert.match(
      refused.output,
      /a backport such as 0\.38\.2 after 0\.39\.0 is refused on purpose/,
    );
    assert.equal(stub.log.length, 0, marker);
  }
  // A backport: 1.3.0 after 1.3.1 is refused, never published under latest.
  const newer = await registry(t, seeded());
  setLatest(newer, "1.3.1");
  const backport = await publishStep(t, newer);
  assert.equal(backport.status, 1);
  assert.match(backport.output, /1\.3\.0 is below the stable floor 1\.3\.1/);
  assert.equal(newer.log.length, 0);
});

test("stable npm compares the floor as numbers, and no latest at all is no floor", async (t) => {
  const tens = await registry(t, seeded());
  setLatest(tens, { [PROTOCOL]: "1.10.0", [CLIENT]: "1.9.0" });
  const refused = await publishStep(t, tens);
  assert.equal(refused.status, 1);
  assert.match(
    refused.output,
    /below the stable floor 1\.10\.0 \(npm:@sealant\/runtime-protocol@latest\)/,
  );
  assert.equal(tens.log.length, 0);
  // 1.2.10 is below 1.3.0 as numbers, though above it as text.
  const below = await registry(t, seeded());
  setLatest(below, { [PROTOCOL]: "1.2.9", [CLIENT]: "1.2.10" });
  const above = await publishStep(t, below);
  assert.equal(above.status, 0, above.output);
  assert.match(
    above.output,
    /Stable floor: 1\.2\.10 npm:@sealant\/runtime-client@latest; 1\.3\.0 may publish/,
  );
  assert.equal(below.log.length, 2);
  const none = await registry(t, seeded());
  setLatest(none, undefined);
  const first = await publishStep(t, none);
  assert.equal(first.status, 0, first.output);
  assert.match(first.output, /Stable floor: none; 1\.3\.0 may publish/);
  assert.equal(none.log.length, 2);
});

test("stable npm at the floor publishes nothing and only verifies, or finishes this release's own partial publish", async (t) => {
  const bytes = Object.fromEntries(PACKAGES.map((name) => [name, tarGz(goodEntries(name))]));
  const ours = (name) => ({
    [VERSION]: { gitHead: COMMIT, dist: { integrity: integrityOf(bytes[name]) } },
  });
  const retried = await registry(
    t,
    seeded({ [PROTOCOL]: ours(PROTOCOL), [CLIENT]: ours(CLIENT) }, { latest: VERSION }),
  );
  const retry = await publishStep(t, retried);
  assert.equal(retry.status, 0, retry.output);
  assert.match(retry.output, /1\.3\.0 may retry/);
  assert.equal((retry.output.match(/a same-version retry publishes nothing/g) ?? []).length, 2);
  assert.equal(retried.log.length, 0);
  // The protocol at the floor alone (an attempt that stopped before the client): the client publishes.
  const partial = await registry(t, seeded({ [PROTOCOL]: ours(PROTOCOL) }));
  partial.packages.get(PROTOCOL)["dist-tags"].latest = VERSION;
  const finished = await publishStep(t, partial);
  assert.equal(finished.status, 0, finished.output);
  assert.match(
    finished.output,
    /Stable floor: 1\.3\.0 npm:@sealant\/runtime-protocol@latest; 1\.3\.0 may retry/,
  );
  assert.deepEqual(
    partial.log.map(({ name }) => name),
    [CLIENT],
  );
  // A marker at the version with neither package published: moved by hand.
  const handMoved = await registry(t, seeded());
  setLatest(handMoved, VERSION);
  const moved = await publishStep(t, handMoved);
  assert.equal(moved.status, 1);
  assert.match(moved.output, /a marker was moved by hand/);
  assert.equal(handMoved.log.length, 0);
  // Other bytes already published under the version, at the floor: the incident, nothing published.
  const forged = await registry(
    t,
    seeded(
      {
        [PROTOCOL]: ours(PROTOCOL),
        [CLIENT]: { [VERSION]: { gitHead: COMMIT, dist: { integrity: "sha512-other" } } },
      },
      { latest: VERSION },
    ),
  );
  const incident = await publishStep(t, forged);
  assert.equal(incident.status, 1);
  assert.match(incident.output, /::error::INCIDENT: @sealant\/runtime-client@1\.3\.0/);
  assert.equal(forged.log.length, 0);
});

/** Markers present but malformed: each fails the floor, never reads as absent or as the version it starts with. */
const MALFORMED = [
  ["a prerelease", { latest: "1.3.0-next.2" }, /latest is "1\.3\.0-next\.2", not a plain/],
  ["trailing text", { latest: "1.2.2 invalid" }, /latest is "1\.2\.2 invalid", not a plain/],
  ["a trailing newline", { latest: "1.2.2\n" }, /not a plain/],
  ["null", { latest: null }, /latest is null, not a plain/],
  ["empty", { latest: "" }, /latest is "", not a plain/],
  ["not a string", { latest: 122 }, /latest is 122, not a plain/],
  ["not X.Y.Z", { latest: "1.2" }, /latest is "1\.2", not a plain/],
  ["a leading zero", { latest: "01.2.2" }, /not a plain/],
  // Past 9 digits a part could overflow Bash's 64-bit arithmetic: refused as not plain.
  ["a part of 10 digits", { latest: "1234567890.0.0" }, /not a plain/],
  ["a part past 64 bits", { latest: "9223372036854775808.0.0" }, /not a plain/],
  ["a list", [], /dist-tags is not a JSON object/],
  ["a string", "1.2.2", /dist-tags is not a JSON object/],
];

test("stable npm fails, publishing nothing, on an unreadable or malformed marker", async (t) => {
  for (const [label, change, problem] of [
    ["npm answers 500", { distTagsStatus: 500 }, /the registry answered 500/],
    ["npm answers 403", { distTagsStatus: 403 }, /the registry answered 403/],
  ]) {
    const stub = await registry(t, seeded(), change);
    const result = await publishStep(t, stub);
    assert.equal(result.status, 1, label);
    assert.match(result.output, problem, label);
    assert.equal(stub.log.length, 0, label);
  }
  const unknown = await registry(t, seeded());
  unknown.packages.delete(CLIENT);
  const missing = await publishStep(t, unknown);
  assert.equal(missing.status, 1);
  assert.match(missing.output, /the registry answered 404/);
  assert.equal(unknown.log.length, 0);
  for (const [label, tags, problem] of MALFORMED) {
    const stub = await registry(t, seeded());
    stub.packages.get(CLIENT)["dist-tags"] = tags;
    const result = await publishStep(t, stub);
    assert.equal(result.status, 1, label);
    assert.match(result.output, problem, label);
    assert.match(result.output, /npm:@sealant\/runtime-client dist-tags/, label);
    assert.equal(stub.log.length, 0, label);
  }
  // The largest part accepted still compares as a number, above the release.
  const top = await registry(t, seeded());
  setLatest(top, { [PROTOCOL]: "1.2.2", [CLIENT]: "999999999.0.0" });
  const result = await publishStep(t, top);
  assert.equal(result.status, 1);
  assert.match(result.output, /below the stable floor 999999999\.0\.0/);
  assert.equal(top.log.length, 0);
});

test("stable npm refuses a dry-run or prerelease version, publishing nothing", async (t) => {
  for (const version of ["1.3.0-dryrun.38700000001.1", "1.3.0-next.4"]) {
    const stub = await registry(t, seeded());
    const result = await publishStep(t, stub, { version });
    assert.equal(result.status, 1, version);
    assert.match(
      result.output,
      /the release is '1\.3\.0-[a-z]+\.[0-9.]+', not a plain X\.Y\.Z/,
      version,
    );
    assert.equal(stub.log.length, 0, version);
  }
});

// --- the normalizer the pack job runs, and the publisher's copy of its check ---

const normalizer = fileURLToPath(new URL("./normalize-npm-tarball.mjs", import.meta.url));
const normalize = (args) =>
  spawnSync(process.execPath, [normalizer, ...args], {
    env: { ...process.env, NORMALIZE_PACOTE: PACOTE },
    encoding: "utf8",
  });

test("the normalizer drops what the publisher refuses, repacks once, and its output checks", (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "sealantd-normalize-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const packed = path.join(directory, "packed.tgz");
  // What pnpm pack writes for the client: scripts, devDependencies, publishConfig beyond access.
  writeFileSync(
    packed,
    tarGz([
      ...goodEntries(CLIENT, VERSION, {
        scripts: { build: "tsc -p tsconfig.json", prepublishOnly: "pnpm run build" },
        devDependencies: { typescript: "6.0.3" },
      }),
      ["package/dist/.npmrc", "registry=https://evil.example/\n"],
    ]),
  );
  const expected = [
    "--name",
    CLIENT,
    "--version",
    VERSION,
    "--commit",
    COMMIT,
    "--channel",
    "latest",
  ];
  mkdirSync(path.join(directory, "out"));
  const made = normalize([packed, "--out", path.join(directory, "out"), ...expected]);
  assert.equal(made.status, 0, made.stderr);
  const record = JSON.parse(made.stdout);
  assert.equal(record.file, "sealant-runtime-client-1.3.0.tgz");
  assert.deepEqual(readdirSync(path.join(directory, "out")), [record.file]);
  const out = path.join(directory, "out", record.file);
  assert.equal(record.integrity, integrityOf(readFileSync(out)));
  const checked = normalize(["--check", out, ...expected]);
  assert.equal(checked.status, 0, checked.stderr);
  assert.deepEqual(JSON.parse(checked.stdout), record);
  // The raw pack is refused by --check, never rewritten by it.
  const raw = normalize(["--check", packed, ...expected]);
  assert.equal(raw.status, 1);
  assert.match(raw.stderr, /not normalized: it keeps scripts, devDependencies/);
  // A wrong version or commit is refused when normalizing too.
  for (const [flag, value] of [
    ["--version", "1.3.1"],
    ["--commit", "beef"],
  ]) {
    const args = [...expected];
    args[args.indexOf(flag) + 1] = value;
    assert.equal(
      normalize([packed, "--out", path.join(directory, "out"), ...args]).status,
      1,
      flag,
    );
  }
});

test("the publisher's check and normalize-npm-tarball.mjs --check give the same answers", async (t) => {
  // The publisher runs no repository file, so it carries the check written out; this holds the
  // copy to the script the pack job ran.
  const directory = mkdtempSync(path.join(tmpdir(), "sealantd-npm-parity-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const cases = {
    normalized: goodEntries(CLIENT),
    "the protocol": goodEntries(PROTOCOL),
    "a tag": goodEntries(CLIENT, VERSION, { tag: "latest" }),
    scripts: goodEntries(CLIENT, VERSION, { scripts: { prepare: "x" } }),
    "publishConfig beyond access": goodEntries(CLIENT, VERSION, {
      publishConfig: { access: "public", tag: "x" },
    }),
    "publishConfig without access": goodEntries(CLIENT, VERSION, { publishConfig: {} }),
    "an .npmrc": [...goodEntries(CLIENT), ["package/lib/.npmrc", "x=1\n"]],
    "a binding.gyp": [...goodEntries(CLIENT), ["package/binding.gyp", "{}"]],
    "a forged commit": goodEntries(CLIENT, VERSION, { gitHead: "forged" }),
    "another version": goodEntries(CLIENT, "1.3.1"),
    "a prerelease": goodEntries(CLIENT, "1.3.0-next.4"),
    "a dry-run version": goodEntries(CLIENT, "1.3.0-dryrun.9.1"),
    "an alias": goodEntries(CLIENT, VERSION, {
      dependencies: { [PROTOCOL]: VERSION, a: "npm:b@1" },
    }),
    "a sibling range": goodEntries(CLIENT, VERSION, { dependencies: { [PROTOCOL]: "^1.3.0" } }),
    "a sibling alias": goodEntries(CLIENT, VERSION, {
      dependencies: { [PROTOCOL]: `npm:${PROTOCOL}-next@${VERSION}` },
    }),
  };
  const answers = {};
  for (const [label, entries] of Object.entries(cases)) {
    const tarball = path.join(directory, `${Object.keys(answers).length}.tgz`);
    writeFileSync(tarball, tarGz(entries));
    const name = label === "the protocol" ? PROTOCOL : CLIENT;
    const fromBlock = await new Promise((resolve) => {
      const child = spawn(
        "bash",
        [
          "-c",
          `set -euo pipefail\n${block}\ncheck_tarball "$@"`,
          "check",
          tarball,
          name,
          VERSION,
          COMMIT,
          "latest",
        ],
        { env: { ...process.env, REPUBLISH_TEST_PACOTE: PACOTE }, stdio: "ignore" },
      );
      child.on("close", resolve);
    });
    const script = normalize([
      "--check",
      tarball,
      "--name",
      name,
      "--version",
      VERSION,
      "--commit",
      COMMIT,
      "--channel",
      "latest",
    ]).status;
    answers[label] = [fromBlock === 0, script === 0];
  }
  for (const [label, [byBlock, byScript]] of Object.entries(answers))
    assert.equal(byBlock, byScript, `${label}: block ${byBlock}, script ${byScript}`);
  assert.deepEqual(
    Object.entries(answers)
      .filter(([, [accepted]]) => accepted)
      .map(([label]) => label),
    ["normalized", "the protocol"],
  );
});

// --- the delays ---

test("the npm step logs both delays it runs with, before anything else, and refuses garbage", () => {
  const preamble = npmStep().slice(0, npmStep().indexOf("# --- floor ---"));
  const run = (environment) =>
    spawnSync("bash", ["--noprofile", "--norc", "-e", "-c", preamble], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, ...environment },
    });
  const production = run({});
  assert.equal(production.status, 0, production.stderr);
  assert.match(production.stdout, /^retry backoff: production \(1500 ms × attempt\)$/m);
  assert.match(production.stdout, /^integrity read-back wait: production \(5 s × attempt\)$/m);
  const overridden = run({ RELEASE_TEST_RETRY_MS: "7", REPUBLISH_TEST_WAIT: "0" });
  assert.match(overridden.stdout, /^retry backoff: overridden to 7 ms × attempt$/m);
  assert.match(overridden.stdout, /^integrity read-back wait: overridden to 0 s × attempt$/m);
  const garbage = run({ REPUBLISH_TEST_WAIT: "5s secret-token" });
  assert.notEqual(garbage.status, 0);
  assert.doesNotMatch(garbage.stdout + garbage.stderr, /secret-token/);
  // The read-back sleeps the production 5 s unless a test overrides it, and nowhere else.
  assert.equal(
    (workflow.match(/\bsleep \$\(\(attempt \* \$\{REPUBLISH_TEST_WAIT:-5\}\)\)/g) ?? []).length,
    1,
  );
  // release-overrides.test.mjs keeps every workflow from setting it.
});

test("the npm step, run whole, logs the production delays when no test overrides them", async (t) => {
  const stub = await registry(t, seeded());
  const unset = await publishStep(t, stub, {
    environment: { RELEASE_TEST_RETRY_MS: "", REPUBLISH_TEST_WAIT: "" },
  });
  assert.equal(unset.status, 0, unset.output);
  assert.equal(
    (unset.output.match(/retry backoff: production \(1500 ms × attempt\)/g) ?? []).length,
    1,
  );
  assert.equal(
    (unset.output.match(/integrity read-back wait: production \(5 s × attempt\)/g) ?? []).length,
    1,
  );
  assert.doesNotMatch(unset.output, /overridden/);
});
