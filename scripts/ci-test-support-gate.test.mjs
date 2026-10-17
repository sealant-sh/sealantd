// scripts/ci-test-support-gate.sh fails closed: a dependency graph it cannot read, or one that says
// nothing, fails the gate instead of reading as "test-support is absent" (#182 audit, round 2).
// A fake cargo first on PATH answers each graph read and probe build as the case says, so no Rust
// toolchain is needed.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const gate = path.join(here, "ci-test-support-gate.sh");

// What a graph read answers: `fail` exits 101 as a cargo error would; `absent` and `present` are a
// graph without and with the feature; `empty` succeeds with nothing.
const crates = "sealantd v0.0.0 (/w/crates/sealantd)\\nsealant-capture v0.0.0 (/w/crates/sealant-capture)\\n";
const graphs = {
  absent: `${crates}sealant-capture feature "default"\\nsealantd feature "default"\\n`,
  present: `${crates}sealant-capture feature "test-support"\\nsealantd feature "test-support"\\n`,
  // sealant-capture's off and sealantd's on: the gate reads each crate's feature on its own.
  sealantd: `${crates}sealant-capture feature "default"\\nsealantd feature "test-support"\\n`,
  // sealant-capture's on and sealantd's off.
  capture: `${crates}sealant-capture feature "test-support"\\nsealantd feature "default"\\n`,
  empty: "",
};

const fakeCargo = (t, { normal, dev, grepFails = false }) => {
  const bin = mkdtempSync(path.join(tmpdir(), "ci-test-support-gate-"));
  t.after(() => rmSync(bin, { recursive: true, force: true }));
  const answer = (mode) =>
    mode === "fail" ? 'echo "error: injected" >&2; exit 101' : `printf '${graphs[mode]}'; exit 0`;
  writeFileSync(
    path.join(bin, "cargo"),
    `#!/bin/sh
case "$*" in
*"tree "*"-i sealant-capture"*) exit 0 ;;
*"tree "*"-i sealantd"*) exit 0 ;;
*"tree "*"-e normal,build,features") ${answer(normal)} ;;
*"tree "*"-e normal,build,dev,features") ${answer(dev)} ;;
*"check "*"--features control") exit 0 ;;
*"check "*names-the-manual-clock) echo 'error[E0432]: unresolved import \`sealant_capture::ManualClock\`'; exit 101 ;;
*"check "*injects-a-clock) echo 'error[E0609]: no field \`clock\` on type \`CaptureConfig\`'; exit 101 ;;
*"check "*names-the-dotfiles-hold) echo 'error[E0432]: unresolved import \`sealantd::test_support\`'; exit 101 ;;
esac
echo "fake cargo: unexpected: $*" >&2
exit 99
`,
  );
  chmodSync(path.join(bin, "cargo"), 0o755);
  if (grepFails) {
    // A grep that errs, as an unreadable input or a bad pattern would (exit 2).
    writeFileSync(path.join(bin, "grep"), '#!/bin/sh\necho "grep: injected" >&2\nexit 2\n');
    chmodSync(path.join(bin, "grep"), 0o755);
  }
  return `${bin}${path.delimiter}${process.env.PATH}`;
};

const run = (t, graphsRead) =>
  spawnSync("bash", [gate], {
    encoding: "utf8",
    env: { ...process.env, PATH: fakeCargo(t, graphsRead) },
  });

const passed = "test-support: on in the tests only";

test("with every graph read sound and the probes refused, the gate passes", (t) => {
  const r = run(t, { normal: "absent", dev: "present" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(passed));
});

test("a normal graph that cannot be read fails the gate, not passes as absent", (t) => {
  const r = run(t, { normal: "fail", dev: "present" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /cargo tree -e normal,build,features failed/);
  assert.doesNotMatch(r.stdout, new RegExp(passed));
});

test("a control graph that cannot be read fails the gate", (t) => {
  const r = run(t, { normal: "absent", dev: "fail" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /cargo tree -e normal,build,dev,features failed/);
  assert.doesNotMatch(r.stdout, new RegExp(passed));
});

test("a normal graph read that succeeds empty fails the gate", (t) => {
  const r = run(t, { normal: "empty", dev: "present" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /does not list sealant-capture/);
});

test("the feature in the normal graph fails the gate", (t) => {
  const r = run(t, { normal: "present", dev: "present" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /sealant-capture's test-support is enabled outside the tests/);
});

test("sealantd's feature alone in the normal graph fails the gate", (t) => {
  const r = run(t, { normal: "sealantd", dev: "present" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /sealantd's test-support is enabled outside the tests/);
});

test("a control graph with sealant-capture's feature but not sealantd's fails the gate", (t) => {
  const r = run(t, { normal: "absent", dev: "capture" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /no test turns on sealantd's test-support/);
});

test("a control graph without the feature fails the gate: the check would look for nothing", (t) => {
  const r = run(t, { normal: "absent", dev: "absent" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /checks nothing/);
});

test("a search that errs fails the gate, not reads as a line not found", (t) => {
  const r = run(t, { normal: "absent", dev: "present", grepFails: true });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /grep exited 2/);
  assert.doesNotMatch(r.stdout, new RegExp(passed));
});
