// `process.started` never carries argument text: `args` stays in the schema, always empty, and
// `argCount` / `argLengths` (UTF-8 bytes per argument) describe the arguments. These are the JSON
// names Sealant Core's normalizer reads from the payload (protobuf JSON, camelCase).

import { test } from "node:test";
import assert from "node:assert/strict";

import { fromBinary, toBinary, toJson } from "@bufbuild/protobuf";

import { create, ProcessStartedSchema } from "@sealant/runtime-protocol";

test("ProcessStarted's argument fields use Core's JSON names", () => {
  const byName = new Map(ProcessStartedSchema.fields.map((f) => [f.name, f]));
  assert.equal(byName.get("arg_count")?.jsonName, "argCount");
  assert.equal(byName.get("arg_count")?.number, 8);
  assert.equal(byName.get("arg_lengths")?.jsonName, "argLengths");
  assert.equal(byName.get("arg_lengths")?.number, 9);
  assert.equal(byName.get("args")?.number, 5);

  const started = create(ProcessStartedSchema, {
    pid: 7,
    pgid: 7,
    executable: "/bin/sh",
    cwd: "/workspace",
    startedAt: 1n,
    argCount: 4,
    argLengths: [20, 0, 16, 13],
  });
  assert.deepEqual(toJson(ProcessStartedSchema, started, { alwaysEmitImplicit: true }), {
    pid: 7,
    pgid: 7,
    pidfd: false,
    executable: "/bin/sh",
    args: [],
    cwd: "/workspace",
    startedAt: "1",
    argCount: 4,
    argLengths: [20, 0, 16, 13],
  });

  const back = fromBinary(ProcessStartedSchema, toBinary(ProcessStartedSchema, started));
  assert.equal(back.argCount, 4);
  assert.deepEqual(back.argLengths, [20, 0, 16, 13]);
  assert.deepEqual(back.args, []);
});
