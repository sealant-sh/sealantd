// `secretEnv` (`process.secret-env.v1`): the descriptor carries it (tag 14 on ExecArgs, 11 on
// OpenSessionArgs), the client sends it only to a daemon that names the capability on the same
// connection, and the real daemon hands it to the process and records the value masked.

import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { rmSync } from "node:fs";
import { Duplex } from "node:stream";
import { Buffer } from "node:buffer";

import { fromBinary, toBinary } from "@bufbuild/protobuf";

import { SECRET_ENV_CAPABILITY, SealantClient } from "@sealant/runtime-client";
import {
  ClientMessageSchema,
  ExecArgsSchema,
  OpenSessionArgsSchema,
  SessionMode,
  ServerMessageSchema,
  StreamKind,
  create,
  encodeFrame,
  encodeServer,
  type ControlRequest,
} from "@sealant/runtime-protocol";

const VALUE = "fake-pg-password-5d1e";
const secretEnv = [{ key: "PGPASSWORD", value: VALUE }];

test("secretEnv is tag 14 on ExecArgs and 11 on OpenSessionArgs, and round-trips", () => {
  assert.equal(ExecArgsSchema.fields.find((f) => f.name === "secret_env")?.number, 14);
  assert.equal(OpenSessionArgsSchema.fields.find((f) => f.name === "secret_env")?.number, 11);
  const exec = create(ExecArgsSchema, { executable: "/bin/true", secretEnv });
  const back = fromBinary(ExecArgsSchema, toBinary(ExecArgsSchema, exec));
  assert.deepEqual(
    back.secretEnv.map(({ key, value }) => ({ key, value })),
    secretEnv,
  );
  const open = create(OpenSessionArgsSchema, { cols: 80, rows: 24, secretEnv });
  const reopened = fromBinary(OpenSessionArgsSchema, toBinary(OpenSessionArgsSchema, open));
  assert.equal(reopened.secretEnv[0]?.value, VALUE);
});

/** A daemon stand-in that names `supports` and accepts every other request. */
class FakeDaemon extends Duplex {
  readonly requests: ControlRequest[] = [];
  readonly supports: string[];
  /** Capability answers wait for this. */
  hold: Promise<void> = Promise.resolve();
  constructor(supports: string[]) {
    super();
    this.supports = supports;
  }
  _read(): void {}
  _write(chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    const msg = fromBinary(ClientMessageSchema, chunk.subarray(4, 4 + chunk.readUInt32BE(0)));
    if (msg.message.case === "request") {
      const request = msg.message.value;
      this.requests.push(request);
      const result =
        request.command?.command.case === "runtimeGetCapabilities"
          ? { case: "capabilities" as const, value: { supports: this.supports } }
          : { case: "execAccepted" as const, value: { processId: "proc_1" } };
      const response = create(ServerMessageSchema, {
        message: {
          case: "response",
          value: {
            schemaVersion: request.schemaVersion,
            requestId: request.requestId,
            outcome: { outcome: { case: "ok", value: { result } } },
          },
        },
      });
      const answer = () => this.push(encodeFrame(encodeServer(response)));
      if (result.case === "capabilities") void this.hold.then(answer);
      else queueMicrotask(answer);
    }
    cb();
  }
}

test("secretEnv is never sent to a daemon that does not name the capability", async () => {
  const old = new FakeDaemon(["exec.user"]);
  const client = SealantClient.fromStream(old);
  try {
    await assert.rejects(client.exec({ executable: "/bin/true", secretEnv }), /secret-env/);
    await assert.rejects(client.openSession({ cols: 80, rows: 24, secretEnv }), /secret-env/);
    await assert.rejects(client.execAttached({ executable: "/bin/true", secretEnv }), /secret-env/);
    // A raw request, the path Core's requestResult takes, is checked the same way.
    await assert.rejects(
      client.request({ case: "openSession", value: { cols: 80, rows: 24, secretEnv } }),
      /secret-env/,
    );
    assert.deepEqual(
      old.requests.map((r) => r.command?.command.case),
      Array(4).fill("runtimeGetCapabilities"),
    );
    // Without secretEnv nothing is asked first.
    await client.exec({ executable: "/bin/true" });
    assert.equal(old.requests.at(-1)?.command?.command.case, "exec");
  } finally {
    client.close();
  }

  const current = new FakeDaemon([SECRET_ENV_CAPABILITY]);
  const supported = SealantClient.fromStream(current);
  try {
    await supported.exec({ executable: "/bin/true", secretEnv });
    const sent = current.requests.at(-1)?.command?.command;
    assert.equal(sent?.case, "exec");
    assert.equal(sent?.case === "exec" ? sent.value.secretEnv[0]?.value : undefined, VALUE);
  } finally {
    supported.close();
  }
});

const here = dirname(fileURLToPath(import.meta.url));
const binPath = join(resolve(here, "../../.."), "target", "debug", "sealantd");

test("the daemon hands secretEnv to an exec and a pipe session, and records it masked", async () => {
  const socketPath = join(tmpdir(), `sealantd-secret-env-${process.pid}-${Date.now()}.sock`);
  const { client, child } = await SealantClient.spawn({ binPath, socketPath, workspace: tmpdir() });
  try {
    const script = `printf 'len=%s pw=%s' "\${#PGPASSWORD}" "$PGPASSWORD"`;
    const events = client.events();
    const exec = await client.exec({ executable: "/bin/sh", args: ["-c", script], secretEnv });
    const session = await client.openSession({
      shell: "/bin/sh",
      args: ["-c", script],
      cols: 0,
      rows: 0,
      mode: SessionMode.PIPE,
      secretEnv,
    });
    const recorded = new Map<string, string>();
    let exits = 0;
    for await (const event of events) {
      const id = event.processId ?? "";
      if (event.payload.case === "ioChunk" && event.payload.value.stream === StreamKind.STDOUT) {
        const text = Buffer.from(event.payload.value.content ?? new Uint8Array()).toString();
        recorded.set(id, (recorded.get(id) ?? "") + text);
      }
      if (event.payload.case === "processExited" && ++exits === 2) break;
    }
    for (const id of [exec.processId, session.processId]) {
      assert.equal(recorded.get(id), "len=21 pw=***REDACTED***");
    }
    await client.shutdown(200);
  } finally {
    client.close();
    child.kill("SIGKILL");
    rmSync(socketPath, { force: true });
  }
});

/** The `exec` requests a daemon stand-in received, as executable and secret values. */
function execs(daemon: FakeDaemon): Array<[string, string[]]> {
  return daemon.requests.flatMap((r) =>
    r.command?.command.case === "exec"
      ? [[r.command.command.value.executable, r.command.command.value.secretEnv.map((v) => v.value)]]
      : [],
  );
}

test("a call without secretEnv is sent at once, ahead of a later call", async () => {
  const daemon = new FakeDaemon([SECRET_ENV_CAPABILITY]);
  const client = SealantClient.fromStream(daemon);
  try {
    await Promise.all([client.exec({ executable: "/bin/true" }), client.shutdown(10)]);
    assert.deepEqual(
      daemon.requests.map((r) => r.command?.command.case),
      ["exec", "runtimeGracefulShutdown"],
    );
  } finally {
    client.close();
  }
});

test("a call with secretEnv sends its own command, though its options change while it waits", async () => {
  const daemon = new FakeDaemon([SECRET_ENV_CAPABILITY]);
  let release = () => {};
  daemon.hold = new Promise((resolve) => (release = resolve));
  const client = SealantClient.fromStream(daemon);
  try {
    const options = { executable: "/trusted-client", args: ["a"], secretEnv: [...secretEnv] };
    const first = client.exec(options);
    options.executable = "/different-client";
    options.args.push("b");
    options.secretEnv = [];
    const second = client.exec(options);
    release();
    await Promise.all([first, second]);
    assert.deepEqual(execs(daemon).sort(), [
      ["/different-client", []],
      ["/trusted-client", [VALUE]],
    ]);
    const trusted = daemon.requests.find(
      (r) => r.command?.command.case === "exec" && r.command.command.value.executable === "/trusted-client",
    );
    assert.deepEqual(trusted?.command?.command.case === "exec" ? trusted.command.command.value.args : [], ["a"]);
  } finally {
    client.close();
  }
});
