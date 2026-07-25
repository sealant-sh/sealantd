// Shared support for the mount / PTY demos: a control connection into a running workspace
// container via `docker exec -i socat` (the same bridge the Core control plane uses).

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { Duplex } from "node:stream";

import { SealantClient } from "@sealant/runtime-client";

export interface DemoConnection {
  client: SealantClient;
  child: ChildProcess;
  /** Abruptly kill the transport (simulates a client crash — no detach, no goodbye). */
  destroy(): void;
}

export function connectToContainer(container: string): DemoConnection {
  const child = spawn(
    "docker",
    ["exec", "-i", container, "socat", "-", "UNIX-CONNECT:/run/sealant/control.sock"],
    { stdio: ["pipe", "pipe", "inherit"] },
  );
  const stream = Duplex.from({ writable: child.stdin!, readable: child.stdout! });
  const client = SealantClient.fromStream(stream);
  return {
    client,
    child,
    destroy() {
      child.kill("SIGKILL");
    },
  };
}

export function jsonish(value: unknown): string {
  return JSON.stringify(
    value,
    (_k, v) => (typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? `<${v.length}b>` : v),
    2,
  );
}

export function textOf(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

export async function withTimeout<T>(label: string, ms: number, p: Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout waiting for ${label}`)), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

export function ok(label: string): void {
  console.log(`  ✔ ${label}`);
}
