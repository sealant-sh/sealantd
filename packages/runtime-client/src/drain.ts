import type { Duplex } from "node:stream";

export class Drain {
  readonly #stream: Duplex;
  #failure: Error | undefined;
  #waiters = new Set<{ resolve: () => void; reject: (error: Error) => void }>();

  constructor(stream: Duplex) {
    this.#stream = stream;
    stream.on("drain", () => {
      for (const waiter of this.#waiters) waiter.resolve();
      this.#waiters.clear();
    });
    stream.on("error", (error: Error) => this.fail(error));
  }

  wait(): Promise<void> {
    const stream = this.#stream;
    // Node emits no `drain` after `end()`, so a waiter registered then would never settle.
    if (!this.#failure && (stream.destroyed || stream.writableEnded)) {
      this.#failure = new Error("connection closed");
    }
    if (this.#failure) return Promise.reject(this.#failure);
    if (!stream.writableNeedDrain) return Promise.resolve();
    return new Promise((resolve, reject) => this.#waiters.add({ resolve, reject }));
  }

  fail(error: Error): void {
    this.#failure ??= error;
    for (const waiter of this.#waiters) waiter.reject(this.#failure);
    this.#waiters.clear();
  }
}
