// @sealant/runtime-client/effect
//
// The trace context of the Effect fiber that is calling the client, for `ClientOptions.traceContext`:
//
//   SealantClient.fromStream(duplex, { traceContext: effectTraceContext })
//
// A client method called from an Effect (`Effect.tryPromise(() => client.exec(...))`) runs its
// first synchronous step inside the calling fiber, which is when the client reads the hook. The
// request is then traced under that fiber's current span. `effect` is an optional peer dependency:
// only this entry point imports it.

import { Context, Fiber, Tracer } from "effect";

import type { TraceInput } from "./wire.js";

/**
 * The current fiber's span as a W3C trace context, or undefined when no fiber is running or it is
 * in no span.
 */
export function effectTraceContext(): TraceInput | undefined {
  const fiber = Fiber.getCurrent();
  if (fiber === undefined) return undefined;
  const span = Context.getOrUndefined(fiber.context, Tracer.ParentSpan);
  if (span === undefined) return undefined;
  return `00-${span.traceId}-${span.spanId}-${span.sampled ? "01" : "00"}`;
}
