---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

A control request can now carry the caller's W3C trace context, so the daemon's work on it shows up in the caller's trace. `ControlRequest` has an optional `trace` field (`TraceContext { traceparent, tracestate }`, field 4). A daemon from before this ignores the field, and a request without it works as before.

`SealantClient.connect`, `fromStream` and `spawn` take a `traceContext` hook. The client calls it as each request starts and sends what it returns. `request(command, { trace })` sets the context for one request, as a `traceparent` string or `{ traceparent, tracestate }`. A malformed context, or a hook that throws, leaves the request untraced and still sends it. Effect callers can pass `effectTraceContext` from the new `@sealant/runtime-client/effect` entry point. It reads the calling fiber's current span, so `Effect.tryPromise(() => client.exec(...))` inside `Effect.withSpan` sends that span as the parent. `effect` is an optional peer dependency, needed only for that entry point.
