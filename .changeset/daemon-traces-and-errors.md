---
"@sealant/runtime-protocol": minor
---

sealantd can send its traces and errors to Sentry. Set `SEALANT_SENTRY_DSN` on the daemon, and optionally `SEALANT_SENTRY_ENVIRONMENT`, `SEALANT_SENTRY_RELEASE` and `SEALANT_SENTRY_TRACES_SAMPLE_RATE`. `SEALANT_OTEL_EXPORTER_OTLP_ENDPOINT` and `SEALANT_OTEL_EXPORTER_OTLP_HEADERS` send spans to another collector. Without them nothing is exported and no network call is made. The names carry a `SEALANT_` prefix so that a workspace image's own `SENTRY_DSN` stays the user's, and boot keeps them out of the harness's environment.

Each control request becomes a `sealantd.control.<method>` span, a child of the caller's trace when the request carries `trace`, and exec, session open and attach get child spans for their stages. Spans name the method, request id and error code, never arguments, environment or output. A request that fails with an internal error is reported to Sentry once. Every string in a report is masked with the daemon's secrets and loses URL credentials and query strings. `--log-level` now filters stderr only, so `off` still exports.
