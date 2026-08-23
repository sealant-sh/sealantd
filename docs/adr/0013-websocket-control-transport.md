# ADR-0013: Secure WebSocket control transport

Status: accepted 2026-08-23. Supersedes the "no network transport" consequence of ADR-0004 for one
narrowly scoped case; the Unix socket remains the default and the stdio frontend is unchanged.

Cross-repo context: `sealant/docs/kubernetes-support-design.md` (D3).

## Context

ADR-0004 chose a Unix socket (0600 + `SO_PEERCRED`) over any TCP listener because the controller
and the workspace shared a host. On Kubernetes they do not: the Sealant worker and SSH gateway run
in their own Pods, usually on other nodes, and `docker exec … socat` has no equivalent. The daemon
needs a network frontend that is at least as strong as the socket boundary.

## Decision

Add a third, **opt-in** frontend in `sealant-control`: `serve_wss` / `WssListener`.

- **Off by default.** It starts only when `SEALANT_CONTROL_WSS_LISTEN` (boot) or `--wss-listen`
  (bare CLI) is set. With none of the `SEALANT_CONTROL_WSS_*` variables present, `sealantd boot`
  and `sealantd --socket …` behave exactly as before. The Unix socket is still bound in both modes
  because it is the readiness signal and the in-Pod path for local tooling.
- **Mutual TLS, no anonymous fallback.** rustls (`ring` provider — builds on musl, runs from the
  `scratch` image, no system trust store) with `WebPkiClientVerifier` over the configured client CA
  (`SEALANT_CONTROL_WSS_CLIENT_CA`). A peer with no certificate, a certificate from another CA, or a
  certificate lacking the `clientAuth` extended key usage fails the TLS handshake before any HTTP
  byte is read. The workspace's own server certificate is issued with `serverAuth` only, so a
  process inside the workspace that can read `/run/sealant/tls` cannot authenticate as the control
  plane.
- **Bounded.** One path (`/control`, anything else is `404` + close), a handshake deadline, a
  connection semaphore (`SEALANT_CONTROL_WSS_MAX_CONNECTIONS`, default 64), and a WebSocket message
  size cap of `max_frame_bytes + 4`.
- **Same protocol bytes.** Binary messages carry the unchanged length-prefixed Protobuf stream. The
  WebSocket is adapted into `AsyncRead` + `AsyncWrite` and handed to the existing
  `handle_connection`, so dispatch, the bounded outbound queue (backpressure), and
  connection-scoped channel teardown are one implementation across Unix, stdio and WSS.
- **Graceful shutdown** rides the same `watch::Receiver<bool>`: the listener stops accepting,
  live connections unwind through `handle_connection`, stragglers are aborted after a short grace.
- **No secrets in logs.** Handshake failures log the rustls/tungstenite error kind and the peer
  address; certificates, keys and payloads are never logged.

Configuration (boot env / CLI flag):

| Variable | Flag | Meaning |
| --- | --- | --- |
| `SEALANT_CONTROL_WSS_LISTEN` | `--wss-listen` | `host:port` to bind; enables the frontend |
| `SEALANT_CONTROL_WSS_CERT` | `--wss-cert` | PEM server chain, leaf first |
| `SEALANT_CONTROL_WSS_KEY` | `--wss-key` | PEM private key |
| `SEALANT_CONTROL_WSS_CLIENT_CA` | `--wss-client-ca` | PEM CA bundle for client certificates |
| `SEALANT_CONTROL_WSS_MAX_CONNECTIONS` | `--wss-max-connections` | positive integer, default 64 |

All five are consumed by boot (never forwarded to the harness environment). Partial configuration
is a startup error, as is unreadable TLS material or a failed bind: the daemon exits instead of
running without the listener it was asked for.

## Alternatives considered

- **Bearer token on the upgrade request.** Simpler PKI, but the token is a per-workspace secret the
  control plane must mint, distribute and rotate, and it gives the daemon no way to verify *which*
  component is calling. Kept as a documented fallback for operators who cannot run cert-manager; not
  implemented.
- **Plain `ws://` behind NetworkPolicy.** Rejected: NetworkPolicy is a reachability control, not
  authentication, and is CNI-dependent.
- **A relay sidecar exposing the Unix socket.** Rejected: an extra privileged-adjacent container
  per Pod, a second hop to secure, and no reduction in daemon code.

## Consequences

- `sealant-control` gains `rustls`, `tokio-rustls`, `rustls-pemfile`, `tokio-tungstenite`,
  `tokio-util` (io) and `futures`; `rcgen` is a dev-dependency for the PKI in tests.
- The threat model (`docs/runtime/threat-model.md`) gains a network boundary that is only present
  when configured; the control plane's client key is the credential to protect.
- Node clients adapt the WebSocket with `ws`'s `createWebSocketStream` and feed the Duplex to the
  unchanged `SealantClient.fromStream` (implemented in `sealant`'s worker/gateway, not in
  `@sealant/runtime-client`, to avoid coupling the SDK to a TLS material layout).
