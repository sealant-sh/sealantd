---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

Daemon: opt-in mutual-TLS WebSocket control frontend (ADR-0013). `SEALANT_CONTROL_WSS_LISTEN`
(boot) / `--wss-listen` (bare CLI) serve the unchanged length-prefixed Protobuf control protocol
over `wss://…/control` beside the Unix socket — rustls with `WebPkiClientVerifier` and no anonymous
fallback, so no certificate, a foreign CA, or a serverAuth-only certificate fails the handshake
before any HTTP byte is read. With the new variables absent the daemon behaves exactly as before.
