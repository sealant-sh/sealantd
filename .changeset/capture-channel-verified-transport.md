---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

The capture session channel fails closed on transport (daemon-only; the packages ride the release
train). `sealantd` now dials `SEALANT_CAPTURE_ENDPOINT` and every presigned object URL over HTTPS
with a verified certificate, and never falls back. An endpoint it does not dial refuses boot, before
the session token leaves the process; an object URL it does not dial is refused when the registrar
answers it, before a byte is sent.

- Plain HTTP is dialled to loopback, and otherwise only when the launcher sets
  `SEALANT_CAPTURE_ALLOW_PLAINTEXT=true`: a statement that the network between the executor and the
  channel is private. **A launcher that reaches the channel over plain HTTP on a Docker, cluster or
  VPC network must set it, or boot refuses with a message naming the variable.**
- `SEALANT_CAPTURE_CA_PEM` (inline) or `SEALANT_CAPTURE_CA_FILE` (a path) names the roots the
  channel's certificate must chain to, in place of the public roots;
  `SEALANT_CAPTURE_OBJECT_CA_PEM` / `SEALANT_CAPTURE_OBJECT_CA_FILE` do the same for object URLs.
- Certificate and host name verification cannot be turned off, and the plaintext exception does not
  relax it.
- No redirect is followed on the channel or on an object URL; a 3xx is reported as the answer.
- `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` in the daemon's environment are no longer honoured on
  these two paths.
- A refusal names the host only, never a path or query, since a presigned URL is a credential.
