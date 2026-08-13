---
"@sealant/runtime-protocol": minor
"@sealant/runtime-client": minor
---

UDP forwards: `openForward` accepts `protocol: "udp"` and opens a connected
UDP socket instead of a TCP stream. The channel is already message-framed, so
one frame is exactly one datagram in both directions — boundaries hold end to
end. Omitted or `"tcp"` keeps the existing byte-stream behavior; the wire
field is absent for TCP, so old daemons and clients interoperate unchanged.
