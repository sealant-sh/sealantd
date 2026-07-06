# syntax=docker/dockerfile:1
#
# Multi-arch, statically linked sealantd image (plan §20-21). Build the daemon as a fully static
# musl binary, then ship it on `scratch`. Multi-arch via BuildKit/buildx: each target platform
# builds its native musl target (amd64 natively, arm64 under QEMU), so no cross-linker is needed.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f docker/Dockerfile -t sealantd:latest .
#
# The protobuf compiler is vendored by the build (protoc-bin-vendored), so the build needs no system
# protoc and the runtime binary has no protobuf dependency.

FROM rust:slim AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN set -eux; \
    case "$(uname -m)" in \
      x86_64)  target=x86_64-unknown-linux-musl ;; \
      aarch64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    cargo build --release --bin sealantd --target "$target"; \
    cp "target/$target/release/sealantd" /sealantd

# Minimal runtime: a single static binary on scratch (no shell, no libc, no attack surface).
FROM scratch AS runtime
COPY --from=builder /sealantd /usr/local/bin/sealantd
# Default socket lives in the workspace's runtime dir; override via flags.
ENTRYPOINT ["/usr/local/bin/sealantd"]
