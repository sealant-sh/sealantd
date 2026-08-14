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

# Static socat, shipped beside sealantd. The workspace control socket is bridged to the host over
# a `docker exec` relay that needs socat in the workspace image; vendoring a fully static musl
# build here lets image builders `COPY --from` it into ANY base (custom base images included)
# instead of depending on the base's package manager. Built from source: no distro ships a static
# socat package. OpenSSL/readline/libwrap are disabled — the relay only needs UNIX/STDIO/TCP.
FROM alpine:3.22 AS socat-builder
RUN apk add --no-cache build-base linux-headers wget
ARG SOCAT_VERSION=1.8.0.3
RUN set -eux; \
    wget -q "http://www.dest-unreach.org/socat/download/socat-${SOCAT_VERSION}.tar.gz"; \
    tar xzf "socat-${SOCAT_VERSION}.tar.gz"; \
    cd "socat-${SOCAT_VERSION}"; \
    CFLAGS="-static -Os" LDFLAGS="-static" ./configure --disable-openssl --disable-readline --disable-libwrap; \
    make -j"$(nproc)"; \
    strip socat; \
    cp socat /socat

# Minimal runtime: static binaries on scratch (no shell, no libc, no attack surface).
FROM scratch AS runtime
COPY --from=builder /sealantd /usr/local/bin/sealantd
COPY --from=socat-builder /socat /usr/local/bin/socat
# Default socket lives in the workspace's runtime dir; override via flags.
ENTRYPOINT ["/usr/local/bin/sealantd"]
