# syntax=docker/dockerfile:1
#
# `ghcr.io/sealant-sh/egress-proxy`: one per isolated workspace, run as `<name>-proxy`
# (workspace isolation architecture §3.1, §7). A static musl `sealant-egress-proxy` on scratch,
# running as UID/GID 65532 with no shell, no libc and no system trust store (the public roots it
# verifies brokered upstreams against are compiled in).
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f docker/egress-proxy.Dockerfile -t egress-proxy:latest .
#
# The orchestrator runs it read-only with every capability dropped, and lets the non-root user
# bind the DNS port:
#
#   docker run --read-only --cap-drop ALL --security-opt no-new-privileges:true \
#     --sysctl net.ipv4.ip_unprivileged_port_start=53 \
#     -v mend-control:/run/sealant:rw,volume-subpath=<name>-proxy egress-proxy

FROM rust:1.100.0-slim AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Same cache layout and mtime stamping as docker/Dockerfile: dependencies come from the cache,
# the workspace's own crates always rebuild.
ARG TARGETPLATFORM
# The release the binary reports to Sentry (`sealantd@<version>`) when its environment names none;
# the next and release workflows pass it. Empty in a local build.
ARG SENTRY_RELEASE
RUN --mount=type=cache,id=sealantd-cargo-registry-${TARGETPLATFORM},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=sealantd-cargo-git-${TARGETPLATFORM},target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=sealantd-target-${TARGETPLATFORM},target=/src/target,sharing=locked \
    set -eux; \
    case "$(uname -m)" in \
      x86_64)  target=x86_64-unknown-linux-musl ;; \
      aarch64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;; \
    esac; \
    find /src -path /src/target -prune -o -type f -exec touch -c {} +; \
    rustup target add "$target"; \
    cargo build --locked --release -p sealant-egress-proxy --bin sealant-egress-proxy --target "$target"; \
    cp "target/$target/release/sealant-egress-proxy" /sealant-egress-proxy

FROM scratch AS runtime
COPY --from=builder /sealant-egress-proxy /usr/local/bin/sealant-egress-proxy
# Exec form, since scratch has no shell: a binary that is not static fails the build here.
RUN ["/usr/local/bin/sealant-egress-proxy", "--version"]
USER 65532:65532
# 8080 explicit proxy, 15080/15443/15444/15100 transparent relay from sealant-vm-runner, 53 DNS.
EXPOSE 8080 15080 15443 15444 15100 53/udp 53/tcp
ENTRYPOINT ["/usr/local/bin/sealant-egress-proxy"]
