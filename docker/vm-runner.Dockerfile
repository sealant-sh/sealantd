# syntax=docker/dockerfile:1
#
# ghcr.io/sealant-sh/vm-runner: the image of every host-vm workspace container
# (workspace-isolation-architecture.md §3.1, §4). It holds the static `sealant-vm-runner`, a
# sha256-pinned Cloud Hypervisor v54 release binary, `nft`, and the guest kernel.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f docker/vm-runner.Dockerfile \
#     -t vm-runner:dev .
#
# The kernel is built here from kernel/build-kernel.sh by default (a few minutes per platform). To
# package a kernel built beforehand with that script instead, put it at kernel/out/<arch>/
# (`vmlinux` for x86_64, `Image` for aarch64) and pass `--build-arg KERNEL_SOURCE=prebuilt`.
#
# The container runs as root only until the runner has created tap0 and its nftables table; then
# the runner drops to 65532 with no capabilities before starting the VMM. HostVmRuntimeAdapter
# starts it with `--cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID
# --cap-add SETPCAP --security-opt no-new-privileges:true --read-only`, `/dev/kvm` and
# `/dev/net/tun`.

ARG KERNEL_SOURCE=build

FROM rust:1.100.0-slim AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Cache mounts and mtime stamping as in docker/Dockerfile (see there for why).
ARG TARGETPLATFORM
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
    cargo build --locked --release --bin sealant-vm-runner --target "$target"; \
    cp "target/$target/release/sealant-vm-runner" /sealant-vm-runner

# Cloud Hypervisor's own static release binaries. The sha256s are the release assets' digests as
# GitHub reports them for v54.0 (checked against a download). A new version changes all three.
FROM alpine:3.22 AS cloud-hypervisor
ARG CLOUD_HYPERVISOR_VERSION=v54.0
ARG CLOUD_HYPERVISOR_SHA256_AMD64=4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b
ARG CLOUD_HYPERVISOR_SHA256_ARM64=e8a6d9786ea678e739f1a386682846e93742dcb9c7b6e3e0c62e3bda6cff0ef3
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) asset=cloud-hypervisor-static; sum=$CLOUD_HYPERVISOR_SHA256_AMD64 ;; \
      arm64) asset=cloud-hypervisor-static-aarch64; sum=$CLOUD_HYPERVISOR_SHA256_ARM64 ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    wget -q -O /cloud-hypervisor \
      "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CLOUD_HYPERVISOR_VERSION}/${asset}"; \
    echo "${sum}  /cloud-hypervisor" | sha256sum -c -; \
    chmod 0755 /cloud-hypervisor

# The guest kernel, built from the pinned tarball and the fragment for this platform.
FROM debian:bookworm-slim AS kernel-build
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils make gcc libc6-dev \
      flex bison bc perl libelf-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY kernel/build-kernel.sh kernel/linux-6.12-microvm.x86_64.config \
     kernel/linux-6.12-microvm.aarch64.config /kernel/
ARG TARGETARCH
RUN --mount=type=cache,id=sealant-kernel-tarball,target=/cache \
    set -eux; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64; image=vmlinux ;; \
      arm64) arch=aarch64; image=Image ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    KERNEL_CACHE=/cache /kernel/build-kernel.sh "$arch" /build; \
    mkdir /out; cp "/build/$image" /out/kernel; cp /build/config /build/SHA256SUMS /out/

# A kernel built beforehand with kernel/build-kernel.sh.
FROM alpine:3.22 AS kernel-prebuilt
ARG TARGETARCH
COPY kernel/out/ /prebuilt/
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) src=/prebuilt/x86_64; image=vmlinux ;; \
      arm64) src=/prebuilt/aarch64; image=Image ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    (cd "$src" && sha256sum -c SHA256SUMS); \
    mkdir /out; cp "$src/$image" /out/kernel; cp "$src/config" "$src/SHA256SUMS" /out/

FROM kernel-${KERNEL_SOURCE} AS kernel

FROM alpine:3.22 AS runtime
RUN apk add --no-cache nftables
COPY --from=builder /sealant-vm-runner /usr/local/bin/sealant-vm-runner
COPY --from=cloud-hypervisor /cloud-hypervisor /usr/local/bin/cloud-hypervisor
COPY --from=kernel /out/kernel /usr/share/sealant/vm/kernel
COPY --from=kernel /out/config /out/SHA256SUMS /usr/share/sealant/vm/
# Fail the build, not the first workspace, when a binary is missing or not runnable here.
RUN set -eux; \
    /usr/local/bin/sealant-vm-runner --version; \
    /usr/local/bin/cloud-hypervisor --version | grep -q '^cloud-hypervisor v54\.'; \
    /usr/sbin/nft --version; \
    test -s /usr/share/sealant/vm/kernel
ENTRYPOINT ["/usr/local/bin/sealant-vm-runner"]
