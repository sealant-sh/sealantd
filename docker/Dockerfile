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
# Cargo's registry, its git checkouts and the target directory are BuildKit cache mounts, one of each
# per platform, so two platforms built on one builder never wait on each other's lock: a rebuild on
# the same builder after an edit compiles what changed, not the whole tree (Mend's verify stack
# rebuilds sealantd in a session after each fix; a cold build takes about 1.5 min at 12 CPUs). A
# release builder starts empty, so a release build is unchanged. The binaries are copied out of the
# mount, which the image never contains.
#
# Cargo decides a crate is fresh by file mtimes. The target directory outlives the tree it was built
# from, and `COPY` keeps whatever mtimes the context carries, so a source older than the cached
# artifacts (another checkout, a restored tree) would ship the cached binary. Every source file is
# stamped with the build's time first: the workspace's own crates always rebuild, and only the
# dependencies come from the cache.
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
    cargo build --locked --release --bin sealantd --bin sealantctl --target "$target"; \
    cp "target/$target/release/sealantd" /sealantd; \
    cp "target/$target/release/sealantctl" /sealantctl

# Static socat, shipped beside sealantd. The workspace control socket is bridged to the host over
# a `docker exec` relay that needs socat in the workspace image; vendoring a fully static musl
# build here lets image builders `COPY --from` it into ANY base (custom base images included)
# instead of depending on the base's package manager. Built from source: no distro ships a static
# socat package. OpenSSL/readline/libwrap are disabled — the relay only needs UNIX/STDIO/TCP.
FROM alpine:3.22 AS socat-builder
RUN apk add --no-cache build-base linux-headers wget
# The tarball is fetched over HTTPS and checked against a pinned sha256 before anything unpacks it.
# Upstream's own HTTPS (www.dest-unreach.org) presents a self-signed certificate for another host,
# so it comes from two distribution mirrors instead: Fedora's lookaside cache, which is addressed by
# the tarball's sha512, then Alpine's distfiles. Both serve upstream's release byte for byte; the
# sha512 is the one Alpine's aports recorded when it packaged 1.8.0.3. A new version changes all
# three ARGs together.
ARG SOCAT_VERSION=1.8.0.3
ARG SOCAT_SHA256=a9f9eb6cfb9aa6b1b4b8fe260edbac3f2c743f294db1e362b932eb3feca37ba4
ARG SOCAT_SHA512=600a3387e9756e0937d2db49de9066df03d9818e4042da6b72109d1b5688dd72352754773a19bd2558fe93ec6a8a73e80e7cf2602fd915960f66c403fd89beef
RUN set -eux; \
    tarball="socat-${SOCAT_VERSION}.tar.gz"; \
    for url in \
        "https://src.fedoraproject.org/repo/pkgs/socat/${tarball}/sha512/${SOCAT_SHA512}/${tarball}" \
        "https://distfiles.alpinelinux.org/distfiles/v3.22/${tarball}"; do \
        if wget -q -O "$tarball" "$url" && echo "${SOCAT_SHA256}  ${tarball}" | sha256sum -c -; then \
            break; \
        fi; \
        rm -f "$tarball"; \
    done; \
    echo "${SOCAT_SHA256}  ${tarball}" | sha256sum -c -; \
    echo "${SOCAT_SHA512}  ${tarball}" | sha512sum -c -; \
    tar xzf "$tarball"; \
    cd "socat-${SOCAT_VERSION}"; \
    CFLAGS="-static -Os" LDFLAGS="-static" ./configure --disable-openssl --disable-readline --disable-libwrap; \
    make -j"$(nproc)"; \
    strip socat; \
    cp socat /socat

# Minimal runtime: static binaries on scratch (no shell, no libc, no attack surface).
FROM scratch AS runtime
COPY --from=builder /sealantd /usr/local/bin/sealantd
# The control socket's client, shipped beside the daemon for the same reason as socat: an image
# builder can `COPY --from` it into any base. A Lambda MicroVM's in-VM agent runs
# `sealantctl capture flush` in the platform's suspend and terminate hooks, where no control plane
# is connected to ask the daemon for it.
COPY --from=builder /sealantctl /usr/local/bin/sealantctl
# Exec form, since scratch has no shell: a client that is missing or not static fails the release
# here, not the first MicroVM that is stopped.
RUN ["/usr/local/bin/sealantctl", "--version"]
COPY --from=socat-builder /socat /usr/local/bin/socat
# Default socket lives in the workspace's runtime dir; override via flags.
ENTRYPOINT ["/usr/local/bin/sealantd"]
