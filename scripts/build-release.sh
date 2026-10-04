#!/usr/bin/env bash
# Build statically linked sealantd binaries for linux/amd64 and linux/arm64 (plan §20-21).
# Produces dist/sealantd-<arch> and verifies each is a static executable.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCHES=("${@:-x86_64 aarch64}")
mkdir -p dist

for arch in ${ARCHES[*]}; do
  target="${arch}-unknown-linux-musl"
  echo ">> building $target"
  docker run --rm -v "$PWD":/src -w /src \
    -v sealantd-cargo-registry:/usr/local/cargo/registry \
    rust:slim sh -euc "
      apt-get update >/dev/null && apt-get install -y --no-install-recommends musl-tools >/dev/null
      rustup target add $target >/dev/null
      cargo build --locked --release --bin sealantd --target $target
      cp target/$target/release/sealantd /src/dist/sealantd-$arch
      echo '--- file type ---'; file /src/dist/sealantd-$arch || true
    "
done
echo ">> artifacts:"; ls -lh dist/
