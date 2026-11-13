#!/usr/bin/env bash
# Run the workspace tests on Linux in a container, caching target/ and the cargo
# registry in named volumes so incremental builds are fast. The macOS target/ is
# never touched (CARGO_TARGET_DIR points at the volume).
#
# Usage: scripts/linux-test.sh [extra cargo test args...]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${SEALANTD_RUST_IMAGE:-rust:1.100.0-slim}"
exec docker run --rm -t \
  -v "$REPO":/src -w /src \
  -v sealantd-cargo-registry:/usr/local/cargo/registry \
  -v sealantd-linux-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=always \
  "$IMAGE" \
  cargo test --workspace "$@"
