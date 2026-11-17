#!/usr/bin/env bash
# Prints the path of tlx, the TLA+ model checker the models in docs/formal/ run on, built from the
# one commit pinned below. Builds it the first time.
#
#   tlx.sh            the binary's path, after building it into the cache if it is not there
#   tlx.sh --commit   the pinned commit (CI keys its cache of the binary by it)
#
# tlx (github.com/tlaplus-x/tlx) is version 0.1 with no releases, so it is built from source. That
# needs git, cargo and a C compiler as `cc`; with rustup, the build uses the Rust release tlx's own
# rust-toolchain.toml pins. The binary goes to ${XDG_CACHE_HOME:-~/.cache}/sealantd-formal/
# tlx-<commit>/tlx, and the build runs CARGO_BUILD_JOBS jobs when that is set. FORMAL_TLX, when
# set, names a binary to use instead (a tlx you built yourself, at your own risk).
#
# Exit status 0: the path is on stdout. 2: no tlx, and it could not be built (it says why).
set -euo pipefail

TLX_REPO=https://github.com/tlaplus-x/tlx
TLX_COMMIT=8d5f082b0f0d922bf5999d9a8db00c70a4c1d261

case "${1:-}" in
  --commit)
    echo "$TLX_COMMIT"
    exit 0
    ;;
  "") ;;
  *)
    echo "tlx.sh: unknown argument $1" >&2
    exit 2
    ;;
esac

if [[ -n "${FORMAL_TLX:-}" ]]; then
  [[ -x "$FORMAL_TLX" ]] || {
    echo "tlx.sh: FORMAL_TLX is $FORMAL_TLX, which is not an executable" >&2
    exit 2
  }
  echo "$FORMAL_TLX"
  exit 0
fi

dir="${XDG_CACHE_HOME:-$HOME/.cache}/sealantd-formal/tlx-$TLX_COMMIT"
bin="$dir/tlx"
if [[ -x "$bin" ]]; then
  echo "$bin"
  exit 0
fi

missing=()
for tool in git cargo cc; do command -v "$tool" >/dev/null || missing+=("$tool"); done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "tlx.sh: tlx ${TLX_COMMIT:0:10} is not built, and building it needs ${missing[*]} on PATH:" >&2
  echo "  Rust through rustup (https://rustup.rs) and a C compiler as cc. Or set FORMAL_TLX." >&2
  exit 2
fi

echo "tlx.sh: building tlx ${TLX_COMMIT:0:10} into $dir (the first time only: a few minutes)" >&2
src=$(mktemp -d -t tlx-src.XXXXXX)
trap 'rm -rf -- "$src"' EXIT
# Fetched by its full hash, so the source is that commit and nothing else.
git -C "$src" init -q
git -C "$src" fetch -q --depth 1 "$TLX_REPO" "$TLX_COMMIT"
git -C "$src" checkout -q FETCH_HEAD
if ! (
  cd "$src"
  if command -v rustup >/dev/null; then rustup toolchain install >&2; fi
  cargo build --release --locked -p tlx-cli >&2
); then
  echo "tlx.sh: the build of tlx ${TLX_COMMIT:0:10} failed (above)" >&2
  exit 2
fi
mkdir -p "$dir"
cp "$src/target/release/tlx" "$bin.part"
mv "$bin.part" "$bin"
echo "$bin"
