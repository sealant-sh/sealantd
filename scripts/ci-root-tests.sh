#!/usr/bin/env bash
# The tests that need root (Mend's per-person layout: ownership on restore, processes as another
# uid). Each passes without running as anyone else; here the built test binaries run under sudo
# with SEALANTD_REQUIRE_ROOT_TESTS=1, so a skip is a failure.
set -euo pipefail

command -v setfacl >/dev/null || sudo apt-get install -y --no-install-recommends acl

run_as_root() {
  local package=$1 target=$2
  shift 2
  local bin
  bin=$(cargo test -p "$package" --test "$target" --no-run --message-format=json \
    | jq -r --arg t "$target" 'select(.executable != null and .target.name == $t) | .executable')
  echo "root: $package --test $target"
  sudo env SEALANTD_REQUIRE_ROOT_TESTS=1 PATH="$PATH" "$bin" "$@"
}

run_as_root sealant-capture owner_map
# One thread: a test sets the daemon's own environment (what a person's commands must not see).
run_as_root sealantd run_as_user --test-threads 1
