#!/usr/bin/env bash
# sealant-capture's `test-support` feature (the manual clock, and the `CaptureConfig::clock` field
# that injects it) is for tests only: a daemon whose captures wait on a clock nobody moves stops
# capturing without an error (#182). This holds that:
#   1. no workspace package turns it on through a normal or build dependency, on any target (the
#      tests turn it on through dev-dependencies, which no build of the daemon has);
#   2. a crate that depends on sealant-capture without it can neither name `ManualClock` nor set
#      `CaptureConfig::clock`, and with it (the probe's `control` feature) can do both.
# It fails closed: a graph it cannot read, or a search that errs, fails the gate rather than
# reading as "absent" (scripts/ci-test-support-gate.test.mjs).
set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
	echo "ci-test-support-gate: $*" >&2
	exit 1
}

# Each graph is read whole, as a command of its own, before anything searches it.
read_graph() {
	local edges=$1 graph
	if ! graph=$(cargo tree --workspace --target all --locked --prefix none -e "$edges"); then
		fail "cargo tree -e $edges failed: the gate cannot say what that graph holds"
	fi
	printf '%s\n' "$graph"
}

# Whether `$2` holds the line `$1`: 0 yes, 1 no; a search that errs fails the gate.
holds() {
	local status=0
	grep -qF -- "$1" <<<"$2" || status=$?
	case $status in
	0 | 1) return "$status" ;;
	*) fail "searching a graph for '$1' failed (grep exited $status)" ;;
	esac
}

feature='sealant-capture feature "test-support"'
normal=$(read_graph normal,build,features) || exit 1
# A graph read that succeeds holds the crate it is about: an empty one says nothing.
holds 'sealant-capture v' "$normal" || fail "the normal and build graph does not list sealant-capture"
if holds "$feature" "$normal"; then
	echo "sealant-capture's test-support is enabled outside the tests:" >&2
	cargo tree --workspace --target all --locked -e normal,build,features -i sealant-capture >&2 || true
	exit 1
fi
# The control: the tests do turn it on, so the check above looked for the right name.
with_dev=$(read_graph normal,build,dev,features) || exit 1
holds "$feature" "$with_dev" ||
	fail "no test turns on sealant-capture's test-support: the check above checks nothing"

probe=scripts/test-support-probe
cp Cargo.lock "$probe/Cargo.lock"
export CARGO_TARGET_DIR="$PWD/target"
check() { cargo check --quiet --manifest-path "$probe/Cargo.toml" --bin "$@" 2>&1; }
for bin in names-the-manual-clock injects-a-clock; do
	case $bin in
	names-the-manual-clock) want='unresolved import `sealant_capture::ManualClock`' ;;
	injects-a-clock) want='no field `clock` on type' ;;
	esac
	if out=$(check "$bin"); then
		fail "$bin compiled without test-support"
	fi
	if ! holds "$want" "$out"; then
		echo "$out" >&2
		fail "$bin failed without test-support, but not for the gate ($want)"
	fi
	if ! out=$(check "$bin" --features control); then
		echo "$out" >&2
		fail "$bin did not compile with test-support (the control)"
	fi
done
echo "sealant-capture's test-support: on in the tests only; the manual clock and clock injection are unreachable without it"
