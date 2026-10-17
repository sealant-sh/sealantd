#!/usr/bin/env bash
# The `test-support` features are for tests only: sealant-capture's (the manual clock, and the
# `CaptureConfig::clock` field that injects it: a daemon whose captures wait on a clock nobody
# moves stops capturing without an error, #182) and sealantd's (the dotfiles copy's hold seam,
# `SEALANTD_DOTFILES_TEST_HOLD`: a daemon that waits where a test tells it to, #186). This holds
# that:
#   1. no workspace package turns either on through a normal or build dependency, on any target
#      (the tests turn them on through dev-dependencies, which no build of the daemon has);
#   2. a crate that depends on sealant-capture or sealantd without it can neither name
#      `ManualClock`, set `CaptureConfig::clock` nor name `sealantd::test_support`, and with it
#      (the probe's `control` feature) can do all three.
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

normal=$(read_graph normal,build,features) || exit 1
with_dev=$(read_graph normal,build,dev,features) || exit 1
for crate in sealant-capture sealantd; do
	feature="$crate feature \"test-support\""
	# A graph read that succeeds holds the crate it is about: an empty one says nothing.
	holds "$crate v" "$normal" || fail "the normal and build graph does not list $crate"
	if holds "$feature" "$normal"; then
		echo "$crate's test-support is enabled outside the tests:" >&2
		cargo tree --workspace --target all --locked -e normal,build,features -i "$crate" >&2 || true
		exit 1
	fi
	# The control: the tests do turn it on, so the check above looked for the right name.
	holds "$feature" "$with_dev" ||
		fail "no test turns on $crate's test-support: the check above checks nothing"
done

probe=scripts/test-support-probe
cp Cargo.lock "$probe/Cargo.lock"
export CARGO_TARGET_DIR="$PWD/target"
check() { cargo check --quiet --manifest-path "$probe/Cargo.toml" --bin "$@" 2>&1; }
for bin in names-the-manual-clock injects-a-clock names-the-dotfiles-hold; do
	case $bin in
	names-the-manual-clock) want='unresolved import `sealant_capture::ManualClock`' ;;
	injects-a-clock) want='no field `clock` on type' ;;
	names-the-dotfiles-hold) want='unresolved import `sealantd::test_support`' ;;
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
echo "test-support: on in the tests only; the manual clock, clock injection and the dotfiles hold are unreachable without it"
