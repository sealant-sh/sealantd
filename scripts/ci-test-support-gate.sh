#!/usr/bin/env bash
# sealant-capture's `test-support` feature (the manual clock, and the `CaptureConfig::clock` field
# that injects it) is for tests only: a daemon whose captures wait on a clock nobody moves stops
# capturing without an error (#182). This holds that:
#   1. no workspace package turns it on through a normal or build dependency, on any target (the
#      tests turn it on through dev-dependencies, which no build of the daemon has);
#   2. a crate that depends on sealant-capture without it can neither name `ManualClock` nor set
#      `CaptureConfig::clock`, and with it (the probe's `control` feature) can do both.
set -euo pipefail
cd "$(dirname "$0")/.."

feature='sealant-capture feature "test-support"'
graph() { cargo tree --workspace --target all --locked --prefix none -e "$1"; }
if graph normal,build,features | grep -qF "$feature"; then
	echo "sealant-capture's test-support is enabled outside the tests:" >&2
	cargo tree --workspace --target all --locked -e normal,build,features -i sealant-capture >&2
	exit 1
fi
# The control: the tests do turn it on, so the check above looked for the right name.
if ! graph normal,build,dev,features | grep -qF "$feature"; then
	echo "no test turns on sealant-capture's test-support: the check above checks nothing" >&2
	exit 1
fi

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
		echo "$bin compiled without test-support" >&2
		exit 1
	fi
	if ! grep -qF "$want" <<<"$out"; then
		echo "$bin failed without test-support, but not for the gate ($want):" >&2
		echo "$out" >&2
		exit 1
	fi
	if ! out=$(check "$bin" --features control); then
		echo "$bin did not compile with test-support (the control):" >&2
		echo "$out" >&2
		exit 1
	fi
done
echo "sealant-capture's test-support: on in the tests only; the manual clock and clock injection are unreachable without it"
