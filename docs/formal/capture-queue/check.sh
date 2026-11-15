#!/usr/bin/env bash
# Model-checks CaptureQueue.tla with TLC (README.md beside this file says what it checks).
#
#   check.sh            every row of ROWS at the full bounds; exits 0 only when each row ends with
#                       the verdict and the distinct-state count ROWS pins
#   check.sh --quick    the same at the pull-request bounds: seconds
#   check.sh <row>      one row (with --quick or not), printing TLC's whole output and its trace
#
# TLC is tla2tools 1.7.4 (TLC 2.19), checked against its sha256 before it runs: $TLA2TOOLS_JAR when
# set, else the copy cached under ~/.cache/sealantd-formal, fetched from the GitHub release once
# (needs java and curl). TLC runs on $FORMAL_WORKERS workers (default 4) for a row that must hold;
# a row that must fail runs on one, so it stops at the same shortest trace every time.
#
# Exit status 0: every row as expected. 1: a row was not. 2: no checker, or a wrong argument.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TLA2TOOLS_VERSION=1.7.4
TLA2TOOLS_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88

# Bounds: snaps, crashes, refusals.
FULL="6 3 2"
QUICK="4 2 1"

# row | mutants | invariants | expected | distinct states (full) | distinct states (--quick)
#
# `code` is the code as it is: every invariant holds. Each `mutant-` row breaks one mechanism the
# code relies on (two for `mutant-no-cas`), so the row shows its invariant can fail and that the
# checker sees it. `resume-keeps-registered` is the code before SLNT-1009: a capture the registrar
# already holds stays queued after a restart. `mutant-no-cas` needs it: with the fix a registered
# capture is acked at the restart and never sent again, so a register that the registrar answers as
# a lost ack is never sent.
#
# The last two fields pin the distinct states TLC finds. A row is as expected only when its
# verdict and its count both match, so a checker that says "holds" over a different state space
# fails the run. When a change to the model moves a count, take the new one from a TLC run.
ROWS=(
  "code||NoLoss NoDoubleShip QueueContinuesChain AckedAreRegistered ClaimedNeverSuperseded NoConflict|holds|8603032|61783"
  "mutant-resume-keeps-registered-chain|resume-keeps-registered|QueueContinuesChain|violated QueueContinuesChain|858|620"
  "mutant-resume-keeps-registered-conflict|resume-keeps-registered|NoConflict|violated NoConflict|5568|2691"
  "mutant-resume-keeps-registered-loss|resume-keeps-registered|NoLoss|violated NoLoss|9201|3869"
  "mutant-no-journal-loss|no-journal|NoLoss|violated NoLoss|32|32"
  "mutant-no-journal-chain|no-journal|QueueContinuesChain|violated QueueContinuesChain|31|31"
  "mutant-no-cas|no-cas resume-keeps-registered|NoDoubleShip|violated NoDoubleShip|2623|1330"
  "mutant-ack-before-register|ack-before-register|AckedAreRegistered|violated AckedAreRegistered|68|67"
  "mutant-coalesce-in-flight|coalesce-in-flight|ClaimedNeverSuperseded|violated ClaimedNeverSuperseded|23|23"
)

# The help is the comment block at the top of this file.
usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }

quick=0
only=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) quick=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "check.sh: unknown option $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      [[ -z "$only" ]] || {
        echo "check.sh: one row at a time ($only, $1)" >&2
        exit 2
      }
      only=$1
      ;;
  esac
  shift
done
bounds=$FULL
[[ $quick -eq 1 ]] && bounds=$QUICK
read -r snaps crashes refusals <<<"$bounds"
workers=${FORMAL_WORKERS:-4}

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

command -v java >/dev/null || {
  echo "check.sh: java is not on PATH; nothing was checked" >&2
  exit 2
}
if [[ -n "${TLA2TOOLS_JAR:-}" ]]; then
  jar=$TLA2TOOLS_JAR
else
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/sealantd-formal"
  jar="$cache/tla2tools-$TLA2TOOLS_VERSION.jar"
  if [[ ! -f "$jar" ]]; then
    command -v curl >/dev/null || {
      echo "check.sh: no TLA2TOOLS_JAR, no cached tla2tools and no curl to fetch it; nothing was checked" >&2
      exit 2
    }
    mkdir -p "$cache"
    curl -fsSL -o "$jar.part" \
      "https://github.com/tlaplus/tlaplus/releases/download/v$TLA2TOOLS_VERSION/tla2tools.jar"
    mv "$jar.part" "$jar"
  fi
fi
if [[ "$(sha256_of "$jar")" != "$TLA2TOOLS_SHA256" ]]; then
  echo "check.sh: $jar is not tla2tools $TLA2TOOLS_VERSION (sha256 differs); nothing was checked" >&2
  exit 2
fi

scratch=$(mktemp -d -t capture-queue.XXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
# TLC writes its standard modules into java.io.tmpdir: keep them in this run's scratch directory.
export JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$scratch"

run_row() {
  local name=$1 mutants=$2 invariants=$3 expected=$4 pinned=$5
  local set="" m
  for m in $mutants; do set+="${set:+, }\"$m\""; done
  local cfg="$scratch/$name.cfg" log="$scratch/$name.out"
  {
    echo "CONSTANTS"
    echo "  MaxSnaps = $snaps"
    echo "  MaxCrashes = $crashes"
    echo "  MaxRefusals = $refusals"
    echo "  Mutants = {$set}"
    echo "SPECIFICATION Spec"
    echo "INVARIANT TypeOK"
    for inv in $invariants; do echo "INVARIANT $inv"; done
    echo "CHECK_DEADLOCK FALSE"
  } >"$cfg"
  local w=$workers
  [[ "$expected" == holds ]] || w=1
  local started=$SECONDS
  (cd "$here" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "$w" -config "$cfg" \
    -metadir "$scratch/meta-$name" CaptureQueue.tla) 2>&1 |
    grep -v '^Picked up JAVA_TOOL_OPTIONS' >"$log" || true
  local seconds=$((SECONDS - started))
  local observed violated
  if grep -q '^Model checking completed. No error has been found.' "$log"; then
    observed="holds"
  elif violated=$(grep -o '^Error: Invariant [A-Za-z]* is violated' "$log" | head -1) && [[ -n "$violated" ]]; then
    observed="violated $(echo "$violated" | cut -d' ' -f3)"
  else
    observed="error"
  fi
  local states
  states=$(grep -o '[0-9,]* distinct states found' "$log" | tail -1 | cut -d' ' -f1 | tr -d ,)
  local verdict="as expected"
  if [[ "$observed" != "$expected" ]]; then
    verdict="NOT AS EXPECTED"
  elif [[ "${states:-?}" != "$pinned" ]]; then
    verdict="NOT AS EXPECTED: ROWS pins $pinned states"
  fi
  printf '%-32s %-38s %-38s %10s %5ss  %s\n' "$name" "expected: $expected" "observed: $observed" \
    "${states:-?}" "$seconds" "$verdict"
  if [[ -n "$only" || "$verdict" != "as expected" ]]; then
    echo "----- TLC output for $name -----"
    cat "$log"
    echo "----- end of $name -----"
  fi
  [[ "$verdict" == "as expected" ]]
}

echo "TLC (tla2tools $TLA2TOOLS_VERSION) · MaxSnaps = $snaps · MaxCrashes = $crashes · MaxRefusals = $refusals"
failed=0
matched=0
for row in "${ROWS[@]}"; do
  IFS='|' read -r name mutants invariants expected full_states quick_states <<<"$row"
  [[ -n "$only" && "$name" != "$only" ]] && continue
  matched=1
  pinned=$full_states
  [[ $quick -eq 1 ]] && pinned=$quick_states
  run_row "$name" "$mutants" "$invariants" "$expected" "$pinned" || failed=1
done
if [[ $matched -eq 0 ]]; then
  echo "check.sh: no row named $only; rows are:" >&2
  for row in "${ROWS[@]}"; do echo "  ${row%%|*}" >&2; done
  exit 2
fi
exit $failed
