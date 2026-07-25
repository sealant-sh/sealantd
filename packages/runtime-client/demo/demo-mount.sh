#!/usr/bin/env bash
# End-to-end mount-workspace demo (definition of done, capability 1):
#   create a workspace over a caller-owned host worktree (bind mount, no clone) -> run a command
#   that edits files -> observe fileChange events in the record -> stop and DELETE the workspace
#   container -> the edits are still on the host path.
# Also proves the allowlist: a create naming a path outside the store roots refuses to boot.
set -euo pipefail
cd "$(dirname "$0")/../../.."

IMAGE="${SEALANT_DEMO_IMAGE:-sealant-workspace-fedora-opencode:opencode}"
DEMO_ROOT="$(mktemp -d /tmp/sealant-mount-demo.XXXXXX)"
STORE="$DEMO_ROOT/mend-store"
WT="$STORE/wt-session-1"
CTR="sealant-mount-demo-$$"
cleanup() { docker rm -f "$CTR" "$CTR-evil" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo ">> building sealantd"
cargo build -q -p sealantd

echo ">> host store worktree: $WT"
mkdir -p "$WT"
git -C "$WT" init -q -b main
echo "hello from the host store" > "$WT/file.txt"
git -C "$WT" add -A && git -C "$WT" -c user.email=demo@sealant -c user.name=demo commit -qm "seed"
BEFORE_HEAD="$(git -C "$WT" rev-parse HEAD)"

echo ">> [allowlist] boot with a host path OUTSIDE the store roots must be rejected"
set +e
docker run --name "$CTR-evil" \
  -v "$WT:/workspace/repo" \
  -v "$PWD/target/debug/sealantd:/usr/local/bin/sealantd:ro" \
  -e SEALANT_WORKSPACE_SOURCE=mount \
  -e SEALANT_WORKSPACE_MOUNT_HOST_PATH=/home/someone/checkout \
  -e "SEALANT_MOUNT_ALLOWED_STORE_ROOTS=$STORE" \
  -e SEALANT_OS_FAMILY=fedora \
  -e SEALANT_LOGIN_SHELL_PATH=/bin/bash \
  -e SEALANT_FOREGROUND_COMMAND="sleep infinity" \
  --entrypoint /usr/local/bin/sealantd "$IMAGE" boot >/dev/null 2>&1
EVIL_EXIT=$?
set -e
[ "$EVIL_EXIT" -ne 0 ] || { echo "!! allowlist violation was NOT rejected"; exit 1; }
docker logs "$CTR-evil" 2>&1 | grep -o "outside the operator-configured store roots.*" | head -1 | sed 's/^/   rejected: /'
docker rm -f "$CTR-evil" >/dev/null

echo ">> booting mount-mode workspace over the store worktree (no clone; mount IS the repo)"
docker run -d --name "$CTR" \
  -v "$WT:/workspace/repo" \
  -v "$PWD/target/debug/sealantd:/usr/local/bin/sealantd:ro" \
  -e SEALANT_WORKSPACE_SOURCE=mount \
  -e "SEALANT_WORKSPACE_MOUNT_HOST_PATH=$WT" \
  -e "SEALANT_MOUNT_ALLOWED_STORE_ROOTS=$STORE" \
  -e SEALANT_OS_FAMILY=fedora \
  -e SEALANT_LOGIN_SHELL_PATH=/bin/bash \
  -e SEALANT_FOREGROUND_COMMAND="sleep infinity" \
  --entrypoint /usr/local/bin/sealantd "$IMAGE" boot >/dev/null
for _ in $(seq 1 100); do
  docker exec "$CTR" test -S /run/sealant/control.sock 2>/dev/null && break
  sleep 0.1
done
docker logs "$CTR" 2>&1 | grep -o "workspace source is a caller-owned mount.*" | head -1 | sed 's/^/   boot: /'

echo ">> driving the workspace over the control socket (exec edits + record capture)"
node packages/runtime-client/demo/demo-mount.ts "$CTR"

echo ">> stopping and DELETING the workspace container"
docker rm -f "$CTR" >/dev/null

echo ">> verifying the caller-owned worktree on the host survived teardown"
[ "$(git -C "$WT" rev-parse HEAD)" = "$BEFORE_HEAD" ] || { echo "!! git history changed"; exit 1; }
grep -q "edited by workspace run" "$WT/file.txt" || { echo "!! edit lost"; exit 1; }
[ -f "$WT/created-in-session.txt" ] || { echo "!! created file lost"; exit 1; }
[ -f "$WT/sub/deep.txt" ] || { echo "!! nested file lost"; exit 1; }
echo "   file.txt:                $(cat "$WT/file.txt" | tr '\n' ' ')"
echo "   created-in-session.txt:  $(cat "$WT/created-in-session.txt")"
echo "   sub/deep.txt:            $(cat "$WT/sub/deep.txt")"
echo "   git -C worktree status:"
git -C "$WT" status --short | sed 's/^/     /'
echo ">> MOUNT DEMO PASSED — edits persisted on the host after workspace deletion; file events were in the record"
echo "   (worktree kept at $WT for inspection)"
