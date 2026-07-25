#!/usr/bin/env bash
# End-to-end interactive-PTY demo (definition of done, capability 2), run inside a MOUNT-mode
# workspace so the PTY's file writes also prove capability 3 on capability 1. The wrapper boots the
# container; demo-pty.ts drives sessions over the control socket; afterwards the container is
# DELETED and the PTY's write is shown to persist on the host.
set -euo pipefail
cd "$(dirname "$0")/../../.."

IMAGE="${SEALANT_DEMO_IMAGE:-sealant-workspace-fedora-opencode:opencode}"
DEMO_ROOT="$(mktemp -d /tmp/sealant-pty-demo.XXXXXX)"
STORE="$DEMO_ROOT/mend-store"
WT="$STORE/wt-session-1"
CTR="sealant-pty-demo-$$"
cleanup() { docker rm -f "$CTR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo ">> building sealantd"
cargo build -q -p sealantd

mkdir -p "$WT"
git -C "$WT" init -q -b main
echo "seed" > "$WT/file.txt"
git -C "$WT" add -A && git -C "$WT" -c user.email=demo@sealant -c user.name=demo commit -qm "seed"

echo ">> booting mount-mode workspace for PTY sessions ($WT)"
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

echo ">> driving interactive sessions over the control socket"
node packages/runtime-client/demo/demo-pty.ts "$CTR"

echo ">> deleting the workspace container; verifying the PTY's write persisted on the host"
docker rm -f "$CTR" >/dev/null
grep -q "written-from-pty" "$WT/pty-edit.txt" || { echo "!! PTY write lost"; exit 1; }
echo "   pty-edit.txt: $(cat "$WT/pty-edit.txt")"
echo ">> PTY DEMO PASSED (worktree kept at $WT for inspection)"
