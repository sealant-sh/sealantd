#!/usr/bin/env bash
# Boots real microVMs through a vm-runner image, started with the flags HostVmRuntimeAdapter uses
# (workspace-isolation-architecture.md §4.2), and checks what a person running Mend would rely on:
#
#   1. a normal boot: the guest gets its boot config over vsock:1026, reports a synced 76, powers
#      off, and the runner exits 76;
#   2. `docker stop`: the runner presses the guest's power button, the guest reports and powers
#      off within the grace, and the runner exits 76; meanwhile the live Cloud Hypervisor's
#      /proc/<pid>/status shows UID/GID 65532, only the KVM group, NoNewPrivs 1 and all five
#      capability masks zero (Milestone 1 Gate 1's posture check);
#   3. a recovery boot: same handshake, and nothing listens for the session channel (vsock:1027).
#
# The guest is not sealantd but scripts/vm-runner-smoke/init.c, which plays only the guest side of
# vsock:1026. Needs Linux with /dev/kvm and Docker.
#
#   docker build -f docker/vm-runner.Dockerfile -t vm-runner:dev .
#   scripts/vm-runner-smoke.sh vm-runner:dev
set -euo pipefail

image=${1:?usage: $0 <vm-runner image>}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
name="vm-runner-smoke-$$"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run --rm -v "$work":/work alpine:3.22 rm -rf /work/images /work/data /work/run >/dev/null 2>&1 || true
  rm -rf "$work"
}
[ -n "${SMOKE_KEEP:-}" ] || trap cleanup EXIT
echo "work dir: $work"

echo "== building the stand-in init and the disks"
mkdir -p "$work/images" "$work/data" "$work/run"
docker run --rm -v "$here/vm-runner-smoke":/src:ro -v "$work":/work debian:bookworm-slim bash -ec '
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends gcc libc6-dev e2fsprogs >/dev/null 2>&1
  gcc -static -O2 -o /tmp/init /src/init.c
  for variant in exit wait; do
    root=/tmp/root-$variant
    mkdir -p $root/dev $root/proc $root/etc $root/usr/local/bin
    cp /tmp/init $root/usr/local/bin/sealantd
    [ $variant = wait ] && touch $root/etc/smoke-wait-power
    mke2fs -q -t ext4 -d $root /work/images/sha256-smoke-$variant.img 32M
    echo "{\"Env\":[\"PATH=/usr/bin\"],\"WorkingDir\":\"/workspace\"}" \
      > /work/images/sha256-smoke-$variant.config.json
  done
  truncate -s 256M /work/data/data.img
  mkfs.ext4 -q -F /work/data/data.img
  echo "{\"bootEnv\":{\"SMOKE\":\"1\"},\"secretEnv\":{\"SMOKE_TOKEN\":\"not-a-secret\"}}" > /work/run/boot-env.json
  echo "{\"mode\":\"recover\",\"secretEnv\":{\"SMOKE_TOKEN\":\"capture-only\"}}" > /work/run/recovery-env.json
  chmod 0644 /work/images/* /work/run/*.json
  chown -R 65532:65532 /work/data /work/run
'

start() {
  docker run -d --name "$name" \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
    --security-opt no-new-privileges:true \
    --device /dev/kvm:/dev/kvm --device /dev/net/tun:/dev/net/tun \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,uid=65532,gid=65532 \
    --tmpfs /run/vm:rw,nosuid,nodev,noexec,uid=65532,gid=65532 \
    -v "$work/images":/var/lib/sealant/images:ro \
    -v "$work/data":/var/lib/sealant/data \
    -v "$work/run":/run/sealant \
    "$image" --proxy-ip 192.0.2.1 --vcpus 1 --memory-mib 256 --shutdown-grace-secs 20 "$@" >/dev/null
}

wait_log() {
  local pattern=$1 deadline=$((SECONDS + 60))
  until docker logs "$name" 2>&1 | grep -q "$pattern"; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
      docker logs "$name" 2>&1 | tail -40
      echo "FAIL: the runner exited before logging: $pattern" >&2
      exit 1
    fi
    [ $SECONDS -lt $deadline ] || { docker logs "$name" 2>&1 | tail -40; echo "FAIL: no $pattern" >&2; exit 1; }
    sleep 0.2
  done
}

expect_exit() {
  local want=$1 code
  code=$(docker wait "$name")
  if [ "$code" != "$want" ]; then
    docker logs "$name" 2>&1 | tail -60
    echo "FAIL: runner exited $code, expected $want" >&2
    exit 1
  fi
  # The guest's serial console and the runner's log share stderr, so their lines can interleave.
  logs=$(docker logs "$name" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
  echo "$logs" | grep -E "smoke-init|VM ended|privileges dropped"
  docker rm "$name" >/dev/null
}

echo "== 1. normal boot, guest reports a synced 76"
start --image-digest sha256-smoke-exit
expect_exit 76
echo "$logs" | grep -q "1027: accepted" \
  || { echo "FAIL: the host refused vsock:1027 in a normal boot" >&2; exit 1; }

echo "== 2. docker stop presses the power button; the live VMM holds the jail"
start --image-digest sha256-smoke-wait
wait_log "waiting for the power button"
pid=$(docker exec "$name" pgrep -f /usr/local/bin/cloud-hypervisor | head -1)
status=$(docker exec "$name" cat "/proc/$pid/status")
echo "$status" | grep -E '^(Uid|Gid|Groups|NoNewPrivs|Seccomp|Cap(Inh|Prm|Eff|Bnd|Amb)):'
for want in 'Uid:	65532	65532	65532	65532' 'Gid:	65532	65532	65532	65532' 'NoNewPrivs:	1' \
  'CapInh:	0000000000000000' 'CapPrm:	0000000000000000' 'CapEff:	0000000000000000' \
  'CapBnd:	0000000000000000' 'CapAmb:	0000000000000000'; do
  echo "$status" | grep -qxF "$want" || { echo "FAIL: live VMM status lacks: $want" >&2; exit 1; }
done
kvm_gid=$(docker exec "$name" stat -c %g /dev/kvm)
[ "$(echo "$status" | awk '/^Groups:/ {print $2}')" = "$kvm_gid" ] \
  || { echo "FAIL: VMM groups are not exactly the KVM group $kvm_gid" >&2; exit 1; }
docker stop -t 40 "$name" >/dev/null
expect_exit 76

echo "== 3. recovery boot: no session channel"
start --image-digest sha256-smoke-exit --mode recover
expect_exit 76
echo "$logs" | grep -q "1027: refused" \
  || { echo "FAIL: the host accepted vsock:1027 in recovery" >&2; exit 1; }

echo "PASS"
