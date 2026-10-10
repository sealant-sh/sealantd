#!/usr/bin/env bash
# docker/Dockerfile keeps cargo's target directory in a BuildKit cache mount across builds. This
# checks that a cached target never stands in for the source being built: it builds the image from
# this tree with a probe string A, then from a copy whose probe is B but whose file is OLDER than
# the first build (as another checkout or a restored tree can be), on the same builder, and requires
# the second image's sealantctl to carry B and not A.
#
#   scripts/check-docker-cache-freshness.sh            # on the current Docker builder
#
# It needs Docker with BuildKit (buildx) and takes two image builds; it leaves two images tagged
# sealantd-freshness:{a,b} and a cache mount behind, which `docker buildx prune` removes.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
main=crates/sealantctl/src/main.rs

copy() {
  mkdir "$work/$1"
  git -C "$root" ls-files -z | (cd "$root" && xargs -0 tar -cf -) | tar -xf - -C "$work/$1"
  # Kept in the binary by #[used]; nothing reads it.
  printf '\n#[used]\nstatic FRESHNESS_PROBE: [u8; 16] = *b"freshness-probe%s";\n' "$2" >> "$work/$1/$main"
}

copy a A
copy b B
# B's change is older than anything A's build wrote.
touch -d '2001-01-01 00:00:00' "$work/b/$main"

docker build --quiet -f "$work/a/docker/Dockerfile" -t sealantd-freshness:a "$work/a" >/dev/null
docker build --quiet -f "$work/b/docker/Dockerfile" -t sealantd-freshness:b "$work/b" >/dev/null

id=$(docker create sealantd-freshness:b)
docker cp "$id:/usr/local/bin/sealantctl" "$work/sealantctl" >/dev/null
docker rm "$id" >/dev/null

if grep -q 'freshness-probeB' "$work/sealantctl" && ! grep -q 'freshness-probeA' "$work/sealantctl"; then
  echo "fresh: the second build's binary is built from its own source"
else
  echo "STALE: the second build shipped a binary of the first build's source" >&2
  exit 1
fi
