#!/usr/bin/env bash
# Builds the host-vm guest kernel (workspace-isolation-architecture.md §5.1) from a pinned Linux
# 6.12 LTS tarball, checked against its sha256 before anything unpacks it.
#
#   kernel/build-kernel.sh x86_64  [out-dir]   # -> out-dir/vmlinux       (Cloud Hypervisor PVH)
#   kernel/build-kernel.sh aarch64 [out-dir]   # -> out-dir/Image
#   kernel/build-kernel.sh --config-only <arch> [out-dir]   # check the config, write only it
#
# The config is `allnoconfig` plus the fragment beside this script
# (linux-6.12-microvm.<arch>.config). Every line of the fragment must survive into the final
# .config; one Kconfig silently dropped (a missing dependency) fails the build, so the fragment is
# the whole description of the kernel. The build is reproducible: timestamp, user, host and build
# number are fixed, so the same inputs give the same bytes.
#
# Needs: curl, sha256sum, tar, xz, make, gcc, flex, bison, bc, perl, libelf and libssl headers.
# Building aarch64 on another arch needs CROSS_COMPILE (e.g. aarch64-linux-gnu-) or LLVM=1.
#
# Environment:
#   KERNEL_CACHE  where the tarball is kept between runs (default: ~/.cache/sealant-kernel)
#   JOBS          parallel jobs (default: nproc)
#   CONFIG_ONLY=1 stop after checking the config; writes only out-dir/config
set -euo pipefail

# A new 6.12.x moves both together. The sha256 is kernel.org's own
# (https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc, signed by the stable team).
KERNEL_VERSION=6.12.119
KERNEL_SHA256=143b287965acb9e270095b95894e59e2eba306d7e1f6b260d4ba74fca70c0333
# Fixed build metadata, and the release date of $KERNEL_VERSION as the timestamp.
BUILD_EPOCH=1795392000 # 2026-11-23T00:00:00Z

if [ "${1:-}" = --config-only ]; then
  CONFIG_ONLY=1
  shift
fi
arch=${1:-}
case "$arch" in
  x86_64)
    karch=x86_64
    target=vmlinux
    artifact=vmlinux
    ;;
  aarch64)
    karch=arm64
    target=Image
    artifact=arch/arm64/boot/Image
    ;;
  *)
    echo "usage: $0 [--config-only] x86_64|aarch64 [out-dir]" >&2
    exit 2
    ;;
esac

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=$(mkdir -p "${2:-$here/out/$arch}" && cd "${2:-$here/out/$arch}" && pwd)
fragment="$here/linux-6.12-microvm.$arch.config"
cache=${KERNEL_CACHE:-$HOME/.cache/sealant-kernel}
jobs=${JOBS:-$(nproc)}
tarball="$cache/linux-$KERNEL_VERSION.tar.xz"

if [ "$(uname -m)" != "$arch" ] && [ -z "${CROSS_COMPILE:-}" ] && [ -z "${LLVM:-}" ]; then
  echo "building $arch on $(uname -m) needs CROSS_COMPILE or LLVM=1" >&2
  exit 2
fi

mkdir -p "$cache"
work=$(mktemp -d "${TMPDIR:-/tmp}/sealant-kernel-$arch.XXXXXX")
trap 'rm -rf "$work"' EXIT
# Two builds (x86_64 and aarch64 in one multi-platform build) may share the cache: each downloads
# into its own work dir and checks it before an atomic rename, so neither sees the other's
# half-written file.
if ! echo "$KERNEL_SHA256  $tarball" | sha256sum -c --status - 2>/dev/null; then
  curl -fsSL --retry 3 -o "$work/download.tar.xz" \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"
  echo "$KERNEL_SHA256  $work/download.tar.xz" | sha256sum -c -
  mv -f "$work/download.tar.xz" "$tarball.$arch.$$"
  mv -f "$tarball.$arch.$$" "$tarball"
fi
echo "$KERNEL_SHA256  $tarball" | sha256sum -c -

tar -xJf "$tarball" -C "$work"
src="$work/linux-$KERNEL_VERSION"

export KBUILD_BUILD_TIMESTAMP="@$BUILD_EPOCH"
export KBUILD_BUILD_USER=sealant
export KBUILD_BUILD_HOST=sealant
export KBUILD_BUILD_VERSION=1
export SOURCE_DATE_EPOCH=$BUILD_EPOCH

make_args=(-C "$src" ARCH="$karch" -j"$jobs")
[ -n "${CROSS_COMPILE:-}" ] && make_args+=(CROSS_COMPILE="$CROSS_COMPILE")
[ -n "${LLVM:-}" ] && make_args+=(LLVM="$LLVM")

make "${make_args[@]}" KCONFIG_ALLCONFIG="$fragment" allnoconfig >/dev/null

# Every `CONFIG_X=v` and `# CONFIG_X is not set` in the fragment must be in the result.
missing=0
while IFS= read -r line; do
  case "$line" in
    CONFIG_*=*) want=$line ;;
    "# CONFIG_"*" is not set") want=$line ;;
    *) continue ;;
  esac
  name=${want#\# }
  name=${name%%[= ]*}
  if [[ $want == \#* ]]; then
    # Off may also be written by omission (an option whose dependencies are off).
    if grep -q "^$name=" "$src/.config"; then
      echo "fragment says $name off; .config has: $(grep "^$name=" "$src/.config")" >&2
      missing=1
    fi
  elif ! grep -qxF "$want" "$src/.config"; then
    got=$(grep -E "^(# )?$name[= ]" "$src/.config" || echo "absent")
    echo "fragment says $want; .config has: $got" >&2
    missing=1
  fi
done <"$fragment"
if [ "$missing" -ne 0 ]; then
  echo "Kconfig dropped lines of $fragment (missing dependencies?)" >&2
  exit 1
fi

if [ "${CONFIG_ONLY:-}" = 1 ]; then
  cp "$src/.config" "$out/config"
  echo "config for Linux $KERNEL_VERSION ($arch) holds every line of the fragment: $out/config"
  exit 0
fi

make "${make_args[@]}" "$target"

cp "$src/$artifact" "$out/$(basename "$artifact")"
cp "$src/.config" "$out/config"
(cd "$out" && sha256sum "$(basename "$artifact")" config | tee SHA256SUMS)
echo "built Linux $KERNEL_VERSION for $arch in $out"
