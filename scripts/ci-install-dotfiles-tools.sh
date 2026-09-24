#!/usr/bin/env bash
# Install GNU stow and chezmoi on an Ubuntu CI runner (amd64 or arm64), so the dotfiles tests in
# crates/sealantd apply real trees with both. CI runs those tests with
# SEALANTD_REQUIRE_DOTFILES_TOOLS=1, which makes a missing tool fail them instead of skipping.
#
# stow comes from apt. chezmoi is not packaged for Ubuntu 24.04, so its release .deb is fetched
# and checked against a pinned SHA-256 (from the release's chezmoi_<v>_checksums.txt).
set -euo pipefail

CHEZMOI_VERSION=2.72.0
arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64) sha256=6023435f5393553345ec10c75cd8160658c415f2bf9c3d8def3e120c92faf629 ;;
  arm64) sha256=9acbc4676bf257002a3439fc0936a9e3553e20ac51573214b7e7a6ef156d5ca1 ;;
  *) echo "no pinned chezmoi .deb for $arch" >&2; exit 1 ;;
esac

deb="$(mktemp -d)/chezmoi_${CHEZMOI_VERSION}_linux_${arch}.deb"
curl -fsSL -o "$deb" \
  "https://github.com/twpayne/chezmoi/releases/download/v${CHEZMOI_VERSION}/chezmoi_${CHEZMOI_VERSION}_linux_${arch}.deb"
echo "$sha256  $deb" | sha256sum --check --strict

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends stow "$deb"
stow --version
chezmoi --version
