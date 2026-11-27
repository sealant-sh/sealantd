#!/usr/bin/env bash
# Build, sign, optionally notarize, verify, and package the macOS Apple Silicon host-VM helper
# bundle (`sealant-vmd-darwin-arm64.tar.gz` + `.sha256`).
#
# Usage:
#   scripts/build-macos-vmd.sh --out <dir> [--kernel <path-to-arm64-Image>] [--version <version>]
#
# Signing & notarization (optional — falls back to ad-hoc signing with the exact entitlements when
# Apple Developer signing env vars are unset, e.g. on PR CI or local development):
#   APPLE_DEVELOPER_IDENTITY     Code signing identity (e.g. "Developer ID Application: ...")
#   APPLE_DEVELOPER_CERT_P12     Base64-encoded .p12 certificate bundle
#   APPLE_DEVELOPER_CERT_PASSWORD Password for the .p12 bundle
#   APPLE_NOTARY_KEY_ID          App Store Connect API Key ID
#   APPLE_NOTARY_ISSUER_ID       App Store Connect Issuer UUID
#   APPLE_NOTARY_PRIVATE_KEY     PEM contents of the App Store Connect .p8 private key
set -euo pipefail

OUT_DIR=""
KERNEL_PATH=""
VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      OUT_DIR=$2
      shift 2
      ;;
    --kernel)
      KERNEL_PATH=$2
      shift 2
      ;;
    --version)
      VERSION=$2
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z $OUT_DIR ]]; then
  echo "Usage: $0 --out <dir> [--kernel <path-to-arm64-Image>] [--version <version>]" >&2
  exit 2
fi

if [[ $(uname -s) != "Darwin" || $(uname -m) != "arm64" ]]; then
  echo "scripts/build-macos-vmd.sh must run on Apple Silicon macOS (Darwin arm64)." >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENTITLEMENTS="$ROOT/macos/sealant-vz-worker/entitlements.plist"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sealant-vmd-build.XXXXXX")
KEYCHAIN=""
NOTARY_KEY_FILE=""

cleanup() {
  if [[ -n $KEYCHAIN ]]; then
    security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true
  fi
  if [[ -n $NOTARY_KEY_FILE ]]; then
    rm -f "$NOTARY_KEY_FILE"
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$OUT_DIR" "$WORK/stage"

echo "==> Building sealant-vmd (aarch64-apple-darwin, release)"
cargo build --locked --release --target aarch64-apple-darwin -p sealant-vmd \
  --manifest-path "$ROOT/Cargo.toml"
cp "$ROOT/target/aarch64-apple-darwin/release/sealant-vmd" "$WORK/stage/sealant-vmd"

echo "==> Building sealant-vz-worker (arm64-apple-macos14.0)"
swiftc \
  -O \
  -target arm64-apple-macos14.0 \
  -framework Foundation \
  -framework Virtualization \
  -framework IOKit \
  "$ROOT/macos/sealant-vz-worker/main.swift" \
  -o "$WORK/stage/sealant-vz-worker"

chmod 0755 "$WORK/stage/sealant-vmd" "$WORK/stage/sealant-vz-worker"

if [[ -n ${APPLE_DEVELOPER_IDENTITY:-} ]]; then
  echo "==> Signing with Developer ID identity"
  if [[ -n ${APPLE_DEVELOPER_CERT_P12:-} ]]; then
    KEYCHAIN="$WORK/sealant-signing.keychain-db"
    KEYCHAIN_PASS=$(openssl rand -hex 24)
    P12_FILE="$WORK/cert.p12"
    printf '%s' "$APPLE_DEVELOPER_CERT_P12" | base64 --decode >"$P12_FILE"
    security create-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"
    security set-keychain-settings -lut 21600 "$KEYCHAIN"
    security unlock-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"
    security import "$P12_FILE" \
      -P "${APPLE_DEVELOPER_CERT_PASSWORD:-}" \
      -A -t cert -f pkcs12 -k "$KEYCHAIN"
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASS" "$KEYCHAIN"
    security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
    rm -f "$P12_FILE"
  fi

  codesign --force --timestamp --options runtime \
    --sign "$APPLE_DEVELOPER_IDENTITY" \
    "$WORK/stage/sealant-vmd"
  codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS" \
    --sign "$APPLE_DEVELOPER_IDENTITY" \
    "$WORK/stage/sealant-vz-worker"

  if [[ -n ${APPLE_NOTARY_KEY_ID:-} && -n ${APPLE_NOTARY_ISSUER_ID:-} && -n ${APPLE_NOTARY_PRIVATE_KEY:-} ]]; then
    echo "==> Submitting signed binaries for Apple notarization"
    NOTARY_KEY_FILE="$WORK/AuthKey_${APPLE_NOTARY_KEY_ID}.p8"
    printf '%s\n' "$APPLE_NOTARY_PRIVATE_KEY" >"$NOTARY_KEY_FILE"
    chmod 0600 "$NOTARY_KEY_FILE"
    NOTARY_ZIP="$WORK/sealant-vmd-notary.zip"
    ditto -c -k --keepParent "$WORK/stage" "$NOTARY_ZIP"
    xcrun notarytool submit "$NOTARY_ZIP" \
      --key "$NOTARY_KEY_FILE" \
      --key-id "$APPLE_NOTARY_KEY_ID" \
      --issuer "$APPLE_NOTARY_ISSUER_ID" \
      --wait \
      --output-format json >"$WORK/notary-result.json"
    cat "$WORK/notary-result.json"
    if ! grep -q '"status"[[:space:]]*:[[:space:]]*"Accepted"' "$WORK/notary-result.json"; then
      echo "::error::Apple notarization was not accepted." >&2
      exit 1
    fi
  else
    echo "::warning::APPLE_NOTARY_* secrets are not set; skipping notarization."
  fi
else
  echo "==> Ad-hoc signing (APPLE_DEVELOPER_IDENTITY unset)"
  codesign --force --sign - "$WORK/stage/sealant-vmd"
  codesign --force --sign - --entitlements "$ENTITLEMENTS" "$WORK/stage/sealant-vz-worker"
fi

echo "==> Verifying signatures and entitlements"
codesign --verify --strict --verbose=2 "$WORK/stage/sealant-vmd"
codesign --verify --strict --verbose=2 "$WORK/stage/sealant-vz-worker"

ENTS_OUT=$(codesign -d --entitlements :- "$WORK/stage/sealant-vz-worker" 2>/dev/null)
if ! grep -q "com.apple.security.virtualization" <<<"$ENTS_OUT"; then
  echo "::error::sealant-vz-worker is missing com.apple.security.virtualization entitlement." >&2
  exit 1
fi

"$WORK/stage/sealant-vmd" --version

if [[ -n $KERNEL_PATH ]]; then
  if [[ ! -f $KERNEL_PATH ]]; then
    echo "::error::Kernel image not found at $KERNEL_PATH" >&2
    exit 1
  fi
  cp "$KERNEL_PATH" "$WORK/stage/Image"
  chmod 0644 "$WORK/stage/Image"
fi

if [[ -n $VERSION ]]; then
  printf '%s\n' "$VERSION" >"$WORK/stage/VERSION"
fi

(cd "$WORK/stage" && shasum -a 256 -- * >SHA256SUMS)

ARCHIVE="$OUT_DIR/sealant-vmd-darwin-arm64.tar.gz"
tar -C "$WORK/stage" -czf "$ARCHIVE" .
(cd "$OUT_DIR" && shasum -a 256 "$(basename "$ARCHIVE")" >"$(basename "$ARCHIVE").sha256")

echo "==> Built $ARCHIVE"
cat "${ARCHIVE}.sha256"
