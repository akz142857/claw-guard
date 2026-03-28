#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# bundle-macos.sh — Build, sign, notarize, and package Claw Guard as a macOS app
#
# Usage:
#   ./scripts/bundle-macos.sh [--sign] [--notarize] [--dmg] [--target TARGET]
#
# Environment variables (required for --sign / --notarize):
#   DEVELOPER_ID        — "Developer ID Application: Name (TEAM_ID)"
#   APPLE_ID            — Apple ID email (for notarization)
#   APPLE_TEAM_ID       — Team ID
#   APPLE_APP_PASSWORD  — App-specific password (generate at appleid.apple.com)
#
# Examples:
#   ./scripts/bundle-macos.sh                                    # Build .app only
#   ./scripts/bundle-macos.sh --sign --notarize --dmg            # Full release
#   ./scripts/bundle-macos.sh --target x86_64-apple-darwin --dmg # Intel build
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Parse args ────────────────────────────────────────────────────────────────
DO_SIGN=false
DO_NOTARIZE=false
DO_DMG=false
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --sign)      DO_SIGN=true ;;
        --notarize)  DO_NOTARIZE=true; DO_SIGN=true ;;  # notarize implies sign
        --dmg)       DO_DMG=true ;;
        --target)    TARGET="$2"; shift ;;
        *)           echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ── Project root ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ── Version from Cargo.toml ──────────────────────────────────────────────────
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo "==> Building Claw Guard v${VERSION}"

# ── Determine target ─────────────────────────────────────────────────────────
if [[ -z "$TARGET" ]]; then
    ARCH=$(uname -m)
    if [[ "$ARCH" == "arm64" ]]; then
        TARGET="aarch64-apple-darwin"
    else
        TARGET="x86_64-apple-darwin"
    fi
fi
echo "==> Target: $TARGET"

# ── Build release binary ─────────────────────────────────────────────────────
echo "==> cargo build --release --target $TARGET"
cargo build --release --target "$TARGET"

BINARY="target/${TARGET}/release/claw-guard"
if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: Binary not found at $BINARY"
    exit 1
fi

# ── Generate .icns from icon.png ─────────────────────────────────────────────
ICON_SRC="assets/icon.png"
ICNS_OUT="assets/icon.icns"

if [[ ! -f "$ICNS_OUT" ]] || [[ "$ICON_SRC" -nt "$ICNS_OUT" ]]; then
    echo "==> Generating .icns icon"
    ICONSET_DIR=$(mktemp -d)/icon.iconset
    mkdir -p "$ICONSET_DIR"
    # Source is 256x256, so we generate sizes up to 256; larger sizes reuse 256
    for SIZE in 16 32 64 128 256; do
        sips -z $SIZE $SIZE "$ICON_SRC" --out "$ICONSET_DIR/icon_${SIZE}x${SIZE}.png" >/dev/null 2>&1
    done
    # @2x variants
    sips -z 32 32   "$ICON_SRC" --out "$ICONSET_DIR/icon_16x16@2x.png"   >/dev/null 2>&1
    sips -z 64 64   "$ICON_SRC" --out "$ICONSET_DIR/icon_32x32@2x.png"   >/dev/null 2>&1
    sips -z 128 128 "$ICON_SRC" --out "$ICONSET_DIR/icon_64x64@2x.png"   >/dev/null 2>&1
    sips -z 256 256 "$ICON_SRC" --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null 2>&1
    sips -z 256 256 "$ICON_SRC" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null 2>&1
    # 512 and 1024 — upscale from 256 (not ideal but functional)
    sips -z 512 512   "$ICON_SRC" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null 2>&1 || true
    sips -z 512 512   "$ICON_SRC" --out "$ICONSET_DIR/icon_512x512.png"    >/dev/null 2>&1 || true
    sips -z 1024 1024 "$ICON_SRC" --out "$ICONSET_DIR/icon_512x512@2x.png" >/dev/null 2>&1 || true
    iconutil -c icns "$ICONSET_DIR" -o "$ICNS_OUT" 2>/dev/null || true
    rm -rf "$(dirname "$ICONSET_DIR")"

    if [[ -f "$ICNS_OUT" ]]; then
        echo "    Created $ICNS_OUT"
    else
        echo "    WARNING: iconutil failed, .app will have no icon"
    fi
fi

# ── Create .app bundle ───────────────────────────────────────────────────────
APP_NAME="Claw Guard.app"
APP_DIR="target/${TARGET}/release/${APP_NAME}"

echo "==> Creating ${APP_NAME}"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Copy binary
cp "$BINARY" "$APP_DIR/Contents/MacOS/claw-guard"
chmod +x "$APP_DIR/Contents/MacOS/claw-guard"

# Copy Info.plist with version substitution
sed "s/__VERSION__/${VERSION}/g" macos/Info.plist > "$APP_DIR/Contents/Info.plist"

# Copy icon
if [[ -f "$ICNS_OUT" ]]; then
    cp "$ICNS_OUT" "$APP_DIR/Contents/Resources/icon.icns"
fi

echo "    ${APP_DIR}"

# ── Code signing ─────────────────────────────────────────────────────────────
if $DO_SIGN; then
    if [[ -z "${DEVELOPER_ID:-}" ]]; then
        echo "ERROR: DEVELOPER_ID not set. Example:"
        echo '  export DEVELOPER_ID="Developer ID Application: Clay & Cosmos (Tianjin) Technology Co., Ltd. (TEAM_ID)"'
        exit 1
    fi

    echo "==> Signing with: $DEVELOPER_ID"
    codesign --force --deep --options runtime \
        --sign "$DEVELOPER_ID" \
        --entitlements macos/entitlements.plist \
        --timestamp \
        "$APP_DIR"

    echo "==> Verifying signature"
    codesign --verify --deep --strict "$APP_DIR"
    spctl --assess --type execute --verbose "$APP_DIR" 2>&1 || true
    echo "    Signature OK"
fi

# ── Notarization ─────────────────────────────────────────────────────────────
if $DO_NOTARIZE; then
    for VAR in APPLE_ID APPLE_TEAM_ID APPLE_APP_PASSWORD; do
        if [[ -z "${!VAR:-}" ]]; then
            echo "ERROR: $VAR not set"
            exit 1
        fi
    done

    echo "==> Submitting for notarization..."

    # Create a zip for notarization submission
    NOTARIZE_ZIP="target/${TARGET}/release/ClawGuard-notarize.zip"
    ditto -c -k --keepParent "$APP_DIR" "$NOTARIZE_ZIP"

    xcrun notarytool submit "$NOTARIZE_ZIP" \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait

    echo "==> Stapling notarization ticket"
    xcrun stapler staple "$APP_DIR"

    rm -f "$NOTARIZE_ZIP"
    echo "    Notarization complete"
fi

# ── Create DMG ───────────────────────────────────────────────────────────────
if $DO_DMG; then
    # Determine architecture label
    case "$TARGET" in
        aarch64-*) ARCH_LABEL="arm64" ;;
        x86_64-*)  ARCH_LABEL="amd64" ;;
        *)         ARCH_LABEL="unknown" ;;
    esac

    DMG_NAME="ClawGuard-v${VERSION}-darwin-${ARCH_LABEL}.dmg"
    DMG_PATH="target/${TARGET}/release/${DMG_NAME}"

    echo "==> Creating DMG: ${DMG_NAME}"

    # Create a temporary directory for DMG contents
    DMG_STAGING=$(mktemp -d)
    cp -R "$APP_DIR" "$DMG_STAGING/"
    ln -s /Applications "$DMG_STAGING/Applications"

    hdiutil create -volname "Claw Guard" \
        -srcfolder "$DMG_STAGING" \
        -ov -format UDZO \
        "$DMG_PATH"

    rm -rf "$DMG_STAGING"

    # Sign the DMG itself
    if $DO_SIGN && [[ -n "${DEVELOPER_ID:-}" ]]; then
        codesign --force --sign "$DEVELOPER_ID" --timestamp "$DMG_PATH"
    fi

    echo "    ${DMG_PATH}"
    echo ""
    echo "==> Done! Artifacts:"
    echo "    App: ${APP_DIR}"
    echo "    DMG: ${DMG_PATH}"
else
    echo ""
    echo "==> Done! App: ${APP_DIR}"
fi
