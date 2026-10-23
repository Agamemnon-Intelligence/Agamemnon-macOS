#!/bin/bash
# Builds a Release copy of Agamemnon signed with a certificate from your keychain (instead of
# CI's ad-hoc signature), so the app and its protection helper carry your Team ID.
#
#   scripts/build-signed.sh "Apple Development: Name (TEAMID)" [output-folder]
#
# An "Apple Development" certificate gives a build that runs on your own Macs. For a public
# download, use a "Developer ID Application" certificate and notarize the DMG (see CI).
set -euo pipefail

IDENTITY="${1:?Pass the signing identity, e.g. \"Apple Development: Name (TEAMID)\" or its SHA-1}"
OUT="${2:-build/signed}"
cd "$(dirname "$0")/.."

# The Team ID is the certificate's OU (works with an identity name or its SHA-1).
TEAM="${TEAM:-}"
if [ -z "$TEAM" ]; then
  TEAM=$(security find-certificate -a -Z -p 2>/dev/null | awk -v id="$IDENTITY" '
      /^SHA-1 hash:/ { keep = (toupper($3) == toupper(id)) }
      keep { print }' | openssl x509 -noout -subject 2>/dev/null \
    | sed -n 's/.*OU *= *\([A-Z0-9]\{10\}\).*/\1/p' | head -1 || true)
fi
if [ -z "$TEAM" ]; then
  TEAM=$(security find-certificate -c "$IDENTITY" -p 2>/dev/null | openssl x509 -noout -subject 2>/dev/null \
    | sed -n 's/.*OU *= *\([A-Z0-9]\{10\}\).*/\1/p' | head -1 || true)
fi
echo "Signing with $IDENTITY (team ${TEAM:-unknown})"

xcodegen generate >/dev/null
xcodebuild -project Agamemnon.xcodeproj -scheme Agamemnon -configuration Release \
  -derivedDataPath "$OUT/dd" -destination "generic/platform=macOS" ONLY_ACTIVE_ARCH=NO \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$IDENTITY" DEVELOPMENT_TEAM="${TEAM:-}" \
  build | grep -E "error:|BUILD" || true

APP="$OUT/dd/Build/Products/Release/Agamemnon.app"
# Re-sign inside-out so the helper and the app share one identity and the hardened runtime.
codesign --force --options runtime --identifier com.mirazbakis.Agamemnon.Helper \
  --sign "$IDENTITY" "$APP/Contents/MacOS/AgamemnonHelper"
codesign --force --options runtime --entitlements Support/Agamemnon.entitlements \
  --sign "$IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -dv "$APP" 2>&1 | grep -E "Authority=|TeamIdentifier=" | head -3
echo "Signed app: $APP"
