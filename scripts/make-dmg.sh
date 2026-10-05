#!/bin/bash
# Packs Agamemnon.app into a compressed, drag-to-install DMG.
# Usage: scripts/make-dmg.sh path/to/Agamemnon.app Agamemnon.dmg
set -euo pipefail

APP="$1"
OUT="$2"
STAGING="$(mktemp -d)/Agamemnon"

mkdir -p "$STAGING"
cp -R "$APP" "$STAGING/"
ln -s /Applications "$STAGING/Applications"
cp LICENSE "$STAGING/LICENSE.txt"

rm -f "$OUT"
hdiutil create \
  -volname "Agamemnon" \
  -srcfolder "$STAGING" \
  -fs HFS+ \
  -format UDZO \
  -imagekey zlib-level=9 \
  -ov \
  "$OUT"

rm -rf "$(dirname "$STAGING")"
hdiutil verify "$OUT"
ls -lh "$OUT"
