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
# hdiutil sometimes fails on CI runners with "Resource busy"; try a few times.
for attempt in 1 2 3 4 5; do
  if hdiutil create \
      -volname "Agamemnon" \
      -srcfolder "$STAGING" \
      -fs HFS+ \
      -format UDZO \
      -imagekey zlib-level=9 \
      -ov \
      "$OUT"; then
    break
  fi
  if [ "$attempt" = 5 ]; then
    echo "hdiutil create failed 5 times" >&2
    exit 1
  fi
  echo "hdiutil create failed (attempt $attempt), retrying in $((attempt * 5)) s…" >&2
  rm -f "$OUT"
  sleep $((attempt * 5))
done

rm -rf "$(dirname "$STAGING")"
hdiutil verify "$OUT"
ls -lh "$OUT"
