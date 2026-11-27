#!/bin/sh
# Sign an assembled Gantry.app inside-out (PLUG-14), then verify it. Called by bundle.sh.
#   sh sign-bundle.sh <Gantry.app> <identity>     identity "-" = ad hoc (owner builds are unsigned)
# Order: every nested binary first, the app last; no --deep when signing, so each is signed explicitly.
#   1. Contents/Frameworks/libbastion_rdp.dylib       hardened runtime, no entitlements
#   2. Contents/Helpers/bastion-plugin-host (if any)  hardened runtime, BastionPluginHelper.entitlements
#                                                     (only allow-unsigned-executable-memory; PLUG-01 q5)
#   3. the app                                        its own entitlements, unchanged
# Then `codesign --verify --deep --strict` on the whole bundle (PLUG-01, PLUG-14 point 2), and a
# check that the helper carries exactly its one entitlement and the app none of it.
# CODESIGN may name another codesign (the Linux test uses a stub).
set -eu
cd "$(dirname "$0")"
APP="$1"
IDENTITY="$2"
CODESIGN="${CODESIGN:-codesign}"
DYLIB="$APP/Contents/Frameworks/libbastion_rdp.dylib"
HELPER="$APP/Contents/Helpers/bastion-plugin-host"
HELPER_ENT=BastionPluginHelper.entitlements
HELPER_KEY=com.apple.security.cs.allow-unsigned-executable-memory

[ -d "$APP" ] || { echo "sign-bundle: no bundle at $APP" >&2; exit 1; }
[ -f "$DYLIB" ] || { echo "sign-bundle: missing $DYLIB" >&2; exit 1; }
# Contents/Helpers holds the plugin helper and nothing else: an unexpected file would be either
# unsigned (and fail --strict) or signed by nobody's decision.
if [ -d "$APP/Contents/Helpers" ]; then
  for f in "$APP/Contents/Helpers"/* "$APP/Contents/Helpers"/.[!.]*; do
    [ -e "$f" ] || continue
    [ "$f" = "$HELPER" ] || { echo "sign-bundle: unexpected file in Contents/Helpers: $f" >&2; exit 1; }
  done
  [ -f "$HELPER" ] && [ ! -L "$HELPER" ] || { echo "sign-bundle: $HELPER must be a regular file" >&2; exit 1; }
fi

if [ "$IDENTITY" = "-" ]; then
  # Ad hoc builds get the hardened runtime too (no paid signing; see README).
  set -- --force --options runtime --sign -
  APP_ENT=Bastion.adhoc.entitlements
else
  set -- --force --options runtime --timestamp --sign "$IDENTITY"
  APP_ENT=Bastion.entitlements
fi
# The helper's entitlement must never reach the app's own file.
if grep -q "$HELPER_KEY" "$APP_ENT"; then echo "sign-bundle: $APP_ENT must not hold $HELPER_KEY" >&2; exit 1; fi

"$CODESIGN" "$@" "$DYLIB"
if [ -f "$HELPER" ]; then
  "$CODESIGN" "$@" --entitlements "$HELPER_ENT" "$HELPER"
fi
"$CODESIGN" "$@" --entitlements "$APP_ENT" "$APP"

"$CODESIGN" --verify --deep --strict --verbose=2 "$APP"
if [ -f "$HELPER" ]; then
  ents="$("$CODESIGN" -d --entitlements - --xml "$HELPER" 2>/dev/null)"
  case "$ents" in *"$HELPER_KEY"*) ;; *) echo "sign-bundle: the helper lacks $HELPER_KEY" >&2; exit 1 ;; esac
  if [ "$(printf '%s\n' "$ents" | grep -o '<key>' | wc -l | tr -d ' ')" != 1 ]; then
    echo "sign-bundle: the helper carries more than $HELPER_KEY" >&2; exit 1
  fi
fi
app_ents="$("$CODESIGN" -d --entitlements - --xml "$APP" 2>/dev/null)"
case "$app_ents" in *"$HELPER_KEY"*) echo "sign-bundle: the app carries $HELPER_KEY" >&2; exit 1 ;; esac
