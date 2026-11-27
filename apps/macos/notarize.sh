#!/bin/sh
# Notarize and staple a Developer-ID-signed build/Gantry.app (from BASTION_SIGN_IDENTITY=… ./bundle.sh).
# Credentials stay in the Keychain: create the profile once with
#   xcrun notarytool store-credentials bastion-notary --apple-id <id> --team-id <team>
# and run with BASTION_NOTARY_PROFILE=bastion-notary (the default).
set -eu
cd "$(dirname "$0")"
APP=build/Gantry.app
PROFILE="${BASTION_NOTARY_PROFILE:-bastion-notary}"
ZIP=build/Gantry-notarize.zip

[ -d "$APP" ] || { echo "missing $APP: run ./bundle.sh" >&2; exit 1; }
if codesign -dv "$APP" 2>&1 | grep -q "Signature=adhoc"; then
  echo "$APP is signed ad hoc; notarization needs BASTION_SIGN_IDENTITY (Developer ID Application)" >&2
  exit 1
fi
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$APP"
spctl --assess --type execute --verbose=2 "$APP"
rm -f "$ZIP"
echo "notarized and stapled $APP"
