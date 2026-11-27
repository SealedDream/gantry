#!/bin/sh
# Assemble build/Gantry.app from a release build: the executable, Info.plist, the bastion-rdp
# dylib in Contents/Frameworks and, when built, the plugin helper in Contents/Helpers (PLUG-14).
# Signs ad hoc by default; set BASTION_SIGN_IDENTITY to a
# "Developer ID Application: …" identity for a distributable build (hardened runtime + timestamp).
# Run ./build-core.sh and ./build-rdp.sh first. Signing is in sign-bundle.sh (inside-out).
set -eu
cd "$(dirname "$0")"
# The version the core reports as installed (core-ffi crate), so updates compare like for like.
VERSION="${BASTION_VERSION:-$(sed -n 's/^version = "\(.*\)"$/\1/p' ../../core-ffi/Cargo.toml | head -1)}"
BUILD="${BASTION_BUILD_NUMBER:-1}"
IDENTITY="${BASTION_SIGN_IDENTITY:--}"
APP=build/Gantry.app
DYLIB=Generated/rdp/lib/libbastion_rdp.dylib
# The plugin helper (PLUG-14, PLUG-06a part 2): one program file at Contents/Helpers/bastion-plugin-host.
# Required: the app starts it when a plugin opens. ./build-plugin-host.sh builds it when it is missing.
# BASTION_ALLOW_NO_PLUGIN_HELPER=1 makes a bundle without it (plugins then cannot open).
HELPER_SRC="${BASTION_PLUGIN_HELPER:-Generated/plugin-host/bastion-plugin-host}"
if [ ! -f "$HELPER_SRC" ] && [ -z "${BASTION_PLUGIN_HELPER:-}" ] && [ "${BASTION_ALLOW_NO_PLUGIN_HELPER:-0}" != 1 ]; then
  sh ./build-plugin-host.sh
fi
if [ -f "$HELPER_SRC" ]; then HAVE_HELPER=1
elif [ "${BASTION_ALLOW_NO_PLUGIN_HELPER:-0}" = 1 ]; then
  HAVE_HELPER=0; echo "note: no plugin helper at $HELPER_SRC; the bundle has no Contents/Helpers" >&2
else echo "missing plugin helper $HELPER_SRC" >&2; exit 1; fi

[ -f "$DYLIB" ] || { echo "missing $DYLIB: run ./build-rdp.sh" >&2; exit 1; }
# A bundle (owner builds included) must never ship a core built with BASTION_TEST_HOOKS=1: its
# test hooks let a UI-driver run skip the real screen-lock observer. Ask the built core itself
# (`test_hooks_build`) through a small C probe linked against the library the app will link.
sh ./check-release-core.sh
swift build -c release
BIN="$(swift build -c release --show-bin-path)/Bastion"
# Nor an app with the UI driver compiled in (uitests/build-app.sh): it would run any UI script
# named by BASTION_UI_SCRIPT. "ui-log.txt" is the driver's log file name and exists only in its code.
if grep -q "ui-log.txt" "$BIN"; then echo "REFUSED: $BIN has the UI test driver compiled in (BASTION_TEST_HOOKS)." >&2; exit 1; fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Frameworks" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Gantry"
cp "$DYLIB" "$APP/Contents/Frameworks/"
if [ "$HAVE_HELPER" = 1 ]; then
  mkdir -p "$APP/Contents/Helpers"
  cp "$HELPER_SRC" "$APP/Contents/Helpers/bastion-plugin-host"
  chmod 755 "$APP/Contents/Helpers/bastion-plugin-host"
fi
# The bundled terminal font (OFL, licence alongside); TerminalFonts registers it at launch.
mkdir -p "$APP/Contents/Resources/Fonts"
cp ../../assets/fonts/*.ttf ../../assets/fonts/OFL.txt "$APP/Contents/Resources/Fonts/"
# Third-party licences and notices for everything linked into the app (Codex L04; scripts/notices.py).
cp ../../licenses/native-mac/THIRD_PARTY_NOTICES.txt "$APP/Contents/Resources/"
# App icon, generated from the master artwork every build (no binary icon in the repo).
swift make-icns.swift ../../docs/design/app-icon/bastion-mac.svg "$APP/Contents/Resources/Gantry.icns"

# Development rpaths point into this source tree, the toolchain, or next to the binary; a shipped
# app must only search the OS Swift runtime and its own Frameworks folder, or a library planted
# at one of those paths would be loaded.
otool -l "$APP/Contents/MacOS/Gantry" | sed -n 's/^ *path \(.*\) (offset [0-9]*)$/\1/p' | while IFS= read -r rp; do
  case "$rp" in
    /usr/lib/swift|@executable_path/../Frameworks) ;;
    *) install_name_tool -delete_rpath "$rp" "$APP/Contents/MacOS/Gantry" ;;
  esac
done

COMMIT=$(sh ../../scripts/build-stamp.sh)  # BUILD-STAMP: BastionCommit in Info.plist
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>Gantry</string>
  <key>CFBundleIdentifier</key><string>dev.gantry.terminal</string>
  <key>CFBundleName</key><string>Gantry</string>
  <key>CFBundleDisplayName</key><string>Gantry Terminal</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD</string>
  <key>BastionCommit</key><string>$COMMIT</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>CFBundleIconFile</key><string>Gantry</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <!-- Gantry documents (.gantry): Finder opens them in Gantry (File › Open Document). Documents
       made before the rename (.bastion) open too. -->
  <key>UTExportedTypeDeclarations</key><array><dict>
    <key>UTTypeIdentifier</key><string>dev.gantry.document</string>
    <key>UTTypeDescription</key><string>Gantry Document</string>
    <key>UTTypeConformsTo</key><array><string>public.json</string><string>public.data</string></array>
    <key>UTTypeTagSpecification</key><dict><key>public.filename-extension</key><array><string>gantry</string></array></dict>
  </dict><dict>
    <key>UTTypeIdentifier</key><string>dev.bastion.document</string>
    <key>UTTypeDescription</key><string>Gantry Document (old format name)</string>
    <key>UTTypeConformsTo</key><array><string>public.json</string><string>public.data</string></array>
    <key>UTTypeTagSpecification</key><dict><key>public.filename-extension</key><array><string>bastion</string></array></dict>
  </dict></array>
  <key>CFBundleDocumentTypes</key><array><dict>
    <key>CFBundleTypeName</key><string>Gantry Document</string>
    <key>CFBundleTypeRole</key><string>Editor</string>
    <key>LSHandlerRank</key><string>Owner</string>
    <key>LSItemContentTypes</key><array><string>dev.gantry.document</string><string>dev.bastion.document</string></array>
  </dict></array>
  <!-- Cisco serves OpenH264 over plain HTTP only; the dylib is SHA-256 checked before loading. -->
  <key>NSAppTransportSecurity</key><dict><key>NSExceptionDomains</key><dict>
    <key>ciscobinary.openh264.org</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>
  </dict></dict>
</dict>
</plist>
PLIST

sh ./sign-bundle.sh "$APP" "$IDENTITY"
echo "built $APP ($VERSION/$BUILD, signed with $IDENTITY)"
