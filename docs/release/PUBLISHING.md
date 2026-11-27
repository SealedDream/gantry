# Publishing Gantry to its public repository

The private repository stays the development repository. The public repository
`SealedDream/gantry` gets one fresh commit made from `scripts/public-export.sh`: no history, no
branches, no internal notes. Later releases repeat steps 2 to 4 and 7 to 9 as a new commit on
top.

Every step that creates, publishes or changes something outside this Mac is marked
**needs owner yes**. Nobody runs those steps without the owner's yes for that step.

## 0. Before you start (no owner yes needed: nothing leaves the Mac)

1. The rename to Gantry, the public README (`docs/public-release-readme`) and the Inno Setup
   installer are merged into `main`.
2. Pick the commit to publish and tag it in the private repo only if the owner wants that tag
   there: `REF=<commit>`.
3. The private lab terms file exists outside the repo (lab host names, VM names, lab user names,
   lab addresses, one per line), for example `~/.config/gantry-release/public-leak-terms.txt`.

## 1. Export and scan (no owner yes needed)

```bash
OUT=~/gantry-public-$(date +%Y%m%d)
PUBLIC_LEAK_TERMS=~/.config/gantry-release/public-leak-terms.txt sh scripts/public-export.sh "$OUT" "$REF"
```

It must end with `public-leak-scan: 0 blocking hit(s)`. Read the warnings it prints too
(internal review IDs in comments, fixture addresses); they do not block but a reviewer signs them
off. Then build and test the export itself:

```bash
cd "$OUT" && sh scripts/ci-mac.sh && sh scripts/secret-scan.sh --tree
```

`secret-scan.sh --tree` needs git: run it after step 2's `git init` and `git add`. The Windows
build of the same tree runs on a builder (`build-core.ps1`, `dotnet build -c Release`).

## 2. Make the one commit locally (no owner yes needed)

```bash
cd "$OUT"
git init -b main
git add -A
git -c user.name="SealedDream" -c user.email="<public contact address>" commit -F - <<'MSG'
feat: Gantry 1.0.0, first public release

Gantry is a remote-administration workstation for macOS and Windows: SSH, SFTP, RDP, VNC,
web sessions, credentials, tunnels and tasks, with one Rust core and two native apps
(SwiftUI on the Mac, WinUI 3 on Windows). It works fully offline.

This repository starts from a clean export of the development tree at 1.0.0.
MSG
```

Check that `git log` shows exactly one commit and `git status` is clean. The author address must
be the chosen public contact, never a personal address.

## 3. Create the public repository — **needs owner yes**

```bash
gh repo create SealedDream/gantry --public \
  --description "Remote administration for macOS and Windows: SSH, SFTP, RDP, VNC, web. Native apps, one Rust core, works offline." \
  --homepage "https://github.com/SealedDream/gantry"
```

Do not let `gh` add a README, licence or .gitignore: the export has them.

## 4. Push the export as one commit — **needs owner yes**

```bash
cd "$OUT"
git remote add origin https://github.com/SealedDream/gantry.git
git push -u origin main
```

## 5. Repository settings — **needs owner yes**

```bash
# Private vulnerability reporting (SECURITY.md points here)
gh api -X PUT repos/SealedDream/gantry/private-vulnerability-reporting
# Topics
gh repo edit SealedDream/gantry --add-topic ssh,rdp,vnc,sftp,remote-desktop,terminal,macos,windows,rust,swiftui,winui3
# Keep the repo free of paid features: no Actions (none are in the export), no wiki
gh repo edit SealedDream/gantry --enable-wiki=false
gh api -X PUT repos/SealedDream/gantry/actions/permissions -F enabled=false
```

Check in the web UI: Settings › Code security › Private vulnerability reporting is on.

## 6. Point the update check at the public repository

The apps look for updates in `core/src/update/github.rs` (`RELEASE_REPO`), and the release
scripts publish to `REPO` in `scripts/release.sh` and the download URLs in
`scripts/sign-update-manifest.sh`. All three must say `SealedDream/gantry` **before** the build
that becomes 1.0.0, so this change goes into the private repo by pull request and the export is
made after it (go back to step 1 if needed). No owner yes for the pull request; the owner's yes
in step 8 covers what it publishes.

## 7. Tag v1.0.0 — **needs owner yes**

```bash
cd "$OUT"
git tag -a v1.0.0 -m "Gantry 1.0.0"
git push origin v1.0.0
```

## 8. Build and upload the release assets — **needs owner yes**

1. Windows, on a builder, from the same tree: `apps\windows\package-windows.ps1` gives
   `Gantry-windows-x64.zip` and the Inno Setup installer.
2. Mac, from the tagged export (`package-release.sh` refuses anything but a clean tagged tree):
   ```bash
   cd "$OUT" && git checkout v1.0.0
   sh scripts/package-release.sh --check v1.0.0 <signed-plugin-dir> <windows-zip> <windows-setup-exe>
   sh scripts/package-release.sh v1.0.0 <signed-plugin-dir> <windows-zip> <windows-setup-exe>
   ```
   Output: `dist/v1.0.0/` with the Mac zip and dmg, the Windows zip and setup, `install.ps1`
   and `SHA256SUMS`.
3. Sign the update manifest and publish (the key file stays outside every repository):
   ```bash
   NOTES=docs/release/v1.0.0-notes.md sh scripts/release.sh --dry-run 1.0.0 <update-key-file> dist/v1.0.0/*
   NOTES=docs/release/v1.0.0-notes.md sh scripts/release.sh 1.0.0 <update-key-file> dist/v1.0.0/*
   ```
   The dry run prints the files; read the list before the real run.

## 9. After publishing — **needs owner yes** for each

- Download each asset from the release page on a clean Mac and a clean Windows 11 machine, check
  `SHA256SUMS`, install, and run "Check for Updates": it must say it is up to date.
- Pin the release as latest if GitHub did not.
- Later releases: export the new ref into a clone of the public repo's working tree
  (`rsync -a --delete --exclude .git "$NEW_OUT"/ gantry/`), commit with release notes, then
  steps 4, 7, 8.
