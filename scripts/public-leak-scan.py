"""Leak scan for the public export (scripts/public-leak-scan.sh is the entry point).

Walks every text file under a folder and reports file:line:category for anything that must not
be published: private IP addresses, e-mail addresses other than the public contact, provider
tokens and private keys (scripts/secret-scan-patterns.txt), absolute home-folder paths, vendor
names in user-facing text, internal workflow references, and the private terms (lab host names,
user names) listed in a file kept OUTSIDE the repository. Matched secrets and private terms are
never printed, only their category. Allowed hits are listed in scripts/public-leak-allow.txt.
Exit 0 = clean, 1 = hits, 2 = usage error.
"""
import os
import re
import sys

PUBLIC_CONTACTS = set()  # add the public contact address here once the owner picks one
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
# Reserved or protocol domains: SSH algorithm names (name@openssh.com) and RFC 2606/6761 examples.
EMAIL_OK_DOMAIN = re.compile(
    r"(?:^|\.)(?:openssh\.com|libssh\.org|lysator\.liu\.se|example|example\.(?:com|net|org)"
    r"|test|invalid|localhost|local|internal|service)$", re.I)
# Name, regex, blocking. Blocking hits fail the scan; the others are printed as "warn" so a
# reviewer sees them, but do not fail it (internal review IDs and design-note paths in comments).
CHECKS = [
    # Home-network range: blocking (the private lab lives in one). Other private ranges are
    # common documentation fixtures (10.0.0.5): reported, not blocking. Known lab addresses are
    # private terms and always block.
    ("private-ip", re.compile(r"(?<![\d.])192\.168\.\d{1,3}\.\d{1,3}(?![\d.])"), True),
    ("private-ip", re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])"), False),
    # Placeholder homes (/Users/me, C:\Users\you) are fine; real ones are private terms.
    ("home-path", re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+|[A-Z]:\\\\?Users\\\\?[A-Za-z0-9._-]+"), False),
    ("vendor-name", re.compile(r"Royal ?TSX?|Royal ?Server|royalapps", re.I), True),
    ("workflow", re.compile(
        r"\b(?:the|a|by|ask(?:ed|s)?|for) coordinator\b|\(coordinator[,)]|Bastion-notes|side-session"
        r"|\bCLAUDE\.md\b|\bAGENTS\.md\b|\bClaude\b|\bFable\b|\bSonnet\b|\bOpus (?:5|review|security)"
        r"|build-queue|\bbuild slot\b|\bmac-lock"), True),
    ("internal-ref", re.compile(
        r"\bCodex\b|docs/(?:tasks|evidence|reviews|plans|workflow)/|\bAUDIT\.md\b|\bBOARD\.md\b"
        r"|audit/fable-review|\bowner build"), False),
    # The old repository name: the rename to Gantry has landed (#1425), so any hit blocks the export.
    ("old-repo-name", re.compile(r"SealedDream" r"/bastion\b"), True),
]
BUILD_FILES = (".ps1", ".sh", ".py", ".csproj", ".props", ".targets", ".toml", ".swift", ".cmd")
# A build or packaging script that reaches into a folder the export leaves out breaks the public build.
TAURI_PATH = re.compile(r"ui-tauri[/\\]")
JUNK_FILE = re.compile(r"(^|/)(\._[^/]*|\.DS_Store)$")
USER_FACING = (".md", ".txt", ".xaml", ".resw", ".strings", ".html")
SKIP_DIRS = {".git", "target", "node_modules", ".build", "bin", "obj"}
MAX_BYTES = 4 * 1024 * 1024


def load_tab_file(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.strip() and not line.startswith("#"):
                rows.append(line.split("\t"))
    return rows


def load_private_terms(path):
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        terms = [t.strip() for t in fh if t.strip() and not t.startswith("#")]
    return [re.compile(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", re.I) for t in terms]


def is_text(data: bytes) -> bool:
    return b"\0" not in data[:8192]


def allowed(allow, category, rel, line):
    for row in allow:
        cat, path_rx = row[0], row[1]
        line_rx = row[2] if len(row) > 2 else ""
        if cat not in (category, "*"):
            continue
        if re.search(path_rx, rel) and (not line_rx or re.search(line_rx, line)):
            return True
    return False


def scan_line(rel, line, secrets, privates):
    hits = []
    for name, rx in secrets:
        if rx.search(line) and "gitleaks:allow" not in line:
            hits.append(("secret:" + name, None))
    for i, rx in enumerate(privates, 1):
        if rx.search(line):
            hits.append((f"private-term-{i}", None))
    for m in EMAIL.finditer(line):
        if m.group(0).lower() not in PUBLIC_CONTACTS and not EMAIL_OK_DOMAIN.search(m.group(1)):
            hits.append(("email", m.group(0)))
    if rel.endswith(BUILD_FILES) and TAURI_PATH.search(line):
        if not line.lstrip().startswith(("#", "//", "///", "<#", "--")):
            hits.append(("excluded-path", "ui-tauri"))
    for name, rx, blocking in CHECKS:
        m = rx.search(line)
        if not m:
            continue
        # A vendor name blocks only in user-facing text: docs, UI files and string literals.
        if name == "vendor-name" and not rel.endswith(USER_FACING):
            before = line[:m.start()]
            blocking = before.count('"') % 2 == 1 and not before.lstrip().startswith(("//", "#", "*"))
        hits.append((name if blocking else "warn:" + name, m.group(0)))
    return hits


def main():
    if len(sys.argv) != 4:
        print("usage: public-leak-scan.py <tree> <repo-scripts-dir> <private-terms-file|''>", file=sys.stderr)
        sys.exit(2)
    tree, scripts, private_file = sys.argv[1], sys.argv[2], sys.argv[3]
    secrets = [(r[0], re.compile(r[1].replace("[[:space:]]", r"\s"))) for r in load_tab_file(os.path.join(scripts, "secret-scan-patterns.txt"))
               if len(r) >= 2]
    allow = load_tab_file(os.path.join(scripts, "public-leak-allow.txt"))
    privates = load_private_terms(private_file)
    found = warned = 0
    for root, dirs, files in os.walk(tree):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, tree)
            for i, rx in enumerate(privates, 1):
                if rx.search(rel):
                    print(f"{rel}:0:private-term-{i} (in the path)"); found += 1
            if JUNK_FILE.search(rel):
                print(f"{rel}:0:junk-file (macOS metadata; export with COPYFILE_DISABLE=1)"); found += 1
                continue
            if os.path.islink(full) or os.path.getsize(full) > MAX_BYTES:
                continue
            with open(full, "rb") as fh:
                data = fh.read()
            if not is_text(data):
                continue
            for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
                for category, shown in scan_line(rel, line, secrets, privates):
                    # Private terms (lab names and addresses) can never be allowed.
                    if not category.startswith("private-term") and allowed(allow, category, rel, line):
                        continue
                    if category.startswith("warn:"):
                        warned += 1
                    else:
                        found += 1
                    print(f"{rel}:{n}:{category}" + (f": {shown[:80]}" if shown else ""))
    print(f"public-leak-scan: {found} blocking hit(s), {warned} warning(s)", file=sys.stderr)
    sys.exit(1 if found else 0)


if __name__ == "__main__":
    main()
