#!/usr/bin/env python3
"""Fail when a Markdown table row has a different cell count than its header (Codex X05).

Usage: python3 scripts/check-md-tables.py [FILE.md ...]   (default: AUDIT.md and the security docs)
Escaped pipes (`\\|`) are not delimiters. A row glued to the next (`... || ...`) shows up as a
row with too many cells; a row cut off from its table by a blank line is reported too. Prints `file:line: expected N cells, got M` and exits 1 on any mismatch.
"""
import re
import os
import sys

DEFAULT = ["AUDIT.md", "SECURITY.md", "THREAT_MODEL.md", "SECURITY_CONTROL_MATRIX.md", "README.md"]
DELIMITER_ROW = re.compile(r"\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*")


def cells(line: str) -> int:
    body = re.sub(r"\\\|", "", line.strip())
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    return body.count("|") + 1


def check(path: str) -> list[str]:
    errors, expected = [], None
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    for i, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            expected = None
            continue
        if expected is None:
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if DELIMITER_ROW.fullmatch(nxt):
                expected = cells(line)
            else:
                errors.append(f"{path}:{i + 1}: table row outside a table (no header/delimiter above)")
            continue
        got = cells(line)
        if got != expected:
            errors.append(f"{path}:{i + 1}: expected {expected} cells, got {got}")
    return errors


def main(argv: list[str]) -> int:
    # Default files that are absent (the public export has no AUDIT.md) are skipped; named ones are not.
    paths = argv or [p for p in DEFAULT if os.path.exists(p)]
    errors = [e for p in paths for e in check(p)]
    print("\n".join(errors) or "tables OK")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
