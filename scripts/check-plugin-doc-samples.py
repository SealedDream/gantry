#!/usr/bin/env python3
"""Checks that every ```rust block of docs/plugins/AUTHORING.md is a `// doc:` block of
plugins/sdk/tests/doc_samples.rs, word for word, so the guide's samples are the compiled ones.

Usage: python3 scripts/check-plugin-doc-samples.py
"""
import re
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs/plugins/AUTHORING.md"
SAMPLES = ROOT / "plugins/sdk/tests/doc_samples.rs"


def main() -> int:
    guide = GUIDE.read_text()
    source = SAMPLES.read_text()
    blocks = [textwrap.dedent(b).strip() for b in re.findall(r"```rust\n(.*?)```", guide, re.S)]
    samples = {
        name: textwrap.dedent(body).strip()
        for name, body in re.findall(r"^\s*// doc:([\w-]+)\n(.*?)^\s*// end$", source, re.S | re.M)
    }
    bad = 0
    for i, block in enumerate(blocks, 1):
        if block not in samples.values():
            print(f"rust block {i} of {GUIDE.name} is not a compiled sample:\n{block[:200]}")
            bad += 1
    unused = [n for n, body in samples.items() if body not in blocks]
    for name in unused:
        print(f"sample {name} is not in {GUIDE.name}")
        bad += 1
    print(f"{len(blocks)} rust blocks, {len(samples)} samples, {bad} problems")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
