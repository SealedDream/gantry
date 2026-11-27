"""Filter repo paths (NUL-separated on stdin) by the rules in scripts/public-export.list.

Rules: "+ pattern" includes, "- pattern" excludes; the last matching rule wins; no match = out.
"*" and "?" stay inside one path component, "**/" is any number of folders, a trailing "/**"
is everything below. Writes the selected paths NUL-separated to stdout.
"""
import re
import sys


def compile_pattern(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?"); i += 3
        elif pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("/.*"); i += 3
        elif pattern.startswith("**", i):
            out.append(".*"); i += 2
        elif pattern[i] == "*":
            out.append("[^/]*"); i += 1
        elif pattern[i] == "?":
            out.append("[^/]"); i += 1
        else:
            out.append(re.escape(pattern[i])); i += 1
    return re.compile("".join(out) + r"\Z")


def load_rules(path: str):
    rules = []
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if len(line) < 3 or line[0] not in "+-" or line[1] != " ":
                sys.exit(f"public-export.list:{n}: expected '+ pattern' or '- pattern': {line}")
            rules.append((line[0] == "+", compile_pattern(line[2:].strip())))
    if not rules:
        sys.exit("public-export.list has no rules")
    return rules


def selected(path: str, rules) -> bool:
    keep = False
    for include, rx in rules:
        if rx.match(path):
            keep = include
    return keep


def main() -> None:
    rules = load_rules(sys.argv[1])
    paths = [p for p in sys.stdin.buffer.read().decode("utf-8").split("\0") if p]
    out = [p for p in paths if selected(p, rules)]
    sys.stdout.buffer.write("".join(p + "\0" for p in out).encode("utf-8"))


if __name__ == "__main__":
    main()
