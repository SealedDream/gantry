#!/usr/bin/env python3
"""plugin-pack.py <plugin dir> <plugin.wasm> <out.bastionplugin> <permissions.json>

Packs an Official plugin into the canonical .bastionplugin layout (docs/specs/plugins.md,
section 6: files back to back, no extra fields, no data descriptors, fixed time stamps so two
packs of the same build are byte-identical) and writes its [permissions] table as the JSON the
release record carries (scripts/plugin-sign.sh record). Used by scripts/plugin-release.sh."""
import json, pathlib, struct, sys, tomllib, zlib

def png(size=32):
    raw = b"".join(b"\x00" + bytes([40, 90, 160, 255]) * size for _ in range(size))
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")

def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    d, wasm, out, perms_out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
    manifest_bytes = (d / "plugin.toml").read_bytes()
    manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    readme = d / "README.md"
    readme_bytes = readme.read_bytes() if readme.is_file() else f"# {manifest['name']}\n\n{manifest['description']}\n".encode()
    licence = manifest["license"]
    files = [
        ("plugin.toml", manifest_bytes),
        ("plugin.wasm", wasm.read_bytes()),
        ("icon.png", png()),
        ("README.md", readme_bytes),
        ("LICENSE", f"SPDX-License-Identifier: {licence}\nFull text: https://spdx.org/licenses/{licence}.html\n".encode()),
        ("THIRD_PARTY_NOTICES.txt", b"Third-party crates and their licences: see the plugin's Cargo.lock in the Bastion repository.\n"),
    ]
    body, directory = b"", b""
    for name, data in files:
        n = name.encode(); crc = zlib.crc32(data) & 0xFFFFFFFF
        comp = zlib.compressobj(9, zlib.DEFLATED, -15); c = comp.compress(data) + comp.flush()
        method, payload = (8, c) if len(c) < len(data) else (0, data)
        local = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0x0800, method, 0, 0x21, crc, len(payload), len(data), len(n), 0) + n
        directory += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 0x031E, 20, 0x0800, method, 0, 0x21, crc, len(payload), len(data), len(n), 0, 0, 0, 0, 0o100644 << 16, len(body)) + n
        body += local + payload
    end = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(files), len(files), len(directory), len(body), 0)
    out.write_bytes(body + directory + end)
    perms_out.write_text(json.dumps(manifest.get("permissions", {}), separators=(",", ":")))

main()
