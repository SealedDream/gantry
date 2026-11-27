#!/usr/bin/env python3
"""pack-plugin.py <plugin dir> <wasm> <out.bastionplugin>: packs a plugin into the canonical
.bastionplugin layout of docs/specs/plugins.md section 6 (files back to back, no extra fields, no
data descriptors). Test fixture only: the package is unsigned, so the app installs it as Unverified."""
import struct, sys, zlib, pathlib

def png(size=32):
    raw = b"".join(b"\x00" + bytes([40, 90, 160, 255]) * size for _ in range(size))
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")

def main():
    d, wasm, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
    files = [("plugin.toml", (d / "plugin.toml").read_bytes()), ("plugin.wasm", wasm.read_bytes()), ("icon.png", png()),
             ("README.md", (d / "README.md").read_bytes()), ("LICENSE", b"MIT OR Apache-2.0 (test fixture)\n"),
             ("THIRD_PARTY_NOTICES.txt", b"None beyond the Bastion plugin SDK.\n")]
    body, directory = b"", b""
    for name, data in files:
        n = name.encode(); crc = zlib.crc32(data) & 0xFFFFFFFF
        comp = zlib.compressobj(9, zlib.DEFLATED, -15); c = comp.compress(data) + comp.flush()
        method, payload = (8, c) if len(c) < len(data) else (0, data)
        local = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0x0800, method, 0, 0x21, crc, len(payload), len(data), len(n), 0) + n
        directory += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 0x031E, 20, 0x0800, method, 0, 0x21, crc, len(payload), len(data), len(n), 0, 0, 0, 0, 0o100644 << 16, len(body)) + n
        body += local + payload
    end = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(files), len(files), len(directory), len(body), 0)
    pathlib.Path(out).write_bytes(body + directory + end)

main()
