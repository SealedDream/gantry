"""pack-ico.py <out.ico> <png>...: pack PNG images into one .ico (PNG-compressed entries, Vista and later)."""
import struct, sys
def size(png):
    if png[:8] != b"\x89PNG\r\n\x1a\n": raise SystemExit("not a PNG")
    return struct.unpack(">II", png[16:24])
def main(out, paths):
    imgs = [open(p, "rb").read() for p in paths]
    head = struct.pack("<HHH", 0, 1, len(imgs))
    off, dirs = 6 + 16 * len(imgs), b""
    for png in imgs:
        w, h = size(png)
        dirs += struct.pack("<BBBBHHII", w % 256, h % 256, 0, 0, 1, 32, len(png), off)
        off += len(png)
    open(out, "wb").write(head + dirs + b"".join(imgs))
if __name__ == "__main__":
    if len(sys.argv) < 3: raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2:])
