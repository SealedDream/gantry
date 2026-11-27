import AppKit
let a = CommandLine.arguments; let icon = NSImage(contentsOfFile: a[1])!
let w = Int(a[3])!, h = Int(a[4])!, gradient = a[5] == "g"
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let r = NSRect(x: 0, y: 0, width: w, height: h)
let navy = NSColor(srgbRed: 0x1E/255, green: 0x1E/255, blue: 0x4B/255, alpha: 1)
let blue = NSColor(srgbRed: 0x27/255, green: 0x52/255, blue: 0xD9/255, alpha: 1)
if gradient { NSGradient(starting: blue, ending: navy)!.draw(in: r, angle: -90) } else { blue.setFill(); r.fill() }
let s = CGFloat(min(w, h)) * (gradient ? 0.62 : 0.86)
let y = gradient ? CGFloat(h) * 0.62 - s/2 : (CGFloat(h) - s)/2
icon.draw(in: NSRect(x: (CGFloat(w)-s)/2, y: y, width: s, height: s))
NSGraphicsContext.current?.flushGraphics()

// 24-bit bottom-up BMP (what Inno Setup reads everywhere)
let row = (w * 3 + 3) & ~3; var d = Data()
func u32(_ v: Int) { var x = UInt32(v).littleEndian; d.append(Data(bytes: &x, count: 4)) }
func u16(_ v: Int) { var x = UInt16(v).littleEndian; d.append(Data(bytes: &x, count: 2)) }
d.append(contentsOf: [0x42, 0x4D]); u32(54 + row * h); u32(0); u32(54)
u32(40); u32(w); u32(h); u16(1); u16(24); u32(0); u32(row * h); u32(2835); u32(2835); u32(0); u32(0)
for yy in stride(from: h - 1, through: 0, by: -1) {
  var line = [UInt8](repeating: 0, count: row)
  for xx in 0..<w { let c = rep.colorAt(x: xx, y: yy)!.usingColorSpace(.sRGB)!
    line[xx*3] = UInt8(c.blueComponent*255+0.5); line[xx*3+1] = UInt8(c.greenComponent*255+0.5); line[xx*3+2] = UInt8(c.redComponent*255+0.5) }
  d.append(contentsOf: line) }
try! d.write(to: URL(fileURLWithPath: a[2]))
