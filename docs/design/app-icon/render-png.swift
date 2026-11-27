// render-png.swift <in.svg> <px> <out.png>: draw an SVG at px × px with AppKit (same renderer as apps/macos/make-icns.swift).
import AppKit
let a = CommandLine.arguments
guard a.count == 4, let svg = NSImage(contentsOfFile: a[1]), let px = Int(a[2]),
      let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                                 hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else {
    FileHandle.standardError.write("usage: render-png.swift <in.svg> <px> <out.png>\n".data(using: .utf8)!); exit(1)
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
NSGraphicsContext.current?.imageInterpolation = .high
svg.draw(in: NSRect(x: 0, y: 0, width: px, height: px))
NSGraphicsContext.restoreGraphicsState()
try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[3]))
