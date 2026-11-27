#if BASTION_TEST_HOOKS
import CoreGraphics

/// Checks for test captures (`UIDriver`): the name, and whether the picture shows anything. A picture
/// that is one flat colour shows no state at all, so the capture step fails instead of saving it. Seen 2026-11-13: fully transparent pictures of sheets that had closed.
enum CaptureCheck {
    /// Longest capture name (it becomes `<name>.png`; file names are capped at 255 bytes).
    static let maxNameLength = 200

    /// A capture name becomes a file in the run's output folder, so it must be a plain file name:
    /// ASCII letters, digits, dot, dash and underscore, not starting with a dot. No path separator
    /// (`../x` would write outside the folder) and no space (the runner reads names as one word).
    static func isValidName(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= maxNameLength, !name.hasPrefix(".") else { return false }
        return name.utf8.allSatisfy { c in
            (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x2E || c == 0x2D || c == 0x5F
        }
    }

    /// Channel difference still counted as the same colour (dithering, colour-space rounding).
    static let tolerance = 2

    /// True when the opaque pixels of `rgba` (8-bit RGBA, premultiplied, `bytesPerRow` wide rows) are all
    /// one colour, or when there are none. Transparent and partly transparent pixels (a window's rounded
    /// corners) are skipped, so an empty white sheet is blank too.
    static func isBlank(rgba: [UInt8], width: Int, height: Int, bytesPerRow: Int) -> Bool {
        var first: (Int, Int, Int)?
        for y in 0..<height {
            for x in 0..<width {
                let i = y * bytesPerRow + x * 4
                guard rgba[i + 3] == 255 else { continue }
                let pixel = (Int(rgba[i]), Int(rgba[i + 1]), Int(rgba[i + 2]))
                guard let f = first else { first = pixel; continue }
                if abs(pixel.0 - f.0) > tolerance || abs(pixel.1 - f.1) > tolerance || abs(pixel.2 - f.2) > tolerance { return false }
            }
        }
        return true
    }

    /// `isBlank(rgba:)` for an image; an image that cannot be drawn counts as blank.
    static func isBlank(_ image: CGImage) -> Bool {
        let (width, height) = (image.width, image.height)
        guard width > 0, height > 0 else { return true }
        var pixels = [UInt8](repeating: 0, count: width * height * 4)
        let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(data: buffer.baseAddress, width: width, height: height, bitsPerComponent: 8,
                                          bytesPerRow: width * 4, space: CGColorSpaceCreateDeviceRGB(),
                                          bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return false }
            context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
            return true
        }
        return !drawn || isBlank(rgba: pixels, width: width, height: height, bytesPerRow: width * 4)
    }
}
#endif
