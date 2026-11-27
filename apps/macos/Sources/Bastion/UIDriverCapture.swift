#if BASTION_TEST_HOOKS
import AppKit

/// The capture steps (`capture`, `capture-window`, `capture-sheet`, `capture-popover`, `top-capture`,
/// `capture-settings-sheet`, and the fit suite's pictures of failing windows).
///
/// The picture is taken here, in the app, at the step (`WindowCapture`), and the step does not end
/// until the file is on disk. Until 2026-11-13 the runner outside the app took it with `screencapture`
/// after reading the log; that failed while the screen was locked and otherwise came late, so
/// pictures showed a later state or a closed sheet (MAC-CAPTURE-01).
extension Driver {
    /// Longest wait for the window to stop changing (a sheet sliding in) before the picture is taken.
    private static let settleLimit = 1.0
    /// Pause between two looks at the window while waiting for it to stop changing.
    private static let settlePoll = 0.1
    /// The step used to hold this long for the outside runner. Kept so every suite's timing is as it
    /// was; the picture no longer depends on it.
    private static let holdAfterCapture = 1.2

    static var screenState: String { WindowCapture.isScreenLocked ? "locked" : "unlocked" }

    /// `capture-source window|views|any`: which sources the captures after this step may use.
    /// `window` is for pictures that go into evidence: the capture fails instead of using the fallback.
    func captureSourceStep(_ arg: String) {
        guard let sources = WindowCapture.sources(for: arg) else { return write("FAIL capture-source \(arg): use window, views or any") }
        WindowCapture.sources = sources
        write("CAPTURE-SOURCE \(arg)")
    }

    /// Writes `<name>.png` for `window` and logs `CAPTURE <window number> <name> source=<window|views>`, or a
    /// FAIL line when the name is not a plain file name or no picture that shows anything could be taken
    /// from the allowed sources. An existing file of that name is replaced.
    func capture(_ window: NSWindow, _ name: String) async {
        let start = CFAbsoluteTimeGetCurrent()
        guard CaptureCheck.isValidName(name) else {
            return write("FAIL capture: the name must be a plain file name (letters, digits, dot, dash, underscore; no leading dot)")
        }
        guard let picture = await settledPicture(of: window) else {
            let tried = WindowCapture.sources.map(\.rawValue).joined(separator: ", ")
            return write("FAIL capture \(name): no picture of window \(window.windowNumber) (screen \(Self.screenState)); "
                         + "sources tried: \(tried); each gave nothing or a blank image")
        }
        guard let data = WindowCapture.png(picture.image) else { return write("FAIL capture \(name): the picture could not be encoded") }
        do {
            try data.write(to: out.appendingPathComponent("\(name).png"), options: .atomic)
        } catch {
            return write("FAIL capture \(name): \(error.localizedDescription)")
        }
        write(String(format: "CAPTURE-INFO %@ source=%@ screen=%@ %dx%d %.0f ms", name, picture.source.rawValue, Self.screenState,
                     picture.image.width, picture.image.height, (CFAbsoluteTimeGetCurrent() - start) * 1000))
        write("CAPTURE \(window.windowNumber) \(name) source=\(picture.source.rawValue)")
        await settle(Self.holdAfterCapture)
    }

    /// The window's picture once two looks in a row are the same, or the last one at the limit
    /// (a blinking caret or a spinner never settles).
    func settledPicture(of window: NSWindow) async -> WindowCapture.Picture? {
        let deadline = CFAbsoluteTimeGetCurrent() + Self.settleLimit
        var last = WindowCapture.take(window)
        while CFAbsoluteTimeGetCurrent() < deadline {
            await settle(Self.settlePoll)
            let next = WindowCapture.take(window)
            let isSame = last != nil && last?.image.dataProvider?.data as Data? == next?.image.dataProvider?.data as Data?
            last = next ?? last
            if isSame { break }
        }
        return last
    }
}
#endif
