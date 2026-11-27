import Foundation
import BastionCore

/// Wakes a terminal view as soon as its core screen changes. A background thread blocks in the
/// core's `waitChange` and hops to the main queue once per change, so a keystroke's echo is
/// drawn on the next display pass instead of waiting for a 60 Hz poll (which also kept the app
/// waking 60 times a second while idle).
final class TerminalWake: @unchecked Sendable {
    /// How long one wait blocks before the thread checks whether it was stopped.
    private static let waitSliceMs: UInt32 = 250
    /// A burst of output (scrollback) redraws at most this often, so copying the screen never
    /// starves the main thread; a lone keystroke echo is not delayed.
    private static let minInterval: TimeInterval = 1.0 / 120.0

    private let terminal: Terminal
    private let lock = NSLock()
    private var stopped = false
    private let delivered = DispatchSemaphore(value: 0)

    /// Starts the thread; `onChange` runs on the main queue, one call at a time.
    init(terminal: Terminal, onChange: @escaping @MainActor () -> Void) {
        self.terminal = terminal
        let thread = Thread { [self] in run(onChange) }
        thread.name = "bastion-terminal-wake"
        thread.qualityOfService = .userInteractive
        thread.start()
    }

    func stop() {
        lock.lock(); stopped = true; lock.unlock()
    }

    private var isStopped: Bool {
        lock.lock(); defer { lock.unlock() }
        return stopped
    }

    private func run(_ onChange: @escaping @MainActor () -> Void) {
        var seen = UInt64.max
        var lastDelivery = Date.distantPast
        while !isStopped {
            let gen = terminal.waitChange(after: seen, timeoutMs: Self.waitSliceMs)
            guard gen != seen, !isStopped else { continue }
            let wait = Self.minInterval - Date().timeIntervalSince(lastDelivery)
            if wait > 0 { Thread.sleep(forTimeInterval: wait) }
            // Read the generation the main thread will draw, then deliver and wait for it, so at
            // most one refresh is queued however fast output arrives.
            seen = terminal.generation()
            DispatchQueue.main.async { [delivered] in
                MainActor.assumeIsolated { onChange() }
                delivered.signal()
            }
            delivered.wait()
            lastDelivery = Date()
        }
    }
}
