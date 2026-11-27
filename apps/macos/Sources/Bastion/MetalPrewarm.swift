import Metal

/// QA P1 (first local shell stall, 600 ms): the first terminal layer makes Core Animation's
/// accelerated drawing create its first Metal command queue, and Metal's one-time process setup
/// (failure-mode init, ~350 ms) ran while the main thread waited on that layer's backing store.
/// One command queue made on a background thread after launch pays that setup off the main thread.
enum MetalPrewarm {
    private static let once: Void = {
        Task.detached(priority: .utility) {
            _ = MTLCreateSystemDefaultDevice()?.makeCommandQueue()
        }
    }()

    static func run() { _ = once }
}
