import Foundation

/// SEC-03: logins remembered for this run, each with the time of its last successful sign-in.
/// Every read asks the core's rule (`rememberedLoginUsable`) with the minutes in force
/// (`sessionLoginReuseMinutes`: user setting and managed maximum, the smaller non-zero one).
/// A login past its time is forgotten on that read, so the caller resolves logins again.
/// Pure Swift (no core import) so `tests/login-reuse` can compile it alone.
struct RememberedLoginStore<Login> {
    /// The core's rule: (remembered at, now, minutes) -> usable.
    let usable: (UInt64, UInt64, UInt32) -> Bool
    /// Seconds on a monotonic clock that keeps counting during sleep.
    let now: () -> UInt64

    private var entries: [String: (login: Login, at: UInt64)] = [:]

    init(usable: @escaping (UInt64, UInt64, UInt32) -> Bool, now: @escaping () -> UInt64 = monotonicSeconds) {
        self.usable = usable
        self.now = now
    }

    /// After a successful sign-in with `login`: (re)starts its time.
    mutating func remember(_ login: Login, for id: String) { entries[id] = (login, now()) }

    /// The remembered login while the rule allows it under `minutes` (read by the caller on every
    /// use, so a changed setting or policy applies at once); otherwise forgets it and returns nil.
    mutating func login(for id: String, minutes: UInt32) -> Login? {
        guard let entry = entries[id] else { return nil }
        if usable(entry.at, now(), minutes) { return entry.login }
        entries[id] = nil
        return nil
    }

    mutating func forget(_ id: String) { entries[id] = nil }
    mutating func forgetAll() { entries = [:] }
}

/// `CLOCK_MONOTONIC` on Darwin counts during sleep and ignores wall-clock changes.
func monotonicSeconds() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1_000_000_000 }
