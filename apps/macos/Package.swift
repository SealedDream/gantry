// swift-tools-version:6.0
import Foundation
import PackageDescription

// Run ./build-core.sh and ./build-rdp.sh first: they produce Generated/ (XCFramework, the RDP dylib
// and the UniFFI Swift bindings for both).
let rdpLib = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Generated/rdp/lib").path

// MAC-MODERN-UI: SwiftPM's build system links through clang with --sysroot only, so clang cannot
// read the SDK's version and writes the deployment target (14.0) as the SDK in LC_BUILD_VERSION.
// AppKit then treats the app as built for macOS 14 and draws the old, pre-Liquid Glass controls.
// Passing -isysroot to the link step records the real SDK version. The path comes from xcrun.
let sdkPath: String? = {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    p.arguments = ["--sdk", "macosx", "--show-sdk-path"]
    let out = Pipe()
    p.standardOutput = out
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return nil }
    p.waitUntilExit()
    let path = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    return p.terminationStatus == 0 && !path.isEmpty ? path : nil
}()
let sdkVersionLink: [LinkerSetting] = sdkPath.map { [.unsafeFlags(["-Xclang-linker", "-isysroot", "-Xclang-linker", $0])] } ?? []

let package = Package(
    name: "Bastion",
    platforms: [.macOS(.v14)],
    targets: [
        .binaryTarget(name: "BastionFFI", path: "Generated/BastionFFI.xcframework"),
        .target(
            name: "BastionCore",
            dependencies: ["BastionFFI"],
            path: "Generated/swift",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration"), .linkedFramework("IOKit"), .linkedLibrary("iconv")]
        ),
        // bastion-rdp is a dylib (IronRDP cannot share a Cargo graph with russh). It is found through the
        // rpath: next to the binary, in a bundle's Contents/Frameworks, or in Generated/ during development.
        .systemLibrary(name: "BastionRdpFFI", path: "Generated/rdp/module"),
        .target(
            name: "BastionRdp",
            dependencies: ["BastionRdpFFI"],
            path: "Generated/rdp/swift",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [.unsafeFlags(["-L\(rdpLib)", "-lbastion_rdp",
                                           "-Xlinker", "-rpath", "-Xlinker", "@executable_path",
                                           "-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks",
                                           "-Xlinker", "-rpath", "-Xlinker", rdpLib])]
        ),
        .executableTarget(name: "Bastion", dependencies: ["BastionCore", "BastionRdp"], path: "Sources/Bastion",
                         linkerSettings: sdkVersionLink),
    ]
)
