// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "portname-macos",
    defaultLocalization: "de",
    platforms: [
        .macOS(.v14)
    ],
    targets: [
        .target(
            name: "PortnameCore",
            path: "Sources/PortnameCore",
            resources: [
                .process("Resources")
            ]
        ),
        .executableTarget(
            name: "Portname",
            dependencies: ["PortnameCore"],
            path: "Sources/PortnameApp"
        ),
        .testTarget(
            name: "PortnameCoreTests",
            dependencies: ["PortnameCore"],
            path: "Tests/PortnameCoreTests"
        ),
    ]
)
