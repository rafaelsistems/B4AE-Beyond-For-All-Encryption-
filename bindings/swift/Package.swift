// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "B4AE",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [
        .library(name: "B4AE", targets: ["B4AE"]),
    ],
    targets: [
        .target(
            name: "B4AE",
            dependencies: [],
            path: "Sources/B4AE",
            linkerSettings: [
                .linkedLibrary("b4ae_ffi", .when(platforms: [.iOS, .macOS])),
                .unsafeFlags(["-L", "../.."], .when(platforms: [.iOS, .macOS])),
            ]
        ),
    ]
)
