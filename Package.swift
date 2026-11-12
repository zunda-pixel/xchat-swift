// swift-tools-version:6.4
import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InternalImportsByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ImmutableWeakCaptures"),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .defaultIsolation(nil),
    .strictMemorySafety(),
    .treatAllWarnings(as: .error),
]

let package = Package(
    name: "XChat",
    platforms: [.macOS(.v27), .iOS(.v27)],
    products: [
        .library(name: "XChat", targets: ["XChat"]),
        .library(name: "Juicebox", targets: ["Juicebox"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.10.0"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-algorithms.git", from: "1.2.0"),
    ],
    targets: [
        .target(
            name: "XChat",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "Algorithms", package: "swift-algorithms"),
            ],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "Juicebox",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "XChatTests",
            dependencies: ["XChat"],
            resources: [.copy("Fixtures/sdk_vectors.json")],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JuiceboxTests",
            dependencies: ["Juicebox"],
            resources: [.copy("Fixtures/noise_nk_vectors.json")],
            swiftSettings: swiftSettings
        ),
    ],
    swiftLanguageModes: [.v6]
)
