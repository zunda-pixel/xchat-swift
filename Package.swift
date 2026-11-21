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
  platforms: [
    .macOS(.v15),
    .iOS(.v18),
    .tvOS(.v18),
    .macCatalyst(.v18),
    .visionOS(.v2),
    .watchOS(.v11),
  ],
  products: [
    .library(name: "XChat", targets: ["XChat"])
  ],
  dependencies: [
    .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0"),
    .package(url: "https://github.com/apple/swift-crypto.git", from: "5.1.1"),
    .package(url: "https://github.com/apple/swift-collections.git", from: "1.7.6"),
    .package(url: "https://github.com/apple/swift-algorithms.git", from: "1.2.1"),
  ],
  targets: [
    .target(
      name: "XChat",
      dependencies: [
        .product(name: "Clibsodium", package: "swift-sodium"),
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "Collections", package: "swift-collections"),
        .product(name: "Algorithms", package: "swift-algorithms"),
      ],
      swiftSettings: swiftSettings
    ),
    .testTarget(
      name: "XChatTests",
      dependencies: ["XChat"],
      resources: [.copy("Fixtures/sdk_vectors.json")],
      swiftSettings: swiftSettings
    ),
  ],
  swiftLanguageModes: [.v6]
)
