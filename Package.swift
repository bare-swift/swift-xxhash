// swift-tools-version: 6.0
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Copyright (c) 2026 The bare-swift Project Authors.

import PackageDescription

let package = Package(
    name: "swift-xxhash",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "XXHash", targets: ["XXHash"])
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.4.0")
    ],
    targets: [
        .target(name: "XXHash"),
        .testTarget(
            name: "XXHashTests",
            dependencies: ["XXHash"],
            resources: [.copy("../Vectors")]
        )
    ]
)
