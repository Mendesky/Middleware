// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Middleware",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "Middleware",
            targets: ["Middleware"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird", from: "2.0.0"),
        .package(url: "https://github.com/beatt83/jose-swift.git", from: "6.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "Middleware",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "jose-swift", package: "jose-swift")
            ]
        ),
        .testTarget(
            name: "MiddlewareTests",
            dependencies: ["Middleware"]
        ),
    ]
)
