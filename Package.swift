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
        .library(
            name: "MiddlewareTesting",
            targets: ["MiddlewareTesting"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird", from: "2.0.0"),
        // jose-swift 6.0.5 把 secp256k1.swift 的版本範圍放寬成 `from: "0.23.0"`（等於 0.23.0..<1.0.0），
        // 會解析到 0.25.0（2026-11-10）；0.25.0 起 SymmetricKey 不再有 `.bytes`，jose-swift 編不過。
        // 6.0.4 以前鎖在 secp256k1.swift 0.15.x，不受影響。jose-swift 修正版本範圍後拿掉上限。
        // 若 jose-swift 沒有持續維護，改 fork 自行維護（直接宣告 jose-swift 的專案要一起換成 fork 的網址）。
        .package(url: "https://github.com/beatt83/jose-swift.git", "6.0.0"..<"6.0.5"),
        .package(url: "https://github.com/apple/swift-openapi-runtime", from: "1.0.0"),
        // Only MiddlewareTesting uses this (for `_CryptoExtras` RSA keys). The range spans 3.x, for packages
        // still on 3.x, and 4.x, because NotificationContext resolves swift-crypto 4.5.2.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "Middleware",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "jose-swift", package: "jose-swift"),
                .product(name: "OpenAPIRuntime", package: "swift-openapi-runtime"),
            ]
        ),
        // Test signer for application tokens; lets services (and this package) mint tokens without OIDCContext.
        .target(
            name: "MiddlewareTesting",
            dependencies: [
                "Middleware",
                .product(name: "jose-swift", package: "jose-swift"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "MiddlewareTests",
            dependencies: [
                "Middleware",
                "MiddlewareTesting",
                .product(name: "HummingbirdTesting", package: "hummingbird"),
                .product(name: "jose-swift", package: "jose-swift"),
            ]
        ),
    ]
)
