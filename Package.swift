// swift-tools-version:5.0

//
//  Package.swift
//  CryptomatorCryptoLib
//
//  Created by Philipp Schmid on 24.09.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import PackageDescription

let package = Package(
	name: "CryptomatorCryptoLib",
	platforms: [
		.iOS(.v9)
	],
	products: [
		.library(name: "CryptomatorCryptoLib", targets: ["CryptomatorCryptoLib"])
	],
	dependencies: [
		.package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.3.0")),
		.package(url: "https://github.com/cryptomator/Base32.git", .upToNextMinor(from: "0.8.0"))
	],
	targets: [
		.target(name: "CryptomatorCryptoLib", dependencies: ["CryptoSwift", "SwiftBase32"]),
		.testTarget(name: "CryptomatorCryptoLibTests", dependencies: ["CryptomatorCryptoLib"])
	],
	swiftLanguageVersions: [.v5]
)
