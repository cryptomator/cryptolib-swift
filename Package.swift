// swift-tools-version:5.1

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
		.iOS(.v9),
		.macOS(.v10_12)
	],
	products: [
		.library(name: "CryptomatorCryptoLib", targets: ["CryptomatorCryptoLib"])
	],
	dependencies: [
		.package(url: "https://github.com/norio-nomura/Base32.git", .upToNextMinor(from: "0.8.0"))
	],
	targets: [
		.target(name: "CryptomatorCryptoLib", dependencies: ["Base32", "scrypt"]),
		.target(name: "scrypt"),
		.testTarget(name: "CryptomatorCryptoLibTests", dependencies: ["CryptomatorCryptoLib"])
	],
	swiftLanguageVersions: [.v5]
)
