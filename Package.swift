// swift-tools-version:6.2

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
		.iOS(.v13),
		.macOS(.v10_15)
	],
	products: [
		.library(name: "CryptomatorCryptoLib", targets: ["CryptomatorCryptoLib"])
	],
	dependencies: [
		.package(url: "https://github.com/norio-nomura/Base32.git", .upToNextMinor(from: "0.9.0"))
	],
	targets: [
		.target(name: "CryptomatorCryptoLib", dependencies: ["Base32", "scrypt"], exclude: ["Info.plist"]),
		.target(name: "scrypt"),
		.testTarget(name: "CryptomatorCryptoLibTests", dependencies: ["CryptomatorCryptoLib"], exclude: ["Info.plist"])
	],
	swiftLanguageModes: [.v6]
)
