// swift-tools-version:5.0

//
//  Package.swift
//  CryptoLib
//
//  Created by Philipp Schmid on 24.09.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import PackageDescription

let package = Package(
	name: "CryptoLib",
	platforms: [
		.iOS(.v9)
	],
	products: [
		.library(name: "CryptoLib", targets: ["CryptoLib"])
	],
	dependencies: [
		.package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.3.0")),
		.package(url: "https://github.com/norio-nomura/Base32.git", .upToNextMinor(from: "0.8.0"))
	],
	targets: [
		.target(name: "CryptoLib", dependencies: ["CryptoSwift", "Base32"], path: "CryptoLib"),
		.testTarget(name: "CryptoLibTests", dependencies: ["CryptoLib"], path: "CryptoLibTests")
	],
	swiftLanguageVersions: [.v5]
)
