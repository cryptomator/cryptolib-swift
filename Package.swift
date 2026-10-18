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
		.iOS(.v15),
		.macOS(.v12)
	],
	products: [
		.library(name: "CryptomatorCryptoLib", targets: ["CryptomatorCryptoLib"])
	],
	targets: [
		.target(name: "CryptomatorCryptoLib", dependencies: ["scrypt"], exclude: ["Info.plist"]),
		.target(name: "scrypt"),
		.testTarget(name: "CryptomatorCryptoLibTests", dependencies: ["CryptomatorCryptoLib"], exclude: ["Info.plist"])
	],
	swiftLanguageModes: [.v6]
)
