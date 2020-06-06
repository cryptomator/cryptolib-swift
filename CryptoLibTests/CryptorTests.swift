//
//  CryptorTests.swift
//  CryptoLibTests
//
//  Created by Sebastian Stenzel on 27.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import XCTest
@testable import CryptoLib

class CryptorTests: XCTestCase {
	var masterkey: Masterkey!

	override func setUp() {
		let aesKey: [UInt8] = Array(repeating: 0x55, count: 32)
		let macKey: [UInt8] = Array(repeating: 0x77, count: 32)
		masterkey = Masterkey.createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey, version: 7)

		XCTAssertNotNil(masterkey)
	}

	func testEncryptDirId() throws {
		let cryptor = Cryptor(masterKey: masterkey)

		let rootDir = try cryptor.encryptDirId("".data(using: .utf8)!)
		XCTAssertEqual("VLWEHT553J5DR7OZLRJAYDIWFCXZABOD", rootDir)

		let testDir = try cryptor.encryptDirId("918acfbd-a467-3f77-93f1-f4a44f9cfe9c".data(using: .utf8)!)
		XCTAssertEqual("7C3USOO3VU7IVQRKFMRFV3QE4VEZJECV", testDir)
	}

	func testEncryptAndDecryptName() throws {
		continueAfterFailure = false

		let cryptor = Cryptor(masterKey: masterkey)
		let dirId = "foo".data(using: .utf8)!
		let originalName = "hello.txt"

		let ciphertextName = try cryptor.encryptFileName(originalName, dirId: dirId)
		XCTAssertNotNil(ciphertextName)

		let cleartextName = try cryptor.decryptFileName(ciphertextName, dirId: dirId)
		XCTAssertNotNil(cleartextName)
		XCTAssertEqual(originalName, cleartextName)
	}

	func testEncryptAndDecryptSingleChunk() throws {
		let cryptor = Cryptor(masterKey: masterkey)
		let nonce = [UInt8](repeating: 0x00, count: 16)
		let filekey = [UInt8](repeating: 0x00, count: 32)
		let cleartext = "hello world".data(using: .ascii)!

		let encrypted = try cryptor.encryptSingleChunk(cleartext.bytes, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)
		let decrypted = try cryptor.decryptSingleChunk(encrypted, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)

		XCTAssertEqual(cleartext.bytes, decrypted)
	}
}
