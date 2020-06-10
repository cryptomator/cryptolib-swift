//
//  CryptorTests.swift
//  CryptoLibTests
//
//  Created by Sebastian Stenzel on 27.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import XCTest
@testable import CryptoLib

class CryptoSupportMock: CryptoSupport {
	override func createRandomBytes(size: Int) throws -> [UInt8] {
		return [UInt8](repeating: 0xF0, count: size)
	}
}

class CryptorTests: XCTestCase {
	var masterkey: Masterkey!

	override func setUp() {
		let aesKey: [UInt8] = Array(repeating: 0x55, count: 32)
		let macKey: [UInt8] = Array(repeating: 0x77, count: 32)
		masterkey = Masterkey.createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey, version: 7)

		XCTAssertNotNil(masterkey)
	}

	func testEncryptDirId() throws {
		let cryptor = Cryptor(masterkey: masterkey)

		let rootDir = try cryptor.encryptDirId("".data(using: .utf8)!)
		XCTAssertEqual("VLWEHT553J5DR7OZLRJAYDIWFCXZABOD", rootDir)

		let testDir = try cryptor.encryptDirId("918acfbd-a467-3f77-93f1-f4a44f9cfe9c".data(using: .utf8)!)
		XCTAssertEqual("7C3USOO3VU7IVQRKFMRFV3QE4VEZJECV", testDir)
	}

	func testEncryptAndDecryptName() throws {
		continueAfterFailure = false

		let cryptor = Cryptor(masterkey: masterkey)
		let dirId = "foo".data(using: .utf8)!
		let originalName = "hello.txt"

		let ciphertextName = try cryptor.encryptFileName(originalName, dirId: dirId)
		XCTAssertNotNil(ciphertextName)

		let cleartextName = try cryptor.decryptFileName(ciphertextName, dirId: dirId)
		XCTAssertNotNil(cleartextName)
		XCTAssertEqual(originalName, cleartextName)
	}

	func testCreateHeader() throws {
		let cryptor = Cryptor(masterkey: masterkey, cryptoSupport: CryptoSupportMock())
		let header = try cryptor.createHeader()
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 16), header.nonce)
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 32), header.contentKey)
	}

	func testEncryptHeader() throws {
		let cryptor = Cryptor(masterkey: masterkey, cryptoSupport: CryptoSupportMock())
		let header = try cryptor.createHeader()
		let encrypted = try cryptor.encryptHeader(header)
		let expected: [UInt8] = [
			0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
			0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
			0x0D, 0x91, 0xF2, 0x9C, 0xC6, 0x35, 0xD7, 0x5E,
			0x1E, 0x42, 0x23, 0x1E, 0xC7, 0x90, 0x57, 0xE3,
			0x8D, 0x98, 0xF3, 0x58, 0x07, 0x2C, 0x9F, 0x03,
			0xBC, 0xEA, 0x5A, 0x98, 0x3B, 0x68, 0x62, 0x89,
			0x3E, 0xBC, 0x5E, 0x5E, 0x27, 0x39, 0xCB, 0x8E,
			0xD4, 0x27, 0x61, 0x06, 0x8E, 0x7F, 0x3A, 0x4E,
			0xC7, 0x9F, 0x4D, 0x3E, 0x20, 0x57, 0xDC, 0xE4,
			0x65, 0xA5, 0xFF, 0x93, 0xC2, 0x7B, 0xD2, 0xB8,
			0x3F, 0xE3, 0xD0, 0x8C, 0xB3, 0x92, 0xED, 0x96
		]
		XCTAssertEqual(expected, encrypted)
	}

	func testDecryptHeader() throws {
		let cryptor = Cryptor(masterkey: masterkey, cryptoSupport: CryptoSupportMock())
		let ciphertext: [UInt8] = [
			0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
			0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
			0x0D, 0x91, 0xF2, 0x9C, 0xC6, 0x35, 0xD7, 0x5E,
			0x1E, 0x42, 0x23, 0x1E, 0xC7, 0x90, 0x57, 0xE3,
			0x8D, 0x98, 0xF3, 0x58, 0x07, 0x2C, 0x9F, 0x03,
			0xBC, 0xEA, 0x5A, 0x98, 0x3B, 0x68, 0x62, 0x89,
			0x3E, 0xBC, 0x5E, 0x5E, 0x27, 0x39, 0xCB, 0x8E,
			0xD4, 0x27, 0x61, 0x06, 0x8E, 0x7F, 0x3A, 0x4E,
			0xC7, 0x9F, 0x4D, 0x3E, 0x20, 0x57, 0xDC, 0xE4,
			0x65, 0xA5, 0xFF, 0x93, 0xC2, 0x7B, 0xD2, 0xB8,
			0x3F, 0xE3, 0xD0, 0x8C, 0xB3, 0x92, 0xED, 0x96
		]
		let decrypted = try cryptor.decryptHeader(ciphertext)
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 16), decrypted.nonce)
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 32), decrypted.contentKey)
	}

	func testEncryptAndDecryptContent() throws {
		// TODO:
	}

	func testEncryptAndDecryptSingleChunk() throws {
		let cryptor = Cryptor(masterkey: masterkey)
		let nonce = [UInt8](repeating: 0x00, count: 16)
		let filekey = [UInt8](repeating: 0x00, count: 32)
		let cleartext = "hello world".data(using: .ascii)!

		let encrypted = try cryptor.encryptSingleChunk(cleartext.bytes, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)
		let decrypted = try cryptor.decryptSingleChunk(encrypted, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)

		XCTAssertEqual(cleartext.bytes, decrypted)
	}
}
