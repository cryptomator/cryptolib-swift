//
//  CryptorTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Sebastian Stenzel on 27.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import XCTest
@testable import CryptomatorCryptoLib

class CryptorTests: XCTestCase {
	var cryptor: Cryptor!
	var tmpDirURL: URL!

	override func setUpWithError() throws {
		let aesKey = [UInt8](repeating: 0x55, count: 32)
		let macKey = [UInt8](repeating: 0x77, count: 32)
		let masterkey = Masterkey.createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey)
		let cryptoSupport = CryptoSupportMock()
		let contentCryptor = CtrThenHmacContentCryptor(macKey: macKey, cryptoSupport: cryptoSupport)
		cryptor = Cryptor(masterkey: masterkey, cryptoSupport: cryptoSupport, contentCryptor: contentCryptor)

		tmpDirURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
		try FileManager.default.createDirectory(at: tmpDirURL, withIntermediateDirectories: true)
	}

	override func tearDownWithError() throws {
		try FileManager.default.removeItem(at: tmpDirURL)
	}

	func testEncryptDirId() throws {
		let rootDir = try cryptor.encryptDirId("".data(using: .utf8)!)
		XCTAssertEqual("VLWEHT553J5DR7OZLRJAYDIWFCXZABOD", rootDir)

		let testDir = try cryptor.encryptDirId("918acfbd-a467-3f77-93f1-f4a44f9cfe9c".data(using: .utf8)!)
		XCTAssertEqual("7C3USOO3VU7IVQRKFMRFV3QE4VEZJECV", testDir)
	}

	func testEncryptAndDecryptName() throws {
		let dirId = "foo".data(using: .utf8)!
		let originalName = "hello.txt"

		let ciphertextName = try cryptor.encryptFileName(originalName, dirId: dirId)
		XCTAssertNotNil(ciphertextName)

		let cleartextName = try cryptor.decryptFileName(ciphertextName, dirId: dirId)
		XCTAssertNotNil(cleartextName)
		XCTAssertEqual(originalName, cleartextName)
	}

	func testDecryptInvalidName() throws {
		let dirId = "foo".data(using: .utf8)!
		XCTAssertThrowsError(try cryptor.decryptFileName("****", dirId: dirId), "invalid ciphertext name encoding") { error in
			XCTAssertEqual(.invalidParameter("Can't base64url-decode ciphertext name: ****"), error as? CryptoError)
		}
		XCTAssertThrowsError(try cryptor.decryptFileName("test", dirId: dirId), "invalid ciphertext name count") { error in
			XCTAssertEqual(.invalidParameter("ciphertext must be at least 16 bytes"), error as? CryptoError)
		}
	}

	func testCreateHeader() throws {
		let header = try cryptor.createHeader()
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 16), header.nonce)
		XCTAssertEqual([UInt8](repeating: 0xF0, count: 32), header.contentKey)
	}

	func testEncryptHeader() throws {
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
		let originalData = Data(repeating: 0x0F, count: 65 * 1024)
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try originalData.write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let overallProgress = Progress(totalUnitCount: 2)
		let progressObserver = overallProgress.observe(\.fractionCompleted) { progress, _ in
			print("\(progress.localizedDescription ?? "") (\(progress.localizedAdditionalDescription ?? ""))")
		}
		overallProgress.becomeCurrent(withPendingUnitCount: 1)
		try cryptor.encryptContent(from: originalURL, to: ciphertextURL)
		overallProgress.resignCurrent()
		overallProgress.becomeCurrent(withPendingUnitCount: 1)
		try cryptor.decryptContent(from: ciphertextURL, to: cleartextURL)
		overallProgress.resignCurrent()
		progressObserver.invalidate()
		XCTAssertTrue(overallProgress.completedUnitCount >= overallProgress.totalUnitCount)

		let cleartextData = try Data(contentsOf: cleartextURL)
		XCTAssertEqual(originalData, cleartextData)
	}

	func testEncryptAndDecryptSingleChunk() throws {
		let nonce = [UInt8](repeating: 0x00, count: 16)
		let filekey = [UInt8](repeating: 0x00, count: 32)
		let cleartext = [UInt8]("hello world".data(using: .ascii)!)

		let encrypted = try cryptor.encryptSingleChunk(cleartext, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)
		let decrypted = try cryptor.decryptSingleChunk(encrypted, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)

		XCTAssertEqual(cleartext, decrypted)
	}

	func testCalculateCiphertextSize() {
		XCTAssertEqual(0, cryptor.calculateCiphertextSize(0))

		XCTAssertEqual(1 + 48, cryptor.calculateCiphertextSize(1))
		XCTAssertEqual(32 * 1024 - 1 + 48, cryptor.calculateCiphertextSize(32 * 1024 - 1))
		XCTAssertEqual(32 * 1024 + 48, cryptor.calculateCiphertextSize(32 * 1024))

		XCTAssertEqual(32 * 1024 + 1 + 48 * 2, cryptor.calculateCiphertextSize(32 * 1024 + 1))
		XCTAssertEqual(32 * 1024 + 2 + 48 * 2, cryptor.calculateCiphertextSize(32 * 1024 + 2))
		XCTAssertEqual(64 * 1024 - 1 + 48 * 2, cryptor.calculateCiphertextSize(64 * 1024 - 1))
		XCTAssertEqual(64 * 1024 + 48 * 2, cryptor.calculateCiphertextSize(64 * 1024))

		XCTAssertEqual(64 * 1024 + 1 + 48 * 3, cryptor.calculateCiphertextSize(64 * 1024 + 1))
	}

	func testCalculateCleartextSize() throws {
		XCTAssertEqual(0, try cryptor.calculateCleartextSize(0))

		XCTAssertEqual(1, try cryptor.calculateCleartextSize(1 + 48))
		XCTAssertEqual(32 * 1024 - 1, try cryptor.calculateCleartextSize(32 * 1024 - 1 + 48))
		XCTAssertEqual(32 * 1024, try cryptor.calculateCleartextSize(32 * 1024 + 48))

		XCTAssertEqual(32 * 1024 + 1, try cryptor.calculateCleartextSize(32 * 1024 + 1 + 48 * 2))
		XCTAssertEqual(32 * 1024 + 2, try cryptor.calculateCleartextSize(32 * 1024 + 2 + 48 * 2))
		XCTAssertEqual(64 * 1024 - 1, try cryptor.calculateCleartextSize(64 * 1024 - 1 + 48 * 2))
		XCTAssertEqual(64 * 1024, try cryptor.calculateCleartextSize(64 * 1024 + 48 * 2))

		XCTAssertEqual(64 * 1024 + 1, try cryptor.calculateCleartextSize(64 * 1024 + 1 + 48 * 3))
	}

	func testCalculateCleartextSizeWithInvalidCiphertextSize() throws {
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(1), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value 1"), error as? CryptoError)
		}
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(48), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value 48"), error as? CryptoError)
		}
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(32 * 1024 + 1 + 48), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value 32817"), error as? CryptoError)
		}
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(32 * 1024 + 48 * 2), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value 32864"), error as? CryptoError)
		}
	}
}
