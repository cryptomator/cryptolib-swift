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
	var contentCryptor: ContentCryptor!
	var cryptor: Cryptor!
	var tmpDirURL: URL!

	override class var defaultTestSuite: XCTestSuite {
		// Return empty `XCTestSuite` so that no tests from this "abstract" `XCTestCase` is run.
		// Make sure to override this in subclasses so that the implemented test case can run.
		return XCTestSuite(name: "InterfaceTests Excluded")
	}

	func setUpWithError(masterkey: Masterkey, cryptoSupport: CryptoSupport, contentCryptor: ContentCryptor) throws {
		self.contentCryptor = contentCryptor
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
		let nonce = [UInt8](repeating: 0x00, count: contentCryptor.nonceLen)
		let filekey = [UInt8](repeating: 0x00, count: 32)
		let cleartext = [UInt8]("hello world".data(using: .ascii)!)

		let encrypted = try cryptor.encryptSingleChunk(cleartext, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)
		let decrypted = try cryptor.decryptSingleChunk(encrypted, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)

		XCTAssertEqual(cleartext, decrypted)
	}

	func testCalculateCiphertextSize() {
		let overheadPerChunk = contentCryptor.nonceLen + contentCryptor.tagLen

		XCTAssertEqual(0, cryptor.calculateCiphertextSize(0))

		XCTAssertEqual(1 + overheadPerChunk, cryptor.calculateCiphertextSize(1))
		XCTAssertEqual(32 * 1024 - 1 + overheadPerChunk, cryptor.calculateCiphertextSize(32 * 1024 - 1))
		XCTAssertEqual(32 * 1024 + overheadPerChunk, cryptor.calculateCiphertextSize(32 * 1024))

		XCTAssertEqual(32 * 1024 + 1 + overheadPerChunk * 2, cryptor.calculateCiphertextSize(32 * 1024 + 1))
		XCTAssertEqual(32 * 1024 + 2 + overheadPerChunk * 2, cryptor.calculateCiphertextSize(32 * 1024 + 2))
		XCTAssertEqual(64 * 1024 - 1 + overheadPerChunk * 2, cryptor.calculateCiphertextSize(64 * 1024 - 1))
		XCTAssertEqual(64 * 1024 + overheadPerChunk * 2, cryptor.calculateCiphertextSize(64 * 1024))

		XCTAssertEqual(64 * 1024 + 1 + overheadPerChunk * 3, cryptor.calculateCiphertextSize(64 * 1024 + 1))
	}

	func testCalculateCleartextSize() throws {
		let overheadPerChunk = contentCryptor.nonceLen + contentCryptor.tagLen

		XCTAssertEqual(0, try cryptor.calculateCleartextSize(0))

		XCTAssertEqual(1, try cryptor.calculateCleartextSize(1 + overheadPerChunk))
		XCTAssertEqual(32 * 1024 - 1, try cryptor.calculateCleartextSize(32 * 1024 - 1 + overheadPerChunk))
		XCTAssertEqual(32 * 1024, try cryptor.calculateCleartextSize(32 * 1024 + overheadPerChunk))

		XCTAssertEqual(32 * 1024 + 1, try cryptor.calculateCleartextSize(32 * 1024 + 1 + overheadPerChunk * 2))
		XCTAssertEqual(32 * 1024 + 2, try cryptor.calculateCleartextSize(32 * 1024 + 2 + overheadPerChunk * 2))
		XCTAssertEqual(64 * 1024 - 1, try cryptor.calculateCleartextSize(64 * 1024 - 1 + overheadPerChunk * 2))
		XCTAssertEqual(64 * 1024, try cryptor.calculateCleartextSize(64 * 1024 + overheadPerChunk * 2))

		XCTAssertEqual(64 * 1024 + 1, try cryptor.calculateCleartextSize(64 * 1024 + 1 + overheadPerChunk * 3))
	}

	func testCalculateCleartextSizeWithInvalidCiphertextSize() throws {
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(1), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value 1"), error as? CryptoError)
		}

		let emptyPayload = contentCryptor.nonceLen + contentCryptor.tagLen
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(emptyPayload), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value \(emptyPayload)"), error as? CryptoError)
		}

		let oneChunkPlusOneByte = cryptor.ciphertextChunkSize + 1
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(oneChunkPlusOneByte), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value \(oneChunkPlusOneByte)"), error as? CryptoError)
		}

		let oneChunkPlusEmptySecondChunk = cryptor.ciphertextChunkSize + contentCryptor.nonceLen + contentCryptor.tagLen
		XCTAssertThrowsError(try cryptor.calculateCleartextSize(oneChunkPlusEmptySecondChunk), "invalid ciphertext size") { error in
			XCTAssertEqual(.invalidParameter("Method not defined for input value \(oneChunkPlusEmptySecondChunk)"), error as? CryptoError)
		}
	}
}
