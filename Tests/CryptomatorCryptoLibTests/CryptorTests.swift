//
//  CryptorTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Sebastian Stenzel on 27.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CryptoKit
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
		let rootDir = try cryptor.encryptDirId(Data("".utf8))
		XCTAssertEqual("VLWEHT553J5DR7OZLRJAYDIWFCXZABOD", rootDir)

		let testDir = try cryptor.encryptDirId(Data("918acfbd-a467-3f77-93f1-f4a44f9cfe9c".utf8))
		XCTAssertEqual("7C3USOO3VU7IVQRKFMRFV3QE4VEZJECV", testDir)
	}

	func testEncryptAndDecryptName() throws {
		let dirId = Data("foo".utf8)
		let originalName = "hello.txt"

		let ciphertextName = try cryptor.encryptFileName(originalName, dirId: dirId)
		XCTAssertNotNil(ciphertextName)

		let cleartextName = try cryptor.decryptFileName(ciphertextName, dirId: dirId)
		XCTAssertNotNil(cleartextName)
		XCTAssertEqual(originalName, cleartextName)
	}

	func testDecryptInvalidName() throws {
		let dirId = Data("foo".utf8)
		XCTAssertThrowsError(try cryptor.decryptFileName("****", dirId: dirId), "invalid ciphertext name encoding") { error in
			XCTAssertEqual(.invalidParameter("Can't base64url-decode ciphertext name: ****"), error as? CryptoError)
		}
		XCTAssertThrowsError(try cryptor.decryptFileName("test", dirId: dirId), "invalid ciphertext name count") { error in
			XCTAssertEqual(.invalidParameter("ciphertext must be at least 16 bytes"), error as? CryptoError)
		}
	}

	func testEncryptAndDecryptContent() async throws {
		let originalData = Data(repeating: 0x0F, count: 65 * 1024)
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try originalData.write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL, progress: encryptProgress)
		XCTAssertEqual(Int64(cryptor.calculateCiphertextSize(65 * 1024)), encryptProgress.totalUnitCount)
		XCTAssertEqual(encryptProgress.totalUnitCount, encryptProgress.completedUnitCount)

		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: decryptProgress)
		XCTAssertEqual(65 * 1024, decryptProgress.totalUnitCount)
		XCTAssertEqual(decryptProgress.totalUnitCount, decryptProgress.completedUnitCount)

		let cleartextData = try Data(contentsOf: cleartextURL)
		XCTAssertEqual(originalData, cleartextData)
	}

	func assertEncryptContentMatchesFixture(expectedSize: Int, expectedSHA256: String) async throws {
		let originalData = Data(makeCleartext(count: 70000))
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try originalData.write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL)
		let ciphertextData = try Data(contentsOf: ciphertextURL)
		XCTAssertEqual(expectedSize, ciphertextData.count)
		XCTAssertEqual(expectedSHA256, SHA256.hash(data: ciphertextData).map { String(format: "%02x", $0) }.joined())

		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL)
		XCTAssertEqual(originalData, try Data(contentsOf: cleartextURL))
	}

	func testEmptyFileCompletesProgress() async throws {
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data().write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL, progress: encryptProgress)
		XCTAssertEqual(1, encryptProgress.totalUnitCount)
		XCTAssertEqual(1, encryptProgress.completedUnitCount)

		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: decryptProgress)
		XCTAssertEqual(1, decryptProgress.totalUnitCount)
		XCTAssertEqual(1, decryptProgress.completedUnitCount)
		XCTAssertEqual(Data(), try Data(contentsOf: cleartextURL))
	}

	func testUnknownSizeCompletesProgress() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let cleartext = makeCleartext(count: 40000)
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let result = await runInFreshTask(input: cleartext) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: nil, progress: progress)
		}
		XCTAssertNil(result.error)
		XCTAssertEqual(Int64(result.output.count - cryptor.fileHeaderSize), progress.totalUnitCount)
		XCTAssertEqual(progress.totalUnitCount, progress.completedUnitCount)
	}

	func testPreCancelledTaskLeavesOutputUntouched() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data(makeCleartext(count: 100)).write(to: originalURL)
		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL)
		let existingData = Data("existing".utf8)

		let encryptOutputURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try existingData.write(to: encryptOutputURL)
		let encryptProgress = Progress.discreteProgress(totalUnitCount: 1)
		encryptProgress.completedUnitCount = 1
		XCTAssertTrue(encryptProgress.isFinished)
		let encryptError = await errorInPreCancelledTask {
			try await cryptor.encryptContent(from: originalURL, to: encryptOutputURL, progress: encryptProgress)
		}
		XCTAssertTrue(encryptError is CancellationError)
		XCTAssertEqual(existingData, try Data(contentsOf: encryptOutputURL))
		XCTAssertFalse(encryptProgress.isFinished)

		let decryptOutputURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try existingData.write(to: decryptOutputURL)
		let decryptProgress = Progress.discreteProgress(totalUnitCount: 1)
		decryptProgress.completedUnitCount = 1
		XCTAssertTrue(decryptProgress.isFinished)
		let decryptError = await errorInPreCancelledTask {
			try await cryptor.decryptContent(from: ciphertextURL, to: decryptOutputURL, progress: decryptProgress)
		}
		XCTAssertTrue(decryptError is CancellationError)
		XCTAssertEqual(existingData, try Data(contentsOf: decryptOutputURL))
		XCTAssertFalse(decryptProgress.isFinished)
	}

	func testCancellationBetweenChunks() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let cleartext = makeCleartext(count: 3 * cryptor.cleartextChunkSize)
		let ciphertext = await runInFreshTask(input: cleartext) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output

		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let encryptResult = await runInFreshTask(input: cleartext, cancellingReadIndex: 1) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: encryptProgress)
		}
		XCTAssertTrue(encryptResult.error is CancellationError)
		XCTAssertEqual(cryptor.fileHeaderSize + cryptor.ciphertextChunkSize, encryptResult.output.count)
		XCTAssertFalse(encryptProgress.isFinished)

		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let decryptResult = await runInFreshTask(input: ciphertext, cancellingReadIndex: 2) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: decryptProgress)
		}
		XCTAssertTrue(decryptResult.error is CancellationError)
		XCTAssertEqual(cryptor.cleartextChunkSize, decryptResult.output.count)
		XCTAssertFalse(decryptProgress.isFinished)
	}

	func testCancellationDuringEndOfFileReadStillSucceeds() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let cleartext = makeCleartext(count: 2 * cryptor.cleartextChunkSize)
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let result = await runInFreshTask(input: cleartext, cancellingReadIndex: 2) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: progress)
		}
		XCTAssertNil(result.error)
		XCTAssertEqual(cryptor.fileHeaderSize + 2 * cryptor.ciphertextChunkSize, result.output.count)
		XCTAssertTrue(progress.isFinished)
	}

	func testInputStreamErrorThrows() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let cleartext = makeCleartext(count: 100)
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let result = await runInFreshTask(input: cleartext, failingReadIndex: 0) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: progress)
		}
		XCTAssertNotNil(result.error)
		XCTAssertLessThanOrEqual(result.output.count, cryptor.fileHeaderSize)
		XCTAssertFalse(progress.isFinished)
	}

	func testInputErrorAfterLastChunkLeavesProgressIncomplete() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let cleartext = makeCleartext(count: 2 * cryptor.cleartextChunkSize)
		let ciphertext = await runInFreshTask(input: cleartext) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output

		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let encryptResult = await runInFreshTask(input: cleartext, failingReadIndex: 2) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: encryptProgress)
		}
		XCTAssertNotNil(encryptResult.error)
		XCTAssertLessThan(encryptProgress.completedUnitCount, encryptProgress.totalUnitCount)

		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let decryptResult = await runInFreshTask(input: ciphertext, failingReadIndex: 3) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: decryptProgress)
		}
		XCTAssertNotNil(decryptResult.error)
		XCTAssertLessThan(decryptProgress.completedUnitCount, decryptProgress.totalUnitCount)
	}

	func testDecryptToUnopenableOutputThrows() async throws {
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data().write(to: originalURL)
		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL)

		let cleartextURL = tmpDirURL.appendingPathComponent("missing", isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: false)
		let progress = Progress.discreteProgress(totalUnitCount: 1)
		progress.completedUnitCount = 1
		XCTAssertTrue(progress.isFinished)
		do {
			try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: progress)
			XCTFail("Expected an error")
		} catch {}
		XCTAssertFalse(FileManager.default.fileExists(atPath: cleartextURL.path))
		XCTAssertFalse(progress.isFinished)
	}

	func testWriteFailureThrows() async throws {
		let cleartext = makeCleartext(count: cryptor.cleartextChunkSize)
		let capacity = cryptor.fileHeaderSize + cryptor.ciphertextChunkSize - 1
		let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
		defer { buffer.deallocate() }
		let cleartextStream = InputStream(data: Data(cleartext))
		let ciphertextStream = OutputStream(toBuffer: buffer, capacity: capacity)
		cleartextStream.open()
		ciphertextStream.open()
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		do {
			try await cryptor.encryptContent(from: cleartextStream, to: ciphertextStream, cleartextSize: cleartext.count, progress: progress)
			XCTFail("Expected an error")
		} catch {}
		XCTAssertFalse(progress.isFinished)
	}

	func testShortReadsKeepChunkBoundaries() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let cleartext = makeCleartext(count: 65 * 1024)
		let ciphertext = await runInFreshTask(input: cleartext, maxReadLength: 1000) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output
		XCTAssertEqual(cryptor.fileHeaderSize + cryptor.calculateCiphertextSize(cleartext.count), ciphertext.count)

		let decrypted = await runInFreshTask(input: ciphertext) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: nil)
		}
		XCTAssertNil(decrypted.error)
		XCTAssertEqual(cleartext, decrypted.output)

		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let shortReadDecrypted = await runInFreshTask(input: ciphertext, maxReadLength: 10) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: progress)
		}
		XCTAssertNil(shortReadDecrypted.error)
		XCTAssertEqual(cleartext, shortReadDecrypted.output)
		XCTAssertTrue(progress.isFinished)
	}

	func testShortWritesKeepOutputComplete() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let cleartext = makeCleartext(count: 65 * 1024)
		let ciphertext = await runInFreshTask(input: cleartext, maxWriteLength: 1000) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output
		XCTAssertEqual(cryptor.fileHeaderSize + cryptor.calculateCiphertextSize(cleartext.count), ciphertext.count)

		let decrypted = await runInFreshTask(input: ciphertext, maxWriteLength: 1000) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: nil)
		}
		XCTAssertNil(decrypted.error)
		XCTAssertEqual(cleartext, decrypted.output)
	}

	func testDecryptTruncatedHeaderThrows() async throws {
		for size in [0, 1, cryptor.fileHeaderSize - 1] {
			let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
			try Data(repeating: 0x00, count: size).write(to: ciphertextURL)
			let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
			let progress = Progress.discreteProgress(totalUnitCount: 0)
			do {
				try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: progress)
				XCTFail("Expected an error for ciphertext size \(size)")
			} catch {
				XCTAssertEqual(.unauthenticCiphertext, error as? CryptoError)
			}
			XCTAssertFalse(progress.isFinished)
		}
	}

	func testDecryptTruncatedChunkThrows() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let header = try cryptor.encryptHeader(cryptor.createHeader())
		let ciphertext = header + [UInt8](repeating: 0x00, count: contentCryptor.nonceLen + contentCryptor.tagLen - 1)
		let result = await runInFreshTask(input: ciphertext) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: nil)
		}
		XCTAssertEqual(.unauthenticCiphertext, result.error as? CryptoError)
	}

	func testConcurrentRoundTrips() async throws {
		let cryptor = try XCTUnwrap(cryptor)
		let tmpDirURL = try XCTUnwrap(tmpDirURL)
		try await withThrowingTaskGroup(of: Void.self) { group in
			for i in 0 ..< 8 {
				group.addTask {
					let originalData = Data((0 ..< 1024 * 1024).map { UInt8(($0 + i) % 251) })
					let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
					try originalData.write(to: originalURL)
					let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
					let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
					try await cryptor.encryptContent(from: originalURL, to: ciphertextURL)
					try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL)
					XCTAssertEqual(originalData, try Data(contentsOf: cleartextURL))
				}
			}
			try await group.waitForAll()
		}
	}

	func testEncryptAndDecryptSingleChunk() throws {
		let nonce = [UInt8](repeating: 0x00, count: contentCryptor.nonceLen)
		let filekey = [UInt8](repeating: 0x00, count: 32)
		let cleartext = [UInt8]("hello world".utf8)

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

	// MARK: - Helpers

	func makeCleartext(count: Int) -> [UInt8] {
		return (0 ..< count).map { UInt8($0 % 251) }
	}

	/// Runs `operation` in a fresh `Task`, so that cancelling it does not cancel the test itself.
	func runInFreshTask(input: [UInt8], maxReadLength: Int = .max, failingReadIndex: Int? = nil, cancellingReadIndex: Int? = nil, maxWriteLength: Int = .max, operation: @escaping @Sendable (InputStream, OutputStream) async throws -> Void) async -> (error: Error?, output: [UInt8]) {
		return await Task {
			let inputStream = ScriptedInputStream(bytes: input, maxReadLength: maxReadLength, failingReadIndex: failingReadIndex) { readIndex in
				if readIndex == cancellingReadIndex {
					withUnsafeCurrentTask { $0?.cancel() }
				}
			}
			let outputStream = ScriptedOutputStream(maxWriteLength: maxWriteLength)
			inputStream.open()
			outputStream.open()
			var error: Error?
			do {
				try await operation(inputStream, outputStream)
			} catch let operationError {
				error = operationError
			}
			return (error, outputStream.bytes)
		}.value
	}

	func errorInPreCancelledTask(_ operation: @escaping @Sendable () async throws -> Void) async -> Error? {
		return await Task {
			withUnsafeCurrentTask { $0?.cancel() }
			do {
				try await operation()
				return nil
			} catch {
				return error
			}
		}.value
	}
}
