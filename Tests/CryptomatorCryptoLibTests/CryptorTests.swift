//
//  CryptorTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Sebastian Stenzel on 27.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CryptoKit
import Foundation
import Testing
@testable import CryptomatorCryptoLib

final class CryptorTests {
	static let schemes: [CryptorScheme] = [.sivGcm, .sivCtrMac]
	static let contentCryptors: [any ContentCryptor] = [GcmContentCryptor(), CtrThenHmacContentCryptor(masterkey: .test)]

	let tmpDirURL: URL

	init() throws {
		self.tmpDirURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
		try FileManager.default.createDirectory(at: tmpDirURL, withIntermediateDirectories: true)
	}

	deinit {
		try? FileManager.default.removeItem(at: tmpDirURL)
	}

	@Test(arguments: schemes) func `encrypt dir id`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let rootDir = try cryptor.encryptDirId(Data("".utf8))
		#expect(rootDir == "VLWEHT553J5DR7OZLRJAYDIWFCXZABOD")

		let testDir = try cryptor.encryptDirId(Data("918acfbd-a467-3f77-93f1-f4a44f9cfe9c".utf8))
		#expect(testDir == "7C3USOO3VU7IVQRKFMRFV3QE4VEZJECV")
	}

	@Test(arguments: schemes) func `encrypt and decrypt name`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let dirId = Data("foo".utf8)
		let originalName = "hello.txt"

		let ciphertextName = try cryptor.encryptFileName(originalName, dirId: dirId)
		#expect(ciphertextName == "GP71XB0uM6ZWwDYeBdhucSXBPpIiDAQz2w==")
		let cleartextName = try cryptor.decryptFileName(ciphertextName, dirId: dirId)
		#expect(originalName == cleartextName)
		let unpaddedCleartextName = try cryptor.decryptFileName("GP71XB0uM6ZWwDYeBdhucSXBPpIiDAQz2w", dirId: dirId)
		#expect(originalName == unpaddedCleartextName)

		let base32CiphertextName = try cryptor.encryptFileName(originalName, dirId: dirId, encoding: .base32)
		#expect(base32CiphertextName == "DD7PKXA5FYZ2MVWAGYPALWDOOES4CPUSEIGAIM63")
		let base32CleartextName = try cryptor.decryptFileName(base32CiphertextName, dirId: dirId, encoding: .base32)
		#expect(originalName == base32CleartextName)
	}

	@Test(arguments: schemes) func `decrypt invalid name`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let dirId = Data("foo".utf8)
		#expect(throws: CryptoError.invalidParameter("Can't base64url-decode ciphertext name: ****")) { try cryptor.decryptFileName("****", dirId: dirId) }
		#expect(throws: CryptoError.invalidParameter("Can't base64url-decode ciphertext name: GP7+XB0uM6ZWwDYeBdhucSXBPpIiDAQz2w==")) { try cryptor.decryptFileName("GP7+XB0uM6ZWwDYeBdhucSXBPpIiDAQz2w==", dirId: dirId) }
		#expect(throws: CryptoError.invalidParameter("ciphertext must be at least 16 bytes")) { try cryptor.decryptFileName("test", dirId: dirId) }

		let ciphertextName = try cryptor.encryptFileName("hello.txt", dirId: dirId)
		#expect(throws: CryptoError.unauthenticCiphertext) { try cryptor.decryptFileName(ciphertextName, dirId: Data("bar".utf8)) }
	}

	@Test(arguments: schemes) func `public initializer creates fresh headers`(scheme: CryptorScheme) throws {
		let cryptor = Cryptor(masterkey: .test, scheme: scheme)
		let first = try cryptor.createHeader()
		let second = try cryptor.createHeader()
		#expect(first.nonce != second.nonce)
		let firstContentKey = first.contentKey.exportBytes()
		let secondContentKey = second.contentKey.exportBytes()
		#expect(firstContentKey != secondContentKey)
	}

	@Test(arguments: schemes) func `encrypt and decrypt content`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let originalData = Data(repeating: 0x0F, count: 65 * 1024)
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try originalData.write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL, progress: encryptProgress)
		#expect(Int64(cryptor.calculateCiphertextSize(65 * 1024)) == encryptProgress.totalUnitCount)
		#expect(encryptProgress.totalUnitCount == encryptProgress.completedUnitCount)

		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: decryptProgress)
		#expect(65 * 1024 == decryptProgress.totalUnitCount)
		#expect(decryptProgress.totalUnitCount == decryptProgress.completedUnitCount)

		let cleartextData = try Data(contentsOf: cleartextURL)
		#expect(originalData == cleartextData)
	}

	@Test(arguments: [
		(CryptorScheme.sivGcm, 70152, "69c5e2f68080d9ecde94c0eb75869808635a0057126d1e46d73521d04a54ee92"),
		(CryptorScheme.sivCtrMac, 70232, "0c22b73f0e99ef06c12db5d56784977921bb69dc477f32b7aea7fc17f3590dbe")
	])
	func `encrypt content matches 110 fixture`(scheme: CryptorScheme, expectedSize: Int, expectedSHA256: String) async throws {
		let cryptor = scheme.makeCryptor()
		let originalData = Data(makeCleartext(count: 70000))
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try originalData.write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL)
		let ciphertextData = try Data(contentsOf: ciphertextURL)
		#expect(expectedSize == ciphertextData.count)
		#expect(expectedSHA256 == SHA256.hash(data: ciphertextData).map { String(format: "%02x", $0) }.joined())

		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL)
		#expect(try originalData == Data(contentsOf: cleartextURL))
	}

	@Test(arguments: schemes) func `empty file completes progress`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data().write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL, progress: encryptProgress)
		#expect(encryptProgress.totalUnitCount == 1)
		#expect(encryptProgress.completedUnitCount == 1)

		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: decryptProgress)
		#expect(decryptProgress.totalUnitCount == 1)
		#expect(decryptProgress.completedUnitCount == 1)
		#expect(try Data() == Data(contentsOf: cleartextURL))
	}

	@Test(arguments: schemes) func `unknown size completes progress`(scheme: CryptorScheme) async {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: 40000)
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let result = await runInFreshTask(input: cleartext) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: nil, progress: progress)
		}
		#expect(result.error == nil)
		#expect(Int64(result.output.count - cryptor.fileHeaderSize) == progress.totalUnitCount)
		#expect(progress.totalUnitCount == progress.completedUnitCount)
	}

	@Test(arguments: schemes) func `pre cancelled task leaves output untouched`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data(makeCleartext(count: 100)).write(to: originalURL)
		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL)
		let existingData = Data("existing".utf8)

		let encryptOutputURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try existingData.write(to: encryptOutputURL)
		let encryptProgress = Progress.discreteProgress(totalUnitCount: 1)
		encryptProgress.completedUnitCount = 1
		#expect(encryptProgress.isFinished)
		let encryptError = await errorInPreCancelledTask {
			try await cryptor.encryptContent(from: originalURL, to: encryptOutputURL, progress: encryptProgress)
		}
		#expect(encryptError is CancellationError)
		#expect(try existingData == Data(contentsOf: encryptOutputURL))
		#expect(!encryptProgress.isFinished)

		let decryptOutputURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try existingData.write(to: decryptOutputURL)
		let decryptProgress = Progress.discreteProgress(totalUnitCount: 1)
		decryptProgress.completedUnitCount = 1
		#expect(decryptProgress.isFinished)
		let decryptError = await errorInPreCancelledTask {
			try await cryptor.decryptContent(from: ciphertextURL, to: decryptOutputURL, progress: decryptProgress)
		}
		#expect(decryptError is CancellationError)
		#expect(try existingData == Data(contentsOf: decryptOutputURL))
		#expect(!decryptProgress.isFinished)
	}

	@Test(arguments: schemes) func `cancellation between chunks`(scheme: CryptorScheme) async {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: 3 * cryptor.cleartextChunkSize)
		let ciphertext = await runInFreshTask(input: cleartext) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output

		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let encryptResult = await runInFreshTask(input: cleartext, cancellingReadIndex: 1) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: encryptProgress)
		}
		#expect(encryptResult.error is CancellationError)
		#expect(cryptor.fileHeaderSize + cryptor.ciphertextChunkSize == encryptResult.output.count)
		#expect(!encryptProgress.isFinished)

		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let decryptResult = await runInFreshTask(input: ciphertext, cancellingReadIndex: 2) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: decryptProgress)
		}
		#expect(decryptResult.error is CancellationError)
		#expect(cryptor.cleartextChunkSize == decryptResult.output.count)
		#expect(!decryptProgress.isFinished)
	}

	@Test(arguments: schemes) func `cancellation during end of file read still succeeds`(scheme: CryptorScheme) async {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: 2 * cryptor.cleartextChunkSize)
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let result = await runInFreshTask(input: cleartext, cancellingReadIndex: 2) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: progress)
		}
		#expect(result.error == nil)
		#expect(cryptor.fileHeaderSize + 2 * cryptor.ciphertextChunkSize == result.output.count)
		#expect(progress.isFinished)
	}

	@Test(arguments: schemes) func `input stream error throws`(scheme: CryptorScheme) async {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: 100)
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let result = await runInFreshTask(input: cleartext, failingReadIndex: 0) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: progress)
		}
		#expect(result.error != nil)
		#expect(result.output.count <= cryptor.fileHeaderSize)
		#expect(!progress.isFinished)
	}

	@Test(arguments: schemes) func `input error after last chunk leaves progress incomplete`(scheme: CryptorScheme) async {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: 2 * cryptor.cleartextChunkSize)
		let ciphertext = await runInFreshTask(input: cleartext) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output

		let encryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let encryptResult = await runInFreshTask(input: cleartext, failingReadIndex: 2) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: encryptProgress)
		}
		#expect(encryptResult.error != nil)
		#expect(encryptProgress.completedUnitCount < encryptProgress.totalUnitCount)

		let decryptProgress = Progress.discreteProgress(totalUnitCount: 0)
		let decryptResult = await runInFreshTask(input: ciphertext, failingReadIndex: 3) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: decryptProgress)
		}
		#expect(decryptResult.error != nil)
		#expect(decryptProgress.completedUnitCount < decryptProgress.totalUnitCount)
	}

	@Test(arguments: schemes) func `decrypt to unopenable output throws`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data().write(to: originalURL)
		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try await cryptor.encryptContent(from: originalURL, to: ciphertextURL)

		let cleartextURL = tmpDirURL.appendingPathComponent("missing", isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: false)
		let progress = Progress.discreteProgress(totalUnitCount: 1)
		progress.completedUnitCount = 1
		#expect(progress.isFinished)
		await #expect(throws: (any Error).self) {
			try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: progress)
		}
		#expect(!FileManager.default.fileExists(atPath: cleartextURL.path))
		#expect(!progress.isFinished)
	}

	@Test(arguments: schemes) func `write failure throws`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: cryptor.cleartextChunkSize)
		let capacity = cryptor.fileHeaderSize + cryptor.ciphertextChunkSize - 1
		let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
		defer { buffer.deallocate() }
		let cleartextStream = InputStream(data: Data(cleartext))
		let ciphertextStream = OutputStream(toBuffer: buffer, capacity: capacity)
		cleartextStream.open()
		ciphertextStream.open()
		let progress = Progress.discreteProgress(totalUnitCount: 0)
		await #expect(throws: (any Error).self) {
			try await cryptor.encryptContent(from: cleartextStream, to: ciphertextStream, cleartextSize: cleartext.count, progress: progress)
		}
		#expect(!progress.isFinished)
	}

	@Test(arguments: schemes) func `short reads keep chunk boundaries`(scheme: CryptorScheme) async {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: 65 * 1024)
		let ciphertext = await runInFreshTask(input: cleartext, maxReadLength: 1000) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output
		#expect(cryptor.fileHeaderSize + cryptor.calculateCiphertextSize(cleartext.count) == ciphertext.count)

		let decrypted = await runInFreshTask(input: ciphertext) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: nil)
		}
		#expect(decrypted.error == nil)
		#expect(cleartext == decrypted.output)

		let progress = Progress.discreteProgress(totalUnitCount: 0)
		let shortReadDecrypted = await runInFreshTask(input: ciphertext, maxReadLength: 10) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: progress)
		}
		#expect(shortReadDecrypted.error == nil)
		#expect(cleartext == shortReadDecrypted.output)
		#expect(progress.isFinished)
	}

	@Test(arguments: schemes) func `short writes keep output complete`(scheme: CryptorScheme) async {
		let cryptor = scheme.makeCryptor()
		let cleartext = makeCleartext(count: 65 * 1024)
		let ciphertext = await runInFreshTask(input: cleartext, maxWriteLength: 1000) {
			try await cryptor.encryptContent(from: $0, to: $1, cleartextSize: cleartext.count, progress: nil)
		}.output
		#expect(cryptor.fileHeaderSize + cryptor.calculateCiphertextSize(cleartext.count) == ciphertext.count)

		let decrypted = await runInFreshTask(input: ciphertext, maxWriteLength: 1000) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: nil)
		}
		#expect(decrypted.error == nil)
		#expect(cleartext == decrypted.output)
	}

	@Test(arguments: schemes) func `decrypt truncated header throws`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		for size in [0, 1, cryptor.fileHeaderSize - 1] {
			let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
			try Data(repeating: 0x00, count: size).write(to: ciphertextURL)
			let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
			let progress = Progress.discreteProgress(totalUnitCount: 0)
			await #expect(throws: CryptoError.unauthenticCiphertext, "ciphertext size \(size)") {
				try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL, progress: progress)
			}
			#expect(!progress.isFinished)
		}
	}

	@Test(arguments: schemes) func `decrypt truncated chunk throws`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let header = try cryptor.encryptHeader(cryptor.createHeader())
		let ciphertext = header + [UInt8](repeating: 0x00, count: scheme.nonceLength + scheme.tagLength - 1)
		let result = await runInFreshTask(input: ciphertext) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: nil)
		}
		#expect(result.error as? CryptoError == .unauthenticCiphertext)
	}

	@Test(arguments: schemes) func `decrypt empty last chunk`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let header = try cryptor.createHeader()
		let ciphertext = try cryptor.encryptHeader(header) + cryptor.encryptSingleChunk([], chunkNumber: 0, headerNonce: header.nonce, fileKey: header.contentKey)
		let result = await runInFreshTask(input: ciphertext) {
			try await cryptor.decryptContent(from: $0, to: $1, ciphertextSize: ciphertext.count, progress: nil)
		}
		#expect(result.error == nil)
		#expect(result.output.isEmpty)
	}

	@Test(arguments: schemes) func `decrypt tampered header throws`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		var header = try cryptor.encryptHeader(cryptor.createHeader())
		header[header.count - 1] ^= 0x01
		#expect(throws: CryptoError.unauthenticCiphertext) { _ = try cryptor.decryptHeader(header) }
	}

	@Test(arguments: schemes) func `decrypt tampered chunk throws`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let nonce = [UInt8](repeating: 0x00, count: scheme.nonceLength)
		let filekey = SecretBytes(count: 32)
		var encrypted = try cryptor.encryptSingleChunk([UInt8]("hello world".utf8), chunkNumber: 0, headerNonce: nonce, fileKey: filekey)
		encrypted[encrypted.count - 1] ^= 0x01
		#expect(throws: CryptoError.unauthenticCiphertext) { try cryptor.decryptSingleChunk(encrypted, chunkNumber: 0, headerNonce: nonce, fileKey: filekey) }
	}

	@Test(arguments: contentCryptors) func `decrypt tampered chunk leaves cleartext untouched`(contentCryptor: any ContentCryptor) throws {
		let key = SecretBytes(count: 32)
		var chunk = try [UInt8]("hello world".utf8).withUnsafeBytes { try contentCryptor.encrypt($0, key: key, nonce: [UInt8](repeating: 0x00, count: contentCryptor.nonceLen), ad: []) }
		chunk[chunk.count - 1] ^= 0x01
		var cleartext = [UInt8](repeating: 0xAA, count: 11)
		#expect(throws: CryptoError.unauthenticCiphertext) {
			try cleartext.withUnsafeMutableBytes { try contentCryptor.decrypt(chunk, key: key, ad: [], into: $0) }
		}
		#expect([UInt8](repeating: 0xAA, count: 11) == cleartext)
	}

	@Test(arguments: schemes) func `concurrent round trips`(scheme: CryptorScheme) async throws {
		let cryptor = scheme.makeCryptor()
		let tmpDirURL = tmpDirURL
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
					#expect(try originalData == Data(contentsOf: cleartextURL))
				}
			}
			try await group.waitForAll()
		}
	}

	@Test(arguments: schemes) func `encrypt and decrypt single chunk`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let nonce = [UInt8](repeating: 0x00, count: scheme.nonceLength)
		let filekey = SecretBytes(count: 32)
		let cleartext = [UInt8]("hello world".utf8)

		let encrypted = try cryptor.encryptSingleChunk(cleartext, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)
		let decrypted = try cryptor.decryptSingleChunk(encrypted, chunkNumber: 0, headerNonce: nonce, fileKey: filekey)

		#expect(cleartext == decrypted)
	}

	@Test(arguments: schemes) func `decrypt single chunk of whole-file ciphertext`(scheme: CryptorScheme) async throws {
		let cryptor = Cryptor(masterkey: .test, scheme: scheme)
		let cleartext = [UInt8]((0 ..< cryptor.cleartextChunkSize * 3 + 100).map { UInt8($0 % 251) })
		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data(cleartext).write(to: cleartextURL)
		try await cryptor.encryptContent(from: cleartextURL, to: ciphertextURL)
		let ciphertext = try [UInt8](Data(contentsOf: ciphertextURL))

		let header = try cryptor.decryptHeader([UInt8](ciphertext[..<cryptor.fileHeaderSize]))
		for chunkNumber in [2, 3] {
			let ciphertextStart = cryptor.fileHeaderSize + chunkNumber * cryptor.ciphertextChunkSize
			let ciphertextChunk = [UInt8](ciphertext[ciphertextStart ..< min(ciphertextStart + cryptor.ciphertextChunkSize, ciphertext.count)])
			let cleartextStart = chunkNumber * cryptor.cleartextChunkSize
			let expected = [UInt8](cleartext[cleartextStart ..< min(cleartextStart + cryptor.cleartextChunkSize, cleartext.count)])
			#expect(try cryptor.decryptChunk(ciphertextChunk, chunkNumber: UInt64(chunkNumber), header: header) == expected)
		}
	}

	@Test(arguments: schemes) func `decrypt whole file built from single chunks`(scheme: CryptorScheme) async throws {
		let cryptor = Cryptor(masterkey: .test, scheme: scheme)
		let chunks = [[UInt8](repeating: 0x01, count: cryptor.cleartextChunkSize), [UInt8](repeating: 0x02, count: 42)]
		let header = try cryptor.createHeader()
		var ciphertext = try cryptor.encryptHeader(header)
		for (chunkNumber, chunk) in chunks.enumerated() {
			ciphertext += try cryptor.encryptChunk(chunk, chunkNumber: UInt64(chunkNumber), header: header)
		}
		#expect(ciphertext.count == cryptor.fileHeaderSize + cryptor.calculateCiphertextSize(chunks.joined().count))

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try Data(ciphertext).write(to: ciphertextURL)
		try await cryptor.decryptContent(from: ciphertextURL, to: cleartextURL)
		#expect(try [UInt8](Data(contentsOf: cleartextURL)) == Array(chunks.joined()))
	}

	@Test(arguments: schemes) func `decrypt chunk with wrong chunk number throws`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let header = try cryptor.createHeader()
		let ciphertext = try cryptor.encryptChunk([UInt8]("hello world".utf8), chunkNumber: 1, header: header)
		#expect(throws: CryptoError.unauthenticCiphertext) { try cryptor.decryptChunk(ciphertext, chunkNumber: 0, header: header) }
	}

	@Test(arguments: schemes) func `decrypt chunk of other file throws`(scheme: CryptorScheme) throws {
		let cryptor = Cryptor(masterkey: .test, scheme: scheme)
		let ciphertext = try cryptor.encryptChunk([UInt8]("hello world".utf8), chunkNumber: 0, header: cryptor.createHeader())
		#expect(throws: CryptoError.unauthenticCiphertext) { try cryptor.decryptChunk(ciphertext, chunkNumber: 0, header: cryptor.createHeader()) }
	}

	@Test(arguments: schemes) func `oversized chunks throw`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let header = try cryptor.createHeader()
		let cleartextChunkSize = cryptor.cleartextChunkSize
		let ciphertextChunkSize = cryptor.ciphertextChunkSize
		#expect(throws: CryptoError.invalidParameter("Cleartext chunk must not exceed \(cleartextChunkSize) bytes, but was \(cleartextChunkSize + 1)")) {
			try cryptor.encryptChunk([UInt8](repeating: 0x00, count: cleartextChunkSize + 1), chunkNumber: 0, header: header)
		}
		#expect(throws: CryptoError.invalidParameter("Ciphertext chunk must not exceed \(ciphertextChunkSize) bytes, but was \(ciphertextChunkSize + 1)")) {
			try cryptor.decryptChunk([UInt8](repeating: 0x00, count: ciphertextChunkSize + 1), chunkNumber: 0, header: header)
		}
	}

	@Test(arguments: schemes) func `calculate ciphertext size`(scheme: CryptorScheme) {
		let cryptor = scheme.makeCryptor()
		let overheadPerChunk = scheme.nonceLength + scheme.tagLength

		#expect(cryptor.calculateCiphertextSize(0) == 0)

		#expect(1 + overheadPerChunk == cryptor.calculateCiphertextSize(1))
		#expect(32 * 1024 - 1 + overheadPerChunk == cryptor.calculateCiphertextSize(32 * 1024 - 1))
		#expect(32 * 1024 + overheadPerChunk == cryptor.calculateCiphertextSize(32 * 1024))

		#expect(32 * 1024 + 1 + overheadPerChunk * 2 == cryptor.calculateCiphertextSize(32 * 1024 + 1))
		#expect(32 * 1024 + 2 + overheadPerChunk * 2 == cryptor.calculateCiphertextSize(32 * 1024 + 2))
		#expect(64 * 1024 - 1 + overheadPerChunk * 2 == cryptor.calculateCiphertextSize(64 * 1024 - 1))
		#expect(64 * 1024 + overheadPerChunk * 2 == cryptor.calculateCiphertextSize(64 * 1024))

		#expect(64 * 1024 + 1 + overheadPerChunk * 3 == cryptor.calculateCiphertextSize(64 * 1024 + 1))
	}

	@Test(arguments: schemes) func `calculate cleartext size`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let overheadPerChunk = scheme.nonceLength + scheme.tagLength

		#expect(try cryptor.calculateCleartextSize(0) == 0)

		#expect(try cryptor.calculateCleartextSize(1 + overheadPerChunk) == 1)
		#expect(try 32 * 1024 - 1 == cryptor.calculateCleartextSize(32 * 1024 - 1 + overheadPerChunk))
		#expect(try 32 * 1024 == cryptor.calculateCleartextSize(32 * 1024 + overheadPerChunk))

		#expect(try 32 * 1024 + 1 == cryptor.calculateCleartextSize(32 * 1024 + 1 + overheadPerChunk * 2))
		#expect(try 32 * 1024 + 2 == cryptor.calculateCleartextSize(32 * 1024 + 2 + overheadPerChunk * 2))
		#expect(try 64 * 1024 - 1 == cryptor.calculateCleartextSize(64 * 1024 - 1 + overheadPerChunk * 2))
		#expect(try 64 * 1024 == cryptor.calculateCleartextSize(64 * 1024 + overheadPerChunk * 2))

		#expect(try 64 * 1024 + 1 == cryptor.calculateCleartextSize(64 * 1024 + 1 + overheadPerChunk * 3))
	}

	@Test(arguments: schemes) func `calculate cleartext size with invalid ciphertext size`(scheme: CryptorScheme) throws {
		let cryptor = scheme.makeCryptor()
		let minusOneChunk = -cryptor.ciphertextChunkSize
		#expect(throws: CryptoError.invalidParameter("Method not defined for input value \(minusOneChunk)")) { try cryptor.calculateCleartextSize(minusOneChunk) }

		#expect(throws: CryptoError.invalidParameter("Method not defined for input value 1")) { try cryptor.calculateCleartextSize(1) }

		let emptyPayload = scheme.nonceLength + scheme.tagLength
		#expect(throws: CryptoError.invalidParameter("Method not defined for input value \(emptyPayload)")) { try cryptor.calculateCleartextSize(emptyPayload) }

		let oneChunkPlusOneByte = 32 * 1024 + emptyPayload + 1
		#expect(throws: CryptoError.invalidParameter("Method not defined for input value \(oneChunkPlusOneByte)")) { try cryptor.calculateCleartextSize(oneChunkPlusOneByte) }

		let oneChunkPlusEmptySecondChunk = 32 * 1024 + emptyPayload * 2
		#expect(throws: CryptoError.invalidParameter("Method not defined for input value \(oneChunkPlusEmptySecondChunk)")) { try cryptor.calculateCleartextSize(oneChunkPlusEmptySecondChunk) }
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

private extension CryptorScheme {
	var nonceLength: Int {
		switch self {
		case .sivCtrMac:
			return 16
		case .sivGcm:
			return 12
		}
	}

	var tagLength: Int {
		switch self {
		case .sivCtrMac:
			return 32
		case .sivGcm:
			return 16
		}
	}
}
