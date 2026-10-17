//
//  Cryptor.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import CryptoKit
import Foundation

public extension Data {
	init?(base64UrlEncoded base64String: String, options: Data.Base64DecodingOptions = []) {
		self.init(base64Encoded: base64String.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"), options: options)
	}

	func base64UrlEncodedString(options: Data.Base64EncodingOptions = []) -> String {
		return base64EncodedString(options: options).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
	}
}

public extension FixedWidthInteger {
	func byteArray() -> [UInt8] {
		return withUnsafeBytes(of: self, { [UInt8]($0) })
	}
}

extension InputStream {
	func readChunk(maxLength: Int) throws -> [UInt8]? {
		var buffer = [UInt8](repeating: 0x00, count: maxLength)
		var length = 0
		while length < maxLength {
			let result = buffer.withUnsafeMutableBufferPointer { read($0.baseAddress! + length, maxLength: maxLength - length) }
			guard result >= 0 else {
				throw streamError ?? CryptoError.ioError
			}
			guard result > 0 else {
				break
			}
			length += result
		}
		guard length > 0 else {
			return nil
		}
		buffer.removeSubrange(length...)
		return buffer
	}
}

extension OutputStream {
	func write(_ bytes: [UInt8]) throws {
		var written = 0
		while written < bytes.count {
			let result = bytes.withUnsafeBufferPointer { write($0.baseAddress! + written, maxLength: bytes.count - written) }
			guard result > 0 else {
				throw streamError ?? CryptoError.ioError
			}
			written += result
		}
	}
}

extension Stream {
	func openChecked() throws {
		open()
		if streamStatus == .error {
			throw streamError ?? CryptoError.ioError
		}
	}
}

private extension Progress {
	func begin(expectedUnitCount: Int?) {
		totalUnitCount = expectedUnitCount.map { Int64(max($0, 1)) } ?? -1
		completedUnitCount = 0
	}

	/// Stays incomplete until the end of the input has been read successfully.
	func update(processedUnitCount: Int64) {
		completedUnitCount = totalUnitCount > 0 ? min(processedUnitCount, totalUnitCount - 1) : processedUnitCount
	}

	func complete(processedUnitCount: Int64) {
		let total = max(processedUnitCount, 1)
		if totalUnitCount != total {
			totalUnitCount = total
		}
		completedUnitCount = total
	}
}

public enum CryptorScheme: String, Codable, Sendable {
	case sivCtrMac = "SIV_CTRMAC"
	case sivGcm = "SIV_GCM"
}

public enum FileNameEncoding: String, Sendable {
	case base64url
	case base32
}

struct FileHeader: ~Copyable {
	let nonce: [UInt8]
	let contentKey: SecretBytes
}

public final class Cryptor: Sendable {
	private let fileHeaderLegacyPayloadSize = 8
	public var fileHeaderSize: Int {
		let fileHeaderPayloadSize = fileHeaderLegacyPayloadSize + kCCKeySizeAES256
		return contentCryptor.nonceLen + fileHeaderPayloadSize + contentCryptor.tagLen
	}

	let cleartextChunkSize = 32 * 1024
	var ciphertextChunkSize: Int {
		return contentCryptor.nonceLen + cleartextChunkSize + contentCryptor.tagLen
	}

	private let masterkey: Masterkey
	private let cryptoSupport: CryptoSupport
	private let contentCryptor: ContentCryptor

	public convenience init(masterkey: Masterkey, scheme: CryptorScheme) {
		self.init(masterkey: masterkey, scheme: scheme, cryptoSupport: DefaultCryptoSupport())
	}

	init(masterkey: Masterkey, scheme: CryptorScheme, cryptoSupport: CryptoSupport) {
		self.masterkey = masterkey
		self.cryptoSupport = cryptoSupport
		self.contentCryptor = switch scheme {
		case .sivCtrMac:
			CtrThenHmacContentCryptor(masterkey: masterkey)
		case .sivGcm:
			GcmContentCryptor()
		}
	}

	// MARK: - Path Encryption and Decryption

	/**
	 Encrypts directory ID.

	 - Parameter dirId: An arbitrary directory ID to be passed to one-way hash function.
	 - Returns: Constant length string that is unlikely to collide with any other name.
	 */
	public func encryptDirId(_ dirId: Data) throws -> String {
		let encrypted = try AesSiv.encrypt(aesKey: masterkey.aesMasterKey, macKey: masterkey.macMasterKey, plaintext: [UInt8](dirId))
		let digest = Insecure.SHA1.hash(data: encrypted)
		return Data(digest).base32EncodedString()
	}

	/**
	 Encrypts filename.

	 - Parameter cleartextName: Original filename including cleartext file extension.
	 - Parameter dirId: Directory ID that will be used as associated data. It will not get encrypted but needs to be provided during decryption.
	 - Parameter encoding: Encoding to use to encode the returned ciphertext. Defaults to base64url.
	 - Returns: Encrypted filename without any file extension.
	 */
	public func encryptFileName(_ cleartextName: String, dirId: Data, encoding: FileNameEncoding = .base64url) throws -> String {
		// encrypt:
		let cleartext = [UInt8](cleartextName.precomposedStringWithCanonicalMapping.utf8)
		let ciphertext = try AesSiv.encrypt(aesKey: masterkey.aesMasterKey, macKey: masterkey.macMasterKey, plaintext: cleartext, ad: [UInt8](dirId))

		// encode:
		switch encoding {
		case .base64url: return Data(ciphertext).base64UrlEncodedString()
		case .base32: return Data(ciphertext).base32EncodedString()
		}
	}

	/**
	 Decrypts filename.

	 - Parameter ciphertextName: Ciphertext only. Any additional strings like file extensions need to be stripped first.
	 - Parameter dirId: The same directed ID used during encryption as associated data.
	 - Parameter encoding: Encoding to use to decode `ciphertextName`. Defaults to base64url.
	 - Returns: Decrypted filename, probably including its cleartext file extension.
	 */
	public func decryptFileName(_ ciphertextName: String, dirId: Data, encoding: FileNameEncoding = .base64url) throws -> String {
		// decode:
		let maybeCiphertextData: Data? = {
			switch encoding {
			case .base64url: return Data(base64UrlEncoded: ciphertextName)
			case .base32: return Data(base32Encoded: ciphertextName)
			}
		}()
		guard let ciphertextData = maybeCiphertextData else {
			throw CryptoError.invalidParameter("Can't \(encoding.rawValue)-decode ciphertext name: \(ciphertextName)")
		}

		// decrypt:
		let cleartext = try AesSiv.decrypt(aesKey: masterkey.aesMasterKey, macKey: masterkey.macMasterKey, ciphertext: [UInt8](ciphertextData), ad: [UInt8](dirId))
		guard let cleartextString = String(bytes: cleartext, encoding: .utf8) else {
			throw CryptoError.invalidParameter("Can't UTF-8-decode cleartext")
		}
		return cleartextString
	}

	// MARK: - File Header Encryption and Decryption

	func createHeader() throws -> FileHeader {
		let nonce = try cryptoSupport.createRandomBytes(size: contentCryptor.nonceLen)
		let contentKey = try cryptoSupport.createRandomSecret(size: kCCKeySizeAES256)
		return FileHeader(nonce: nonce, contentKey: contentKey)
	}

	func encryptHeader(_ header: borrowing FileHeader) throws -> [UInt8] {
		var payload = SecretBytes(count: fileHeaderLegacyPayloadSize + kCCKeySizeAES256)
		payload.withUnsafeMutableBytes { payloadBytes in
			payloadBytes[..<fileHeaderLegacyPayloadSize].initializeMemory(as: UInt8.self, repeating: 0xFF)
			header.contentKey.withUnsafeBytes { payloadBytes[fileHeaderLegacyPayloadSize...].copyBytes(from: $0) }
		}
		return try contentCryptor.encryptHeader(payload, key: masterkey.aesMasterKey, nonce: header.nonce)
	}

	func decryptHeader(_ header: [UInt8]) throws -> FileHeader {
		guard header.count == fileHeaderSize else {
			throw CryptoError.unauthenticCiphertext
		}
		let nonce = [UInt8](header[0 ..< contentCryptor.nonceLen])
		let payload = try contentCryptor.decryptHeader(header, key: masterkey.aesMasterKey)
		let contentKey = payload.withUnsafeBytes { SecretBytes(copying: $0[fileHeaderLegacyPayloadSize...]) }
		return FileHeader(nonce: nonce, contentKey: contentKey)
	}

	// MARK: - File Content Encryption and Decryption

	/**
	 Encrypts file content.

	 Checks for cancellation of the calling Task before opening the output and before each chunk, and throws `CancellationError` when cancelled. On any error, a partially written ciphertext file is left for the caller to delete.

	 - Parameter cleartextURL: The input URL of a cleartext file.
	 - Parameter ciphertextURL: The output URL of the ciphertext file.
	 - Parameter progress: An optional progress whose `totalUnitCount` and `completedUnitCount` this method resets when the call starts and sets from then on. Do not modify them during the call. Units are ciphertext payload bytes, with a total of at least 1. The progress is completed on success and left incomplete on failure or cancellation.
	 */
	@concurrent public func encryptContent(from cleartextURL: URL, to ciphertextURL: URL, progress: Progress? = nil) async throws {
		progress?.begin(expectedUnitCount: nil)

		// open cleartext input stream:
		guard let cleartextStream = InputStream(url: cleartextURL) else {
			throw CryptoError.ioError
		}
		defer { cleartextStream.close() }
		try cleartextStream.openChecked()

		// determine cleartext size:
		let attributes = try FileManager.default.attributesOfItem(atPath: cleartextURL.path)
		let cleartextSize = attributes[FileAttributeKey.size] as? Int

		// a cancelled call must not truncate an existing output file:
		try Task.checkCancellation()

		// open ciphertext output stream:
		guard let ciphertextStream = OutputStream(url: ciphertextURL, append: false) else {
			throw CryptoError.ioError
		}
		defer { ciphertextStream.close() }
		try ciphertextStream.openChecked()

		// encrypt:
		try await encryptContent(from: cleartextStream, to: ciphertextStream, cleartextSize: cleartextSize, progress: progress)
	}

	func encryptContent(from cleartextStream: InputStream, to ciphertextStream: OutputStream, cleartextSize: Int?, progress: Progress?) async throws {
		progress?.begin(expectedUnitCount: cleartextSize.map { calculateCiphertextSize($0) })

		// encrypt and write header:
		let header = try createHeader()
		let ciphertextHeader = try encryptHeader(header)
		try ciphertextStream.write(ciphertextHeader)

		// encrypt and write ciphertext content:
		var chunkNumber: UInt64 = 0
		var processedSize: Int64 = 0
		while let cleartextChunk = try cleartextStream.readChunk(maxLength: cleartextChunkSize) {
			try Task.checkCancellation()
			let ciphertextChunk = try autoreleasepool {
				let ciphertextChunk = try encryptSingleChunk(cleartextChunk, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
				try ciphertextStream.write(ciphertextChunk)
				return ciphertextChunk
			}
			processedSize += Int64(ciphertextChunk.count)
			progress?.update(processedUnitCount: processedSize)
			chunkNumber += 1
			await Task.yield()
		}
		progress?.complete(processedUnitCount: processedSize)
	}

	/**
	 Decrypts file content.

	 Checks for cancellation of the calling Task before opening the output and before each chunk, and throws `CancellationError` when cancelled. On any error, a partially written cleartext file is left for the caller to delete.

	 - Parameter ciphertextURL: The input URL of a ciphertext file.
	 - Parameter cleartextURL: The output URL of the cleartext file.
	 - Parameter progress: An optional progress whose `totalUnitCount` and `completedUnitCount` this method resets when the call starts and sets from then on. Do not modify them during the call. Units are cleartext bytes, with a total of at least 1. The progress is completed on success and left incomplete on failure or cancellation.
	 */
	@concurrent public func decryptContent(from ciphertextURL: URL, to cleartextURL: URL, progress: Progress? = nil) async throws {
		progress?.begin(expectedUnitCount: nil)

		// open ciphertext input stream:
		guard let ciphertextStream = InputStream(url: ciphertextURL) else {
			throw CryptoError.ioError
		}
		defer { ciphertextStream.close() }
		try ciphertextStream.openChecked()

		// determine ciphertext size:
		let attributes = try FileManager.default.attributesOfItem(atPath: ciphertextURL.path)
		let ciphertextSize = attributes[FileAttributeKey.size] as? Int

		// a cancelled call must not truncate an existing output file:
		try Task.checkCancellation()

		// open cleartext output stream:
		guard let cleartextStream = OutputStream(url: cleartextURL, append: false) else {
			throw CryptoError.ioError
		}
		defer { cleartextStream.close() }
		try cleartextStream.openChecked()

		// decrypt:
		try await decryptContent(from: ciphertextStream, to: cleartextStream, ciphertextSize: ciphertextSize, progress: progress)
	}

	func decryptContent(from ciphertextStream: InputStream, to cleartextStream: OutputStream, ciphertextSize: Int?, progress: Progress?) async throws {
		progress?.begin(expectedUnitCount: ciphertextSize.flatMap { try? calculateCleartextSize($0 - fileHeaderSize) })

		// read and decrypt header:
		guard let ciphertextHeader = try ciphertextStream.readChunk(maxLength: fileHeaderSize) else {
			throw CryptoError.unauthenticCiphertext
		}
		let header = try decryptHeader(ciphertextHeader)

		// decrypt and write cleartext content:
		var chunkNumber: UInt64 = 0
		var processedSize: Int64 = 0
		while let ciphertextChunk = try ciphertextStream.readChunk(maxLength: ciphertextChunkSize) {
			try Task.checkCancellation()
			let cleartextChunk = try autoreleasepool {
				let cleartextChunk = try decryptSingleChunk(ciphertextChunk, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
				try cleartextStream.write(cleartextChunk)
				return cleartextChunk
			}
			processedSize += Int64(cleartextChunk.count)
			progress?.update(processedUnitCount: processedSize)
			chunkNumber += 1
			await Task.yield()
		}
		progress?.complete(processedUnitCount: processedSize)
	}

	func encryptSingleChunk(_ chunk: [UInt8], chunkNumber: UInt64, headerNonce: [UInt8], fileKey: borrowing SecretBytes) throws -> [UInt8] {
		let chunkNonce = try cryptoSupport.createRandomBytes(size: contentCryptor.nonceLen)
		return try contentCryptor.encryptChunk(chunk, chunkNumber: chunkNumber, chunkNonce: chunkNonce, fileKey: fileKey, headerNonce: headerNonce)
	}

	func decryptSingleChunk(_ chunk: [UInt8], chunkNumber: UInt64, headerNonce: [UInt8], fileKey: borrowing SecretBytes) throws -> [UInt8] {
		return try contentCryptor.decryptChunk(chunk, chunkNumber: chunkNumber, fileKey: fileKey, headerNonce: headerNonce)
	}

	// MARK: - File Size Calculation

	/**
	 Calculates ciphertext size from cleartext size.

	 - Parameter cleartextSize: Size of the unencrypted payload.
	 - Precondition: `cleartextSize` must not be negative.
	 - Returns: Ciphertext size of a `cleartextSize`-sized cleartext encrypted with this `Cryptor`. Not including the file header.
	 */
	public func calculateCiphertextSize(_ cleartextSize: Int) -> Int {
		precondition(cleartextSize >= 0, "expected cleartextSize to be non-negative, but was \(cleartextSize)")
		let overheadPerChunk = ciphertextChunkSize - cleartextChunkSize
		let numFullChunks = cleartextSize / cleartextChunkSize // floor by int-truncation
		let additionalCleartextBytes = cleartextSize % cleartextChunkSize
		let additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk
		assert(additionalCiphertextBytes >= 0)
		return ciphertextChunkSize * numFullChunks + additionalCiphertextBytes
	}

	/**
	 Calculates cleartext size from ciphertext size.

	 - Parameter ciphertextSize: Size of the encrypted payload. Not including the file header.
	 - Returns: Cleartext size of a `ciphertextSize`-sized ciphertext decrypted with this `Cryptor`.
	 */
	public func calculateCleartextSize(_ ciphertextSize: Int) throws -> Int {
		let overheadPerChunk = ciphertextChunkSize - cleartextChunkSize
		let numFullChunks = ciphertextSize / ciphertextChunkSize // floor by int-truncation
		let additionalCiphertextBytes = ciphertextSize % ciphertextChunkSize
		guard ciphertextSize >= 0, additionalCiphertextBytes == 0 || additionalCiphertextBytes > overheadPerChunk else {
			throw CryptoError.invalidParameter("Method not defined for input value \(ciphertextSize)")
		}
		let additionalCleartextBytes = (additionalCiphertextBytes == 0) ? 0 : additionalCiphertextBytes - overheadPerChunk
		assert(additionalCleartextBytes >= 0)
		return cleartextChunkSize * numFullChunks + additionalCleartextBytes
	}
}
