//
//  Cryptor.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation
import SwiftBase32

extension Data {
	public init?(base64UrlEncoded base64String: String, options: Data.Base64DecodingOptions = []) {
		self.init(base64Encoded: base64String.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"), options: options)
	}

	public func base64UrlEncodedString(options: Data.Base64EncodingOptions = []) -> String {
		return base64EncodedString(options: options).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
	}
}

extension FixedWidthInteger {
	public func byteArray() -> [UInt8] {
		return withUnsafeBytes(of: self, { [UInt8]($0) })
	}
}

extension InputStream {
	public func read(maxLength: Int) throws -> [UInt8]? {
		var buffer = [UInt8](repeating: 0x00, count: maxLength)
		let length = read(&buffer, maxLength: maxLength)
		if length == 0 {
			return nil
		}
		guard length > 0 else {
			throw streamError ?? CryptoError.ioError
		}
		assert(length <= buffer.count)
		buffer.removeSubrange(length...)
		return buffer
	}
}

public enum FileNameEncoding: String {
	case base64url
	case base32
}

struct FileHeader {
	let nonce: [UInt8]
	let contentKey: [UInt8]
}

public class Cryptor {
	static let fileHeaderLegacyPayloadSize = 8
	static let fileHeaderSize = kCCBlockSizeAES128 + fileHeaderLegacyPayloadSize + kCCKeySizeAES256 + Int(CC_SHA256_DIGEST_LENGTH)
	static let cleartextChunkSize = 32 * 1024
	static let ciphertextChunkSize = kCCBlockSizeAES128 + cleartextChunkSize + Int(CC_SHA256_DIGEST_LENGTH)

	private let masterkey: Masterkey
	private let cryptoSupport: CryptoSupport

	init(masterkey: Masterkey, cryptoSupport: CryptoSupport) {
		self.masterkey = masterkey
		self.cryptoSupport = cryptoSupport
	}

	public convenience init(masterkey: Masterkey) {
		self.init(masterkey: masterkey, cryptoSupport: CryptoSupport())
	}

	// MARK: - Path Encryption and Decryption

	public func encryptDirId(_ dirId: Data) throws -> String {
		let encrypted = try AesSiv.encrypt(aesKey: masterkey.aesMasterKey, macKey: masterkey.macMasterKey, plaintext: dirId.bytes)
		var digest = [UInt8](repeating: 0x00, count: Int(CC_SHA1_DIGEST_LENGTH))
		CC_SHA1(encrypted, UInt32(encrypted.count) as CC_LONG, &digest)
		return Data(digest).base32EncodedString
	}

	public func encryptFileName(_ cleartextName: String, dirId: Data, encoding: FileNameEncoding = .base64url) throws -> String {
		// encrypt:
		let cleartext = [UInt8](cleartextName.precomposedStringWithCanonicalMapping.utf8)
		let ciphertext = try AesSiv.encrypt(aesKey: masterkey.aesMasterKey, macKey: masterkey.macMasterKey, plaintext: cleartext, ad: dirId.bytes)

		// encode:
		switch encoding {
		case .base64url: return Data(ciphertext).base64UrlEncodedString()
		case .base32: return Data(ciphertext).base32EncodedString
		}
	}

	public func decryptFileName(_ ciphertextName: String, dirId: Data, encoding: FileNameEncoding = .base64url) throws -> String {
		// decode:
		let maybeCiphertextData: Data? = {
			switch encoding {
			case .base64url: return Data(base64UrlEncoded: ciphertextName)
			case .base32: return ciphertextName.base32DecodedData
			}
		}()
		guard let ciphertextData = maybeCiphertextData else {
			throw CryptoError.invalidParameter("Can't \(encoding.rawValue)-decode ciphertext name: \(ciphertextName)")
		}

		// decrypt:
		let cleartext = try AesSiv.decrypt(aesKey: masterkey.aesMasterKey, macKey: masterkey.macMasterKey, ciphertext: ciphertextData.bytes, ad: dirId.bytes)
		if let str = String(data: Data(cleartext), encoding: .utf8) {
			return str
		} else {
			throw CryptoError.invalidParameter("Unable to decode cleartext using UTF-8.")
		}
	}

	// MARK: - File Header Encryption and Decryption

	func createHeader() throws -> FileHeader {
		let nonce = try cryptoSupport.createRandomBytes(size: kCCBlockSizeAES128)
		let contentKey = try cryptoSupport.createRandomBytes(size: kCCKeySizeAES256)
		return FileHeader(nonce: nonce, contentKey: contentKey)
	}

	func encryptHeader(_ header: FileHeader) throws -> [UInt8] {
		let cleartext = [UInt8](repeating: 0xFF, count: Cryptor.fileHeaderLegacyPayloadSize) + header.contentKey
		let ciphertext = try AesCtr.compute(key: masterkey.aesMasterKey, iv: header.nonce, data: cleartext)
		let toBeAuthenticated = header.nonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterkey.macMasterKey, masterkey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
		return header.nonce + ciphertext + mac
	}

	func decryptHeader(_ header: [UInt8]) throws -> FileHeader {
		// decompose header:
		let beginOfMAC = header.count - Int(CC_SHA256_DIGEST_LENGTH)
		let nonce = [UInt8](header[0 ..< kCCBlockSizeAES128])
		let ciphertext = [UInt8](header[kCCBlockSizeAES128 ..< beginOfMAC])
		let expectedMAC = [UInt8](header[beginOfMAC...])

		// check MAC:
		let toBeAuthenticated = nonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterkey.macMasterKey, masterkey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
		guard cryptoSupport.compareBytes(expected: expectedMAC, actual: mac) else {
			throw CryptoError.unauthenticCiphertext
		}

		// decrypt:
		let cleartext = try AesCtr.compute(key: masterkey.aesMasterKey, iv: nonce, data: ciphertext)
		let contentKey = [UInt8](cleartext[Cryptor.fileHeaderLegacyPayloadSize...])
		return FileHeader(nonce: nonce, contentKey: contentKey)
	}

	// MARK: - File Content Encryption and Decryption

	public func encryptContent(from cleartextURL: URL, to ciphertextURL: URL) throws {
		// open cleartext input stream:
		guard let cleartextStream = InputStream(url: cleartextURL) else {
			throw CryptoError.ioError
		}
		cleartextStream.schedule(in: .current, forMode: .default)
		cleartextStream.open()
		defer { cleartextStream.close() }

		// open ciphertext output stream:
		guard let ciphertextStream = OutputStream(url: ciphertextURL, append: false) else {
			throw CryptoError.ioError
		}
		ciphertextStream.schedule(in: .current, forMode: .default)
		ciphertextStream.open()
		defer { ciphertextStream.close() }

		// encrypt:
		try encryptContent(from: cleartextStream, to: ciphertextStream)
	}

	// TODO: progress
	func encryptContent(from cleartextStream: InputStream, to ciphertextStream: OutputStream) throws {
		// encrypt and write header:
		let header = try createHeader()
		let ciphertextHeader = try encryptHeader(header)
		ciphertextStream.write(ciphertextHeader, maxLength: ciphertextHeader.count)

		// encrypt and write ciphertext content:
		var chunkNumber: UInt64 = 0
		while cleartextStream.hasBytesAvailable {
			guard let cleartextChunk = try cleartextStream.read(maxLength: Cryptor.cleartextChunkSize) else {
				continue
			}
			let ciphertextChunk = try encryptSingleChunk(cleartextChunk, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
			ciphertextStream.write(ciphertextChunk, maxLength: ciphertextChunk.count)
			chunkNumber += 1
		}
	}

	public func decryptContent(from ciphertextURL: URL, to cleartextURL: URL) throws {
		// open ciphertext input stream:
		guard let ciphertextStream = InputStream(url: ciphertextURL) else {
			throw CryptoError.ioError
		}
		ciphertextStream.schedule(in: .current, forMode: .default)
		ciphertextStream.open()
		defer { ciphertextStream.close() }

		// open cleartext output stream:
		guard let cleartextStream = OutputStream(url: cleartextURL, append: false) else {
			throw CryptoError.ioError
		}
		cleartextStream.schedule(in: .current, forMode: .default)
		cleartextStream.open()
		defer { cleartextStream.close() }

		// decrypt:
		try decryptContent(from: ciphertextStream, to: cleartextStream)
	}

	// TODO: progress
	func decryptContent(from ciphertextStream: InputStream, to cleartextStream: OutputStream) throws {
		// read and decrypt header:
		guard let ciphertextHeader = try ciphertextStream.read(maxLength: Cryptor.fileHeaderSize) else {
			throw CryptoError.ioError
		}
		let header = try decryptHeader(ciphertextHeader)

		// decrypt and write cleartext content:
		var chunkNumber: UInt64 = 0
		while ciphertextStream.hasBytesAvailable {
			guard let ciphertextChunk = try ciphertextStream.read(maxLength: Cryptor.ciphertextChunkSize) else {
				continue
			}
			let cleartextChunk = try decryptSingleChunk(ciphertextChunk, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
			cleartextStream.write(cleartextChunk, maxLength: cleartextChunk.count)
			chunkNumber += 1
		}
	}

	func encryptSingleChunk(_ chunk: [UInt8], chunkNumber: UInt64, headerNonce: [UInt8], fileKey: [UInt8]) throws -> [UInt8] {
		let chunkNonce = try cryptoSupport.createRandomBytes(size: kCCBlockSizeAES128)
		let ciphertext = try AesCtr.compute(key: fileKey, iv: chunkNonce, data: chunk)
		let toBeAuthenticated = headerNonce + chunkNumber.bigEndian.byteArray() + chunkNonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterkey.macMasterKey, masterkey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
		return chunkNonce + ciphertext + mac
	}

	func decryptSingleChunk(_ chunk: [UInt8], chunkNumber: UInt64, headerNonce: [UInt8], fileKey: [UInt8]) throws -> [UInt8] {
		assert(chunk.count >= kCCBlockSizeAES128 + Int(CC_SHA256_DIGEST_LENGTH), "ciphertext chunk must at least contain nonce + mac")

		// decompose chunk:
		let beginOfMAC = chunk.count - Int(CC_SHA256_DIGEST_LENGTH)
		let chunkNonce = [UInt8](chunk[0 ..< kCCBlockSizeAES128])
		let ciphertext = [UInt8](chunk[kCCBlockSizeAES128 ..< beginOfMAC])
		let expectedMAC = [UInt8](chunk[beginOfMAC...])

		// check MAC:
		let toBeAuthenticated = headerNonce + chunkNumber.bigEndian.byteArray() + chunkNonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterkey.macMasterKey, masterkey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
		guard cryptoSupport.compareBytes(expected: expectedMAC, actual: mac) else {
			throw CryptoError.unauthenticCiphertext
		}

		// decrypt:
		return try AesCtr.compute(key: fileKey, iv: chunkNonce, data: ciphertext)
	}

	// MARK: - File Size Calculation

	public func calculateCiphertextSize(_ cleartextSize: Int) -> Int {
		assert(cleartextSize >= 0, "expected cleartextSize to be positive, but was \(cleartextSize)")
		let overheadPerChunk = Cryptor.ciphertextChunkSize - Cryptor.cleartextChunkSize
		let numFullChunks = cleartextSize / Cryptor.cleartextChunkSize // floor by int-truncation
		let additionalCleartextBytes = cleartextSize % Cryptor.cleartextChunkSize
		let additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk
		assert(additionalCiphertextBytes >= 0)
		return Cryptor.ciphertextChunkSize * numFullChunks + additionalCiphertextBytes
	}

	public func calculateCleartextSize(_ ciphertextSize: Int) throws -> Int {
		assert(ciphertextSize >= 0, "expected ciphertextSize to be positive, but was \(ciphertextSize)")
		let overheadPerChunk = Cryptor.ciphertextChunkSize - Cryptor.cleartextChunkSize
		let numFullChunks = ciphertextSize / Cryptor.ciphertextChunkSize // floor by int-truncation
		let additionalCiphertextBytes = ciphertextSize % Cryptor.ciphertextChunkSize
		guard additionalCiphertextBytes == 0 || additionalCiphertextBytes > overheadPerChunk else {
			throw CryptoError.invalidParameter("Method not defined for input value \(ciphertextSize)")
		}
		let additionalCleartextBytes = (additionalCiphertextBytes == 0) ? 0 : additionalCiphertextBytes - overheadPerChunk
		assert(additionalCleartextBytes >= 0)
		return Cryptor.cleartextChunkSize * numFullChunks + additionalCleartextBytes
	}
}
