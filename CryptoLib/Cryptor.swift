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

public enum FileNameEncoding: String {
	case base64url
	case base32
}

struct FileHeader {
	let nonce: [UInt8]
	let contentKey: [UInt8]
}

public class Cryptor {
	private let masterKey: Masterkey
	private let csprng: CSPRNG

	public convenience init(masterKey: Masterkey) {
		self.init(masterKey: masterKey, csprng: CSPRNG())
	}

	internal init(masterKey: Masterkey, csprng: CSPRNG) {
		self.masterKey = masterKey
		self.csprng = csprng
	}

	// MARK: - Path Encryption and Decryption

	public func encryptDirId(_ dirId: Data) throws -> String {
		let encrypted = try AesSiv.encrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, plaintext: dirId.bytes)
		var digest = [UInt8](repeating: 0x00, count: Int(CC_SHA1_DIGEST_LENGTH))
		CC_SHA1(encrypted, UInt32(encrypted.count) as CC_LONG, &digest)
		return Data(digest).base32EncodedString
	}

	public func encryptFileName(_ cleartextName: String, dirId: Data, encoding: FileNameEncoding = .base64url) throws -> String {
		// encrypt:
		let cleartext = [UInt8](cleartextName.precomposedStringWithCanonicalMapping.utf8)
		let ciphertext = try AesSiv.encrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, plaintext: cleartext, ad: dirId.bytes)

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
		let cleartext = try AesSiv.decrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, ciphertext: ciphertextData.bytes, ad: dirId.bytes)
		if let str = String(data: Data(cleartext), encoding: .utf8) {
			return str
		} else {
			throw CryptoError.invalidParameter("Unable to decode cleartext using UTF-8.")
		}
	}

	// MARK: - File Header Encryption and Decryption

	func createHeader() throws -> FileHeader {
		let nonce = try csprng.createRandomBytes(size: kCCBlockSizeAES128)
		let contentKey = try csprng.createRandomBytes(size: kCCKeySizeAES256)
		return FileHeader(nonce: nonce, contentKey: contentKey)
	}

	func encryptHeader(_ header: FileHeader) throws -> [UInt8] {
		let cleartext = [UInt8](repeating: 0xFF, count: 8) + header.contentKey
		let ciphertext = try AesCtr.compute(key: masterKey.aesMasterKey, iv: header.nonce, data: cleartext)
		let toBeAuthenticated = header.nonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterKey.macMasterKey, masterKey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
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
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterKey.macMasterKey, masterKey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
		guard checkMAC(expected: expectedMAC, actual: mac) else {
			throw CryptoError.unauthenticCiphertext
		}

		// decrypt:
		let cleartext = try AesCtr.compute(key: masterKey.aesMasterKey, iv: nonce, data: ciphertext)
		let contentKey = [UInt8](cleartext[8...])
		return FileHeader(nonce: nonce, contentKey: contentKey)
	}

	// MARK: - File Content Encryption and Decryption

	// TODO: progress
	func encryptContent(from cleartextURL: URL, to ciphertextURL: URL) throws {
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

		// encrypt and write header:
		let header = try createHeader()
		let ciphertextHeader = try encryptHeader(header)
		ciphertextStream.write(ciphertextHeader, maxLength: ciphertextHeader.count)

		// encrypt and write content:
		var chunkNumber: UInt64 = 0
		while cleartextStream.hasBytesAvailable {
			// read chunk:
			var cleartextChunk = [UInt8](repeating: 0x00, count: 32 * 1024)
			let length = cleartextStream.read(&cleartextChunk, maxLength: cleartextChunk.count)
			guard length >= 0 else {
				throw CryptoError.ioError
			}
			assert(length < cleartextChunk.count)
			cleartextChunk.removeSubrange(length...)

			// encrypt and write chunk:
			let ciphertextChunk = try encryptSingleChunk(cleartextChunk, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
			ciphertextStream.write(ciphertextChunk, maxLength: ciphertextChunk.count)

			// prepare next chunk:
			chunkNumber += 1
		}
	}

	// TODO: progress
	func decryptContent(from ciphertextURL: URL, to cleartextURL: URL) throws {
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

		// read and decrypt file header:
		var ciphertextHeader = [UInt8](repeating: 0x00, count: 88)
		ciphertextStream.read(&ciphertextHeader, maxLength: ciphertextHeader.count)
		let header = try decryptHeader(ciphertextHeader)

		// decrypt content:
		var chunkNumber: UInt64 = 0
		while ciphertextStream.hasBytesAvailable {
			// read chunk:
			var ciphertextChunk = [UInt8](repeating: 0x00, count: 16 + 32 * 1024 + 32)
			let length = ciphertextStream.read(&ciphertextChunk, maxLength: ciphertextChunk.count)
			guard length >= 0 else {
				throw CryptoError.ioError
			}
			assert(length < ciphertextChunk.count)
			ciphertextChunk.removeSubrange(length...)

			// decrypt and write chunk:
			let cleartextChunk = try decryptSingleChunk(ciphertextHeader, chunkNumber: chunkNumber, headerNonce: header.nonce, fileKey: header.contentKey)
			cleartextStream.write(cleartextChunk, maxLength: cleartextChunk.count)

			// prepare next chunk:
			chunkNumber += 1
		}
	}

	func encryptSingleChunk(_ chunk: [UInt8], chunkNumber: UInt64, headerNonce: [UInt8], fileKey: [UInt8]) throws -> [UInt8] {
		let chunkNonce = try csprng.createRandomBytes(size: kCCBlockSizeAES128)
		let ciphertext = try AesCtr.compute(key: fileKey, iv: chunkNonce, data: chunk)
		let toBeAuthenticated = headerNonce + chunkNumber.bigEndian.byteArray() + chunkNonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterKey.macMasterKey, masterKey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
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
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterKey.macMasterKey, masterKey.macMasterKey.count, toBeAuthenticated, toBeAuthenticated.count, &mac)
		guard checkMAC(expected: expectedMAC, actual: mac) else {
			throw CryptoError.unauthenticCiphertext
		}

		// decrypt:
		return try AesCtr.compute(key: fileKey, iv: chunkNonce, data: ciphertext)
	}

	// MARK: - Internal

	/**
	 Constant-time comparison
	 */
	private func checkMAC(expected: [UInt8], actual: [UInt8]) -> Bool {
		assert(expected.count == actual.count, "MACs expected to be of same length")

		if #available(iOS 10.1, *) {
			return timingsafe_bcmp(expected, actual, expected.count) == 0
		} else {
			var diff: UInt8 = 0
			for i in 0 ..< expected.count {
				diff |= expected[i] ^ actual[i]
			}
			return diff == 0
		}
	}
}
