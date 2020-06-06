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

enum CryptorError: Error, Equatable {
	case invalidCiphertext(_ reason: String? = nil)
	case csprngError
	case unauthenticCiphertext
}

public class Cryptor {
	private let masterKey: Masterkey

	public init(masterKey: Masterkey) {
		self.masterKey = masterKey
	}

	// MARK: - Path Encryption and Decryption:

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
			throw CryptorError.invalidCiphertext("Can't \(encoding.rawValue)-decode ciphertext name: \(ciphertextName)")
		}

		// decrypt:
		let cleartext = try AesSiv.decrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, ciphertext: ciphertextData.bytes, ad: dirId.bytes)
		if let str = String(data: Data(cleartext), encoding: .utf8) {
			return str
		} else {
			throw CryptorError.invalidCiphertext("Unable to decode cleartext using UTF-8.")
		}
	}

	// MARK: - File Content Encryption and Decryption

	func encryptSingleChunk(_ chunk: [UInt8], chunkNumber: UInt64, headerNonce: [UInt8], fileKey: [UInt8]) throws -> [UInt8] {
		var chunkNonce = [UInt8](repeating: 0x00, count: kCCBlockSizeAES128)
		guard SecRandomCopyBytes(kSecRandomDefault, chunkNonce.count, &chunkNonce) == errSecSuccess else {
			throw CryptorError.csprngError
		}
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
			throw CryptorError.unauthenticCiphertext
		}

		// decrypt:
		return try AesCtr.compute(key: fileKey, iv: chunkNonce, data: ciphertext)
	}

	// time constant comparison:
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
