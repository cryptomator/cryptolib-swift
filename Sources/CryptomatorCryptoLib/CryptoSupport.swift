//
//  CryptoSupport.swift
//  CryptomatorCryptoLib
//
//  Created by Tobias Hagemann on 10.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

protocol CryptoSupport: Sendable {
	/**
	 Fills a buffer with cryptographically secure random bytes.
	 */
	func fillRandomBytes(_ buffer: UnsafeMutableRawBufferPointer) throws
}

extension CryptoSupport {
	/**
	 Creates an array of cryptographically secure random bytes, for values that are not secret, such as nonces and salts.
	 */
	func createRandomBytes(size: Int) throws -> [UInt8] {
		var randomBytes = [UInt8](repeating: 0x00, count: size)
		try randomBytes.withUnsafeMutableBytes { try fillRandomBytes($0) }
		return randomBytes
	}

	/**
	 Creates cryptographically secure random secret bytes, such as keys.
	 */
	func createRandomSecret(size: Int) throws -> SecretBytes {
		var randomSecret = SecretBytes(count: size)
		try randomSecret.withUnsafeMutableBytes { try fillRandomBytes($0) }
		return randomSecret
	}
}

/**
 Compares byte arrays in constant-time.

 The running time of this function depends only on the lengths of the byte arrays, not on their contents, making it safe to use for comparing secret values such as cryptographic MACs.

 - Parameter expected: Expected bytes for comparison.
 - Parameter actual: Actual bytes for comparison.
 - Returns: `true` if `expected` and `actual` are equal, otherwise `false`. Byte arrays of different lengths are never equal.
 */
func compareBytes(expected: [UInt8], actual: [UInt8]) -> Bool {
	guard expected.count == actual.count else {
		return false
	}
	return timingsafe_bcmp(expected, actual, expected.count) == 0
}

func hmacSha256(key: borrowing SecretBytes, data: [UInt8]) -> [UInt8] {
	var mac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
	key.withUnsafeBytes { keyBytes in
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes.baseAddress, keyBytes.count, data, data.count, &mac)
	}
	return mac
}

struct DefaultCryptoSupport: CryptoSupport {
	func fillRandomBytes(_ buffer: UnsafeMutableRawBufferPointer) throws {
		guard let baseAddress = buffer.baseAddress else {
			return
		}
		guard SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress) == errSecSuccess else {
			throw CryptoError.csprngError
		}
	}
}
