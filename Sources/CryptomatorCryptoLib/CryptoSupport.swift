//
//  CryptoSupport.swift
//  CryptomatorCryptoLib
//
//  Created by Tobias Hagemann on 10.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation

protocol CryptoSupport: Sendable {
	/**
	 Creates an array of cryptographically secure random bytes.

	 - Parameter size: The number of random bytes to return in the array.
	 - Returns: An array with cryptographically secure random bytes.
	 */
	func createRandomBytes(size: Int) throws -> [UInt8]
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

struct DefaultCryptoSupport: CryptoSupport {
	func createRandomBytes(size: Int) throws -> [UInt8] {
		var randomBytes = [UInt8](repeating: 0x00, count: size)
		guard SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes) == errSecSuccess else {
			throw CryptoError.csprngError
		}
		return randomBytes
	}
}
