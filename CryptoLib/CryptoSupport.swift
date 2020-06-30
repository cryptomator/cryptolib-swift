//
//  CryptoSupport.swift
//  CryptoLib
//
//  Created by Tobias Hagemann on 10.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation

internal class CryptoSupport {
	/**
	 Creates an array of cryptographically secure random bytes.

	 - Parameter size: The number of random bytes to return in the array.
	 - Returns: An array with cryptographically secure random bytes.
	 */
	func createRandomBytes(size: Int) throws -> [UInt8] {
		var randomBytes = [UInt8](repeating: 0x00, count: size)
		guard SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes) == errSecSuccess else {
			throw CryptoError.csprngError
		}
		return randomBytes
	}

	/**
	 Compares byte arrays in constant-time.

	 The running time of this method is independent of the byte arrays compared, making it safe to use for comparing secret values such as cryptographic MACs.

	 The byte arrays are expected to be of same length.

	 - Parameter expected: Expected bytes for comparison.
	 - Parameter actual: Actual bytes for comparison.
	 - Returns: `true` if `expected` and `actual` are equal, otherwise `false`.
	 */
	func compareBytes(expected: [UInt8], actual: [UInt8]) -> Bool {
		assert(expected.count == actual.count, "parameters should be of same length")
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
