//
//  CryptoSupport.swift
//  CryptoLib
//
//  Created by Tobias Hagemann on 10.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation

class CryptoSupport {
	func createRandomBytes(size: Int) throws -> [UInt8] {
		var randomBytes = [UInt8](repeating: 0x00, count: size)
		guard SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes) == errSecSuccess else {
			throw CryptoError.csprngError
		}
		return randomBytes
	}

	/**
	 Constant-time comparison
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
