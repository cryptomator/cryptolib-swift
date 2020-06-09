//
//  CSPRNG.swift
//  CryptoLib
//
//  Created by Tobias Hagemann on 09.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation

class CSPRNG {
	func createRandomBytes(size: Int) throws -> [UInt8] {
		var randomBytes = [UInt8](repeating: 0x00, count: size)
		guard SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes) == errSecSuccess else {
			throw CryptoError.csprngError
		}
		return randomBytes
	}
}
