//
//  CryptoSupportMock.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 08.01.21.
//  Copyright © 2021 Skymatic GmbH. All rights reserved.
//

import Foundation
@testable import CryptomatorCryptoLib

struct CryptoSupportMock: CryptoSupport {
	func createRandomBytes(size: Int) throws -> [UInt8] {
		return [UInt8](repeating: 0xF0, count: size)
	}
}
