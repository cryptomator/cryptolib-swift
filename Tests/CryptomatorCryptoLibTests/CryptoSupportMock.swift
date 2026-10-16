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
	func fillRandomBytes(_ buffer: UnsafeMutableRawBufferPointer) throws {
		buffer.initializeMemory(as: UInt8.self, repeating: 0xF0)
	}
}
