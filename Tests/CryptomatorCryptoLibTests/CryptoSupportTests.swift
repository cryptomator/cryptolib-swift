//
//  CryptoSupportTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 15.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Testing
@testable import CryptomatorCryptoLib

struct CryptoSupportTests {
	@Test(arguments: [
		([], [0x00]),
		([0x00], []),
		([0x01, 0x02], [0x01, 0x02, 0x03]),
		([0x01, 0x02, 0x03], [0x01, 0x02])
	]) func `compare bytes of different lengths`(expected: [UInt8], actual: [UInt8]) {
		#expect(!compareBytes(expected: expected, actual: actual))
	}
}
