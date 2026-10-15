//
//  MasterkeyTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Sebastian Stenzel on 26.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Testing
@testable import CryptomatorCryptoLib

struct MasterkeyTests {
	@Test func `create from raw`() throws {
		let aesMasterKey = [UInt8](repeating: 0x77, count: 32)
		let macMasterKey = [UInt8](repeating: 0x55, count: 32)
		let masterkey = try Masterkey.createFromRaw(rawKey: aesMasterKey + macMasterKey)
		#expect(aesMasterKey == masterkey.aesMasterKey)
		#expect(macMasterKey == masterkey.macMasterKey)
	}

	@Test(arguments: [0, 32, 63, 65]) func `create from raw with invalid length`(length: Int) {
		#expect(throws: CryptoError.invalidParameter("rawKey must be 64 bytes")) { try Masterkey.createFromRaw(rawKey: [UInt8](repeating: 0x77, count: length)) }
	}
}
