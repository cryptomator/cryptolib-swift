//
//  MasterkeyTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Sebastian Stenzel on 26.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import XCTest
@testable import CryptomatorCryptoLib

class MasterkeyTests: XCTestCase {
	func testCreateFromRaw() throws {
		let aesMasterKey = [UInt8](repeating: 0x77, count: 32)
		let macMasterKey = [UInt8](repeating: 0x55, count: 32)
		let masterkey = Masterkey.createFromRaw(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
		XCTAssertEqual(aesMasterKey, masterkey.aesMasterKey)
		XCTAssertEqual(macMasterKey, masterkey.macMasterKey)
	}
}
