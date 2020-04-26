//
//  MasterkeyTests.swift
//  CryptoLibTests
//
//  Created by Sebastian Stenzel on 26.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import XCTest
@testable import CryptoLib

class MasterkeyTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
	
	func testWrapAndUnwrapKey() {
		let rawKey = [UInt8](repeating: 0x77, count: 32)
		let kek = [UInt8](repeating: 0x55, count: 32)
		let wrapped = Masterkey.wrapMasterKey(rawKey: rawKey, kek: kek)
		XCTAssertNotNil(wrapped)
		let unwrapped = Masterkey.unwrapMasterKey(wrappedKey: wrapped!, kek: kek)
		XCTAssertNotNil(unwrapped)
		XCTAssertEqual(rawKey, unwrapped)
	}

    func testCreateFromMasterkeyFile() {
		let expectedKeys = [UInt8](repeating: 0x00, count: 32)
		let jsonData = """
		{
			"version": 3,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA="
		}
		""".data(using: .utf8)!
		
		let masterKey = Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd")
		
		XCTAssertNotNil(masterKey)
		XCTAssertEqual(expectedKeys, masterKey?.aesMasterKey)
		XCTAssertEqual(expectedKeys, masterKey?.macMasterKey)
    }

}
