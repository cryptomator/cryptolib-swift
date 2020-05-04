//
//  CryptorTests.swift
//  CryptoLibTests
//
//  Created by Sebastian Stenzel on 27.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import XCTest
@testable import CryptoLib

class CryptorTests: XCTestCase {
	
	var masterkey: Masterkey!

    override func setUp() {
		let aesKey: [UInt8] = Array(repeating: 0x55, count: 32)
		let macKey: [UInt8] = Array(repeating: 0x77, count: 32)
		masterkey = Masterkey.createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey)
		
		XCTAssertNotNil(masterkey)
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testEncryptAndDecryptName() {
		continueAfterFailure = false
		
		let cryptor = Cryptor.init(masterKey: masterkey)
		let dirId = "foo".data(using: .utf8)!
		let originalName = "hello.txt"
		
		let ciphertextName = cryptor.encryptFileName(originalName, dirId: dirId)
		XCTAssertNotNil(ciphertextName)
		
		let cleartextName = cryptor.decryptFileName(ciphertextName!, dirId: dirId)
		XCTAssertNotNil(cleartextName)
		XCTAssertEqual(originalName, cleartextName!)
		
    }


}
