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
	
	func testEncryptDirId() {
		let cryptor = Cryptor.init(masterKey: masterkey)
		
		let rootDir = cryptor.encryptDirId("")
		XCTAssertEqual("VLWEHT553J5DR7OZLRJAYDIWFCXZABOD", rootDir)

		let testDir = cryptor.encryptDirId("918acfbd-a467-3f77-93f1-f4a44f9cfe9c")
		XCTAssertEqual("7C3USOO3VU7IVQRKFMRFV3QE4VEZJECV", testDir)
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
