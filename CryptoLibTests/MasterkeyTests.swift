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
	
	func testWrapAndUnwrapKey() throws {
		let rawKey = [UInt8](repeating: 0x77, count: 32)
		let kek = [UInt8](repeating: 0x55, count: 32)
		let wrapped = try Masterkey.wrapMasterKey(rawKey: rawKey, kek: kek)
		XCTAssertNotNil(wrapped)
		let unwrapped = try Masterkey.unwrapMasterKey(wrappedKey: wrapped, kek: kek)
		XCTAssertNotNil(unwrapped)
		XCTAssertEqual(rawKey, unwrapped)
	}

    func testCreateFromMasterkeyFile() throws {
		let expectedKeys = [UInt8](repeating: 0x00, count: 32)
		let jsonData = """
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".data(using: .utf8)!
		
		let masterKey = try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd")
		
		XCTAssertNotNil(masterKey)
		XCTAssertEqual(expectedKeys, masterKey.aesMasterKey)
		XCTAssertEqual(expectedKeys, masterKey.macMasterKey)
    }
	
	func testCreateFromMasterkeyFileWithWrongPassword() throws {
		let jsonData = """
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".data(using: .utf8)!

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "qwe"), "invalid password", { error in
			XCTAssertEqual(error as! MasterkeyError, MasterkeyError.invalidPassword)
		})
    }
	
	func testCreateFromMasterkeyFileWithInvalidVersionMac() throws {
		let jsonData = """
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+G="
		}
		""".data(using: .utf8)!

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password", { error in
			XCTAssertEqual(error as! MasterkeyError, MasterkeyError.malformedMasterkeyFile("incorrect version or versionMac"))
		})
    }
	
	func testCreateFromMasterkeyFileWithMalformedJson1() throws {
		let jsonData = """
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".data(using: .utf8)!

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password", { error in
			XCTAssertEqual(error as! MasterkeyError, MasterkeyError.malformedMasterkeyFile("invalid base64 data in primaryMasterKey"))
		})
    }
	
	func testCreateFromMasterkeyFileWithMalformedJson2() throws {
		let jsonData = """
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".data(using: .utf8)!

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password", { error in
			XCTAssertEqual(error as! MasterkeyError, MasterkeyError.malformedMasterkeyFile("invalid base64 data in hmacMasterKey"))
		})
    }
	
	func testCreateFromMasterkeyFileWithMalformedJson3() throws {
		let jsonData = """
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l"
		}
		""".data(using: .utf8)!

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password", { error in
			XCTAssertEqual(error as! MasterkeyError, MasterkeyError.malformedMasterkeyFile("invalid base64 data in versionMac"))
		})
    }

}
