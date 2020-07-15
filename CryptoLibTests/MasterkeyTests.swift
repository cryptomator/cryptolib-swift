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

		let masterkey = try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd")

		XCTAssertNotNil(masterkey)
		XCTAssertEqual(7, masterkey.version)
		XCTAssertEqual(expectedKeys, masterkey.aesMasterKey)
		XCTAssertEqual(expectedKeys, masterkey.macMasterKey)
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

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "qwe"), "invalid password") { error in
			XCTAssertEqual(MasterkeyError.invalidPassword, error as? MasterkeyError)
		}
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

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password") { error in
			XCTAssertEqual(MasterkeyError.malformedMasterkeyFile("incorrect version or versionMac"), error as? MasterkeyError)
		}
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

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password") { error in
			XCTAssertEqual(MasterkeyError.malformedMasterkeyFile("invalid base64 data in primaryMasterKey"), error as? MasterkeyError)
		}
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

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password") { error in
			XCTAssertEqual(MasterkeyError.malformedMasterkeyFile("invalid base64 data in hmacMasterKey"), error as? MasterkeyError)
		}
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

		XCTAssertThrowsError(try Masterkey.createFromMasterkeyFile(jsonData: jsonData, password: "asd"), "invalid password") { error in
			XCTAssertEqual(MasterkeyError.malformedMasterkeyFile("invalid base64 data in versionMac"), error as? MasterkeyError)
		}
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

	func testExportEncrypted() throws {
		let masterkey = Masterkey.createFromRaw(aesMasterKey: [UInt8](repeating: 0x55, count: 32), macMasterKey: [UInt8](repeating: 0x77, count: 32), version: 7)
		let json = try masterkey.exportEncrypted(password: "asd", pepper: [UInt8](), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		XCTAssertEqual("8PDw8PDw8PA=", json.scryptSalt)
		XCTAssertEqual(2, json.scryptCostParam)
		XCTAssertEqual(8, json.scryptBlockSize)
		XCTAssertEqual("jvdghkTc01VISrFly37pgaT/UKtXrDCvZcU3tT9Y98zyzn/pJ91bxw==", json.primaryMasterKey)
		XCTAssertEqual("99I+J4bT3rVpZE8yZwKRV9gHVRmQ8XQEujAL9IuwLTc2D3mg5JEjKA==", json.hmacMasterKey)
		XCTAssertEqual("sAWFgFNhmtMPeNWr4zh+9Ps7GOtT0pknX11PRQ7eC9Q=", json.versionMac)
		XCTAssertEqual(7, json.version)
	}
}
