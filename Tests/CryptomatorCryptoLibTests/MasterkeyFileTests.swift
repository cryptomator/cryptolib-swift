//
//  MasterkeyFileTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 08.01.21.
//  Copyright © 2021 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import XCTest
@testable import CryptomatorCryptoLib

class MasterkeyFileTests: XCTestCase {
	func testCreateWithContentFromData() throws {
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		XCTAssertEqual(7, masterkeyFile.content.version)
		XCTAssertEqual("AAAAAAAAAAA=", masterkeyFile.content.scryptSalt)
		XCTAssertEqual(2, masterkeyFile.content.scryptCostParam)
		XCTAssertEqual(8, masterkeyFile.content.scryptBlockSize)
		XCTAssertEqual("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==", masterkeyFile.content.primaryMasterKey)
		XCTAssertEqual("mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==", masterkeyFile.content.hmacMasterKey)
		XCTAssertEqual("cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=", masterkeyFile.content.versionMac)
	}

	func testUnlockWithPassphrase() throws {
		let expectedKey = [UInt8](repeating: 0x00, count: 32)
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		let masterkey = try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]())
		XCTAssertEqual(expectedKey, masterkey.aesMasterKey)
		XCTAssertEqual(expectedKey, masterkey.macMasterKey)
	}

	func testUnlockWithWrongPassphrase() throws {
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		XCTAssertThrowsError(try masterkeyFile.unlock(passphrase: "qwe", pepper: [UInt8]()), "wrong passphrase") { error in
			XCTAssertEqual(.invalidPassphrase, error as? MasterkeyFileError)
		}
	}

	func testUnlockWithInvalidVersionMac() throws {
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+G="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		XCTAssertThrowsError(try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()), "invalid version mac") { error in
			XCTAssertEqual(.malformedMasterkeyFile("incorrect version or versionMac"), error as? MasterkeyFileError)
		}
	}

	func testUnlockWithMalformedJson1() throws {
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		XCTAssertThrowsError(try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()), "malformed json") { error in
			XCTAssertEqual(.malformedMasterkeyFile("invalid base64 data in primaryMasterKey"), error as? MasterkeyFileError)
		}
	}

	func testUnlockWithMalformedJson2() throws {
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		XCTAssertThrowsError(try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()), "malformed json") { error in
			XCTAssertEqual(.malformedMasterkeyFile("invalid base64 data in hmacMasterKey"), error as? MasterkeyFileError)
		}
	}

	func testUnlockWithMalformedJson3() throws {
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l"
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		XCTAssertThrowsError(try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()), "malformed json") { error in
			XCTAssertEqual(.malformedMasterkeyFile("invalid base64 data in versionMac"), error as? MasterkeyFileError)
		}
	}

	func testDeriveKey() throws {
		let expectedKey: [UInt8] = [
			0x8C, 0xF4, 0xA0, 0x4E, 0xC8, 0x45, 0xF4, 0x28,
			0xB2, 0xF9, 0xF9, 0xE1, 0xD9, 0xDF, 0x08, 0xD2,
			0x62, 0x11, 0xD9, 0xAF, 0xE2, 0xF5, 0x5F, 0xDE,
			0xDF, 0xCB, 0xB5, 0xE7, 0x5A, 0xEF, 0x34, 0xF9
		]
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		let kek = try masterkeyFile.deriveKey(passphrase: "asd", pepper: [UInt8]())
		XCTAssertEqual(expectedKey, kek)
	}

	func testUnlockWithKEK() throws {
		let expectedKey = [UInt8](repeating: 0x00, count: 32)
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: data)
		let kek: [UInt8] = [
			0x8C, 0xF4, 0xA0, 0x4E, 0xC8, 0x45, 0xF4, 0x28,
			0xB2, 0xF9, 0xF9, 0xE1, 0xD9, 0xDF, 0x08, 0xD2,
			0x62, 0x11, 0xD9, 0xAF, 0xE2, 0xF5, 0x5F, 0xDE,
			0xDF, 0xCB, 0xB5, 0xE7, 0x5A, 0xEF, 0x34, 0xF9
		]
		let masterkey = try masterkeyFile.unlock(kek: kek)
		XCTAssertEqual(expectedKey, masterkey.aesMasterKey)
		XCTAssertEqual(expectedKey, masterkey.macMasterKey)
	}

	func testLock() throws {
		let masterkey = Masterkey.createFromRaw(aesMasterKey: [UInt8](repeating: 0x55, count: 32), macMasterKey: [UInt8](repeating: 0x77, count: 32))
		let content = try MasterkeyFile.lock(masterkey: masterkey, vaultVersion: 7, passphrase: "asd", pepper: [UInt8](), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		XCTAssertEqual(7, content.version)
		XCTAssertEqual("8PDw8PDw8PA=", content.scryptSalt)
		XCTAssertEqual(2, content.scryptCostParam)
		XCTAssertEqual(8, content.scryptBlockSize)
		XCTAssertEqual("jvdghkTc01VISrFly37pgaT/UKtXrDCvZcU3tT9Y98zyzn/pJ91bxw==", content.primaryMasterKey)
		XCTAssertEqual("99I+J4bT3rVpZE8yZwKRV9gHVRmQ8XQEujAL9IuwLTc2D3mg5JEjKA==", content.hmacMasterKey)
		XCTAssertEqual("sAWFgFNhmtMPeNWr4zh+9Ps7GOtT0pknX11PRQ7eC9Q=", content.versionMac)
	}

	func testLockWithDifferentPeppers() throws {
		let masterkey = Masterkey.createFromRaw(aesMasterKey: [UInt8](repeating: 0x55, count: 32), macMasterKey: [UInt8](repeating: 0x77, count: 32))
		let content1 = try MasterkeyFile.lock(masterkey: masterkey, vaultVersion: 7, passphrase: "asd", pepper: [UInt8](arrayLiteral: 0x01), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		let content2 = try MasterkeyFile.lock(masterkey: masterkey, vaultVersion: 7, passphrase: "asd", pepper: [UInt8](arrayLiteral: 0x02), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		XCTAssertNotEqual(content1, content2)
	}

	func testChangePassphrase() throws {
		let expectedKey = [UInt8](repeating: 0x00, count: 32)
		let data = Data("""
		{
			"version": 7,
			"scryptSalt": "AAAAAAAAAAA=",
			"scryptCostParam": 2,
			"scryptBlockSize": 8,
			"primaryMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"hmacMasterKey": "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==",
			"versionMac": "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g="
		}
		""".utf8)
		let content = try MasterkeyFile.changePassphrase(masterkeyFileData: data, oldPassphrase: "asd", newPassphrase: "qwe", pepper: [UInt8](), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		let masterkeyFile = MasterkeyFile(content: content)
		let masterkey = try masterkeyFile.unlock(passphrase: "qwe", pepper: [UInt8]())
		XCTAssertEqual(expectedKey, masterkey.aesMasterKey)
		XCTAssertEqual(expectedKey, masterkey.macMasterKey)
		XCTAssertThrowsError(try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()), "wrong passphrase") { error in
			XCTAssertEqual(.invalidPassphrase, error as? MasterkeyFileError)
		}
	}

	func testWrapAndUnwrapKey() throws {
		let key = [UInt8](repeating: 0x77, count: 32)
		let kek = [UInt8](repeating: 0x55, count: 32)
		let wrapped = try MasterkeyFile.wrapKey(key, kek: kek)
		let unwrapped = try MasterkeyFile.unwrapKey(wrapped, kek: kek)
		XCTAssertEqual(key, unwrapped)
	}

	func testWrapKeyWithInvalidKey() throws {
		let key = [UInt8](repeating: 0x77, count: 17)
		let kek = [UInt8](repeating: 0x55, count: 32)
		XCTAssertThrowsError(try MasterkeyFile.wrapKey(key, kek: kek), "invalid key") { error in
			XCTAssertEqual(.keyWrapFailed(CCCryptorStatus(kCCParamError)), error as? MasterkeyFileError)
		}
	}
}
