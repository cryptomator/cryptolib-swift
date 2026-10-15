//
//  MasterkeyFileTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 08.01.21.
//  Copyright © 2021 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation
import Testing
@testable import CryptomatorCryptoLib

struct MasterkeyFileTests {
	@Test func `create with content from data`() throws {
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
		#expect(masterkeyFile.content.version == 7)
		#expect(masterkeyFile.content.scryptSalt == "AAAAAAAAAAA=")
		#expect(masterkeyFile.content.scryptCostParam == 2)
		#expect(masterkeyFile.content.scryptBlockSize == 8)
		#expect(masterkeyFile.content.primaryMasterKey == "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==")
		#expect(masterkeyFile.content.hmacMasterKey == "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==")
		#expect(masterkeyFile.content.versionMac == "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=")
	}

	@Test func `unlock with passphrase`() throws {
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
		#expect(expectedKey == masterkey.aesMasterKey)
		#expect(expectedKey == masterkey.macMasterKey)
	}

	@Test func `unlock with wrong passphrase`() throws {
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
		#expect(throws: MasterkeyFileError.invalidPassphrase) { try masterkeyFile.unlock(passphrase: "qwe", pepper: [UInt8]()) }
	}

	@Test(arguments: [
		(makeContent(scryptSalt: "AAAAAAAAAA!!"), "invalid base64 data in scryptSalt"),
		(makeContent(scryptCostParam: -1), "invalid scryptCostParam"),
		(makeContent(scryptCostParam: 1), "invalid scryptCostParam"),
		(makeContent(scryptCostParam: 3), "invalid scryptCostParam"),
		(makeContent(scryptBlockSize: -1), "invalid scryptBlockSize"),
		(makeContent(scryptBlockSize: 0), "invalid scryptBlockSize"),
		(makeContent(scryptCostParam: 1 << 21), "scrypt parameters exceed memory limit"),
		(makeContent(scryptCostParam: 2, scryptBlockSize: 1 << 22), "scrypt parameters exceed memory limit"),
		(makeContent(primaryMasterKey: "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!"), "invalid base64 data in primaryMasterKey"),
		(makeContent(primaryMasterKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "invalid base64 data in primaryMasterKey"),
		(makeContent(hmacMasterKey: "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!"), "invalid base64 data in hmacMasterKey"),
		(makeContent(hmacMasterKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "invalid base64 data in hmacMasterKey"),
		(makeContent(versionMac: "cn2sAK6l"), "invalid base64 data in versionMac"),
		(makeContent(versionMac: "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+G="), "incorrect version or versionMac"),
		(makeContent(version: -1), "invalid version")
	]) func `unlock with malformed content`(content: Content, reason: String) throws {
		let masterkeyFile = MasterkeyFile(content: content)
		#expect(throws: MasterkeyFileError.malformedMasterkeyFile(reason)) { try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()) }
	}

	@Test func `derive key`() throws {
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
		#expect(expectedKey == kek)
	}

	@Test func `unlock with KEK`() throws {
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
		#expect(expectedKey == masterkey.aesMasterKey)
		#expect(expectedKey == masterkey.macMasterKey)
	}

	@Test func lock() throws {
		let content = try MasterkeyFile.lock(masterkey: .test, vaultVersion: 7, passphrase: "asd", pepper: [UInt8](), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		#expect(content.version == 7)
		#expect(content.scryptSalt == "8PDw8PDw8PA=")
		#expect(content.scryptCostParam == 2)
		#expect(content.scryptBlockSize == 8)
		#expect(content.primaryMasterKey == "jvdghkTc01VISrFly37pgaT/UKtXrDCvZcU3tT9Y98zyzn/pJ91bxw==")
		#expect(content.hmacMasterKey == "99I+J4bT3rVpZE8yZwKRV9gHVRmQ8XQEujAL9IuwLTc2D3mg5JEjKA==")
		#expect(content.versionMac == "sAWFgFNhmtMPeNWr4zh+9Ps7GOtT0pknX11PRQ7eC9Q=")
	}

	@Test func `lock with invalid parameters`() {
		#expect(throws: CryptoError.invalidParameter("vaultVersion must be in range 0...\(UInt32.max)")) { try MasterkeyFile.lock(masterkey: .test, vaultVersion: -1, passphrase: "asd") }
		#expect(throws: CryptoError.invalidParameter("scryptCostParam must be a power of 2 greater than 1")) { try MasterkeyFile.lock(masterkey: .test, vaultVersion: 7, passphrase: "asd", scryptCostParam: -1) }
		#expect(throws: CryptoError.invalidParameter("scryptCostParam must be a power of 2 greater than 1")) { try MasterkeyFile.lock(masterkey: .test, vaultVersion: 7, passphrase: "asd", scryptCostParam: 3) }
		#expect(throws: CryptoError.invalidParameter("scryptCostParam exceeds memory limit")) { try MasterkeyFile.lock(masterkey: .test, vaultVersion: 7, passphrase: "asd", scryptCostParam: 1 << 21) }
	}

	@Test func `lock with different peppers`() throws {
		let content1 = try MasterkeyFile.lock(masterkey: .test, vaultVersion: 7, passphrase: "asd", pepper: [UInt8](arrayLiteral: 0x01), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		let content2 = try MasterkeyFile.lock(masterkey: .test, vaultVersion: 7, passphrase: "asd", pepper: [UInt8](arrayLiteral: 0x02), scryptCostParam: 2, cryptoSupport: CryptoSupportMock())
		#expect(content1 != content2)
	}

	@Test func `change passphrase`() throws {
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
		#expect(expectedKey == masterkey.aesMasterKey)
		#expect(expectedKey == masterkey.macMasterKey)
		#expect(throws: MasterkeyFileError.invalidPassphrase) { try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()) }
	}

	@Test func `wrap and unwrap key`() throws {
		let key = [UInt8](repeating: 0x77, count: 32)
		let kek = [UInt8](repeating: 0x55, count: 32)
		let wrapped = try MasterkeyFile.wrapKey(key, kek: kek)
		let unwrapped = try MasterkeyFile.unwrapKey(wrapped, kek: kek)
		#expect(key == unwrapped)
	}

	@Test func `wrap key with invalid key`() throws {
		let key = [UInt8](repeating: 0x77, count: 17)
		let kek = [UInt8](repeating: 0x55, count: 32)
		#expect(throws: MasterkeyFileError.keyWrapFailed(CCCryptorStatus(kCCParamError))) { try MasterkeyFile.wrapKey(key, kek: kek) }
	}

	private static func makeContent(version: Int = 7, scryptSalt: String = "AAAAAAAAAAA=", scryptCostParam: Int = 2, scryptBlockSize: Int = 8, primaryMasterKey: String = "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==", hmacMasterKey: String = "mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==", versionMac: String = "cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=") -> Content {
		return Content(
			version: version,
			scryptSalt: scryptSalt,
			scryptCostParam: scryptCostParam,
			scryptBlockSize: scryptBlockSize,
			primaryMasterKey: primaryMasterKey,
			hmacMasterKey: hmacMasterKey,
			versionMac: versionMac
		)
	}
}
