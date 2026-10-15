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

	@Test func `unlock with invalid version mac`() throws {
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
		#expect(throws: MasterkeyFileError.malformedMasterkeyFile("incorrect version or versionMac")) { try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()) }
	}

	@Test func `unlock with malformed json 1`() throws {
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
		#expect(throws: MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in primaryMasterKey")) { try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()) }
	}

	@Test func `unlock with malformed json 2`() throws {
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
		#expect(throws: MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in hmacMasterKey")) { try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()) }
	}

	@Test func `unlock with malformed json 3`() throws {
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
		#expect(throws: MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in versionMac")) { try masterkeyFile.unlock(passphrase: "asd", pepper: [UInt8]()) }
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
}
