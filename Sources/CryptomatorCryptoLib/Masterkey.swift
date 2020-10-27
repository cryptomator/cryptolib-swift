//
//  Masterkey.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import CryptoSwift
import Foundation

struct MasterkeyJson: Codable {
	let scryptSalt: String
	let scryptCostParam: Int
	let scryptBlockSize: Int
	let primaryMasterKey: String
	let hmacMasterKey: String
	let versionMac: String
	let version: Int
}

public enum MasterkeyError: Error, Equatable {
	case malformedMasterkeyFile(_ reason: String)
	case invalidPassword
	case unwrapFailed(_ status: CCCryptorStatus)
	case wrapFailed(_ status: CCCryptorStatus)
}

public class Masterkey {
	public static let defaultScryptCostParam = 1 << 15 // 2^15
	static let defaultScryptSaltSize = 8
	static let defaultScryptBlockSize = 8
	static let latestVersion = 7

	private(set) var aesMasterKey: [UInt8]
	private(set) var macMasterKey: [UInt8]
	public let version: Int

	private init(aesMasterKey: [UInt8], macMasterKey: [UInt8], version: Int) {
		self.aesMasterKey = aesMasterKey
		self.macMasterKey = macMasterKey
		self.version = version
	}

	deinit {
		for i in 0 ..< aesMasterKey.count {
			aesMasterKey[i] = 0
		}
		for i in 0 ..< macMasterKey.count {
			macMasterKey[i] = 0
		}
	}

	// MARK: - Factory

	/**
	 Creates new masterkey.

	 - Returns: New masterkey instance with secure random bytes. Version will be set to the latest version (currently 7).
	 */
	public static func createNew() throws -> Masterkey {
		let cryptoSupport = CryptoSupport()
		let aesMasterKey = try cryptoSupport.createRandomBytes(size: kCCKeySizeAES256)
		let macMasterKey = try cryptoSupport.createRandomBytes(size: kCCKeySizeAES256)
		return createFromRaw(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey, version: latestVersion)
	}

	/**
	 Creates masterkey from masterkey file.

	 - Parameter fileURL: The URL to the masterkey file that is formatted in JSON.
	 - Parameter password: The password to use for decrypting the masterkey file.
	 - Parameter pepper: An application-specific pepper added to the salt during key derivation. Defaults to empty byte array.
	 - Returns: New masterkey instance using the keys from the supplied `fileURL`.
	 */
	public static func createFromMasterkeyFile(fileURL: URL, password: String, pepper: [UInt8] = [UInt8]()) throws -> Masterkey {
		let jsonData = try Data(contentsOf: fileURL)
		return try createFromMasterkeyFile(jsonData: jsonData, password: password, pepper: pepper)
	}

	/**
	 Creates masterkey from masterkey JSON data.

	 - Parameter jsonData: The JSON data of the masterkey file.
	 - Parameter password: The password to use for decrypting the masterkey file.
	 - Parameter pepper: An application-specific pepper added to the salt during key derivation. Defaults to empty byte array.
	 - Returns: New masterkey instance using the keys from the supplied `jsonData`.
	 */
	public static func createFromMasterkeyFile(jsonData: Data, password: String, pepper: [UInt8] = [UInt8]()) throws -> Masterkey {
		let decoded = try JSONDecoder().decode(MasterkeyJson.self, from: jsonData)
		return try createFromMasterkeyFile(jsonData: decoded, password: password, pepper: pepper)
	}

	private static func createFromMasterkeyFile(jsonData: MasterkeyJson, password: String, pepper: [UInt8]) throws -> Masterkey {
		let pw = [UInt8](password.precomposedStringWithCanonicalMapping.utf8)
		let salt = [UInt8](Data(base64Encoded: jsonData.scryptSalt)!)
		let saltAndPepper = salt + pepper
		let kek = try Scrypt(password: pw, salt: saltAndPepper, dkLen: kCCKeySizeAES256, N: jsonData.scryptCostParam, r: jsonData.scryptBlockSize, p: 1).calculate()

		guard let wrappedMasterKey = Data(base64Encoded: jsonData.primaryMasterKey) else {
			throw MasterkeyError.malformedMasterkeyFile("invalid base64 data in primaryMasterKey")
		}
		let aesKey = try unwrapMasterKey(wrappedKey: wrappedMasterKey.bytes, kek: kek)

		guard let wrappedHmacKey = Data(base64Encoded: jsonData.hmacMasterKey) else {
			throw MasterkeyError.malformedMasterkeyFile("invalid base64 data in hmacMasterKey")
		}
		let macKey = try unwrapMasterKey(wrappedKey: wrappedHmacKey.bytes, kek: kek)

		// time-constant version MAC check:
		guard let storedVersionMac = Data(base64Encoded: jsonData.versionMac), storedVersionMac.count == CC_SHA256_DIGEST_LENGTH else {
			throw MasterkeyError.malformedMasterkeyFile("invalid base64 data in versionMac")
		}
		var calculatedVersionMac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		let versionBytes = withUnsafeBytes(of: UInt32(jsonData.version).bigEndian, Array.init)
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), macKey, macKey.count, versionBytes, versionBytes.count, &calculatedVersionMac)
		var diff: UInt8 = 0x00
		for i in 0 ..< calculatedVersionMac.count {
			diff |= calculatedVersionMac[i] ^ storedVersionMac[i]
		}
		if diff != 0x00 {
			throw MasterkeyError.malformedMasterkeyFile("incorrect version or versionMac")
		}

		return createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey, version: jsonData.version)
	}

	static func createFromRaw(aesMasterKey: [UInt8], macMasterKey: [UInt8], version: Int) -> Masterkey {
		assert(aesMasterKey.count == kCCKeySizeAES256)
		assert(macMasterKey.count == kCCKeySizeAES256)
		return Masterkey(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey, version: version)
	}

	// MARK: - RFC 3394 Key Wrapping

	static func wrapMasterKey(rawKey: [UInt8], kek: [UInt8]) throws -> [UInt8] {
		assert(kek.count == kCCKeySizeAES256)
		var wrappedKeyLen = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), rawKey.count)
		var wrappedKey = [UInt8](repeating: 0x00, count: wrappedKeyLen)
		let status = CCSymmetricKeyWrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, rawKey, rawKey.count, &wrappedKey, &wrappedKeyLen)
		if status == kCCSuccess {
			return wrappedKey
		} else {
			throw MasterkeyError.wrapFailed(status)
		}
	}

	static func unwrapMasterKey(wrappedKey: [UInt8], kek: [UInt8]) throws -> [UInt8] {
		assert(kek.count == kCCKeySizeAES256)
		var unwrappedKeyLen = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count)
		var unwrappedKey = [UInt8](repeating: 0x00, count: unwrappedKeyLen)
		let status = CCSymmetricKeyUnwrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, wrappedKey, wrappedKey.count, &unwrappedKey, &unwrappedKeyLen)
		if status == kCCSuccess {
			assert(unwrappedKeyLen == kCCKeySizeAES256)
			return unwrappedKey
		} else if status == kCCDecodeError {
			throw MasterkeyError.invalidPassword
		} else {
			throw MasterkeyError.unwrapFailed(status)
		}
	}

	// MARK: - Export

	/**
	 Exports encrypted/wrapped masterkey and other metadata as JSON data.

	 - Parameter password: The password used to encrypt the key material.
	 - Parameter pepper: An application-specific pepper added to the salt during key derivation. Defaults to empty byte array.
	 - Parameter scryptCostParam: The work factor for the key derivation function (scrypt). Defaults to 32768.
	 - Returns: JSON data with encrypted/wrapped masterkey and other metadata that can be stored in insecure locations.
	 */
	public func exportEncrypted(password: String, pepper: [UInt8] = [UInt8](), scryptCostParam: Int = Masterkey.defaultScryptCostParam) throws -> Data {
		let masterkeyJson: MasterkeyJson = try exportEncrypted(password: password, pepper: pepper, scryptCostParam: scryptCostParam)
		return try JSONEncoder().encode(masterkeyJson)
	}

	func exportEncrypted(password: String, pepper: [UInt8], scryptCostParam: Int, cryptoSupport: CryptoSupport = CryptoSupport()) throws -> MasterkeyJson {
		let pw = [UInt8](password.precomposedStringWithCanonicalMapping.utf8)
		let salt = try cryptoSupport.createRandomBytes(size: Masterkey.defaultScryptSaltSize)
		let saltAndPepper = salt + pepper
		let kek = try Scrypt(password: pw, salt: saltAndPepper, dkLen: kCCKeySizeAES256, N: scryptCostParam, r: Masterkey.defaultScryptBlockSize, p: 1).calculate()

		let wrappedMasterKey = try Masterkey.wrapMasterKey(rawKey: aesMasterKey, kek: kek)
		let wrappedHmacKey = try Masterkey.wrapMasterKey(rawKey: macMasterKey, kek: kek)

		var versionMac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		let versionBytes = withUnsafeBytes(of: UInt32(version).bigEndian, Array.init)
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), macMasterKey, macMasterKey.count, versionBytes, versionBytes.count, &versionMac)

		return MasterkeyJson(
			scryptSalt: Data(salt).base64EncodedString(),
			scryptCostParam: scryptCostParam,
			scryptBlockSize: Masterkey.defaultScryptBlockSize,
			primaryMasterKey: Data(wrappedMasterKey).base64EncodedString(),
			hmacMasterKey: Data(wrappedHmacKey).base64EncodedString(),
			versionMac: Data(versionMac).base64EncodedString(),
			version: version
		)
	}
}
