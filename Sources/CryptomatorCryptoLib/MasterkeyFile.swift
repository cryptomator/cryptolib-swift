//
//  MasterkeyFile.swift
//  CryptomatorCryptoLib
//
//  Created by Tobias Hagemann on 15.12.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation
#if COCOAPODS
import CryptomatorCryptoLib.scrypt
#else
import scrypt
#endif

struct Content: Codable, Equatable {
	let version: Int
	let scryptSalt: String
	let scryptCostParam: Int
	let scryptBlockSize: Int
	let primaryMasterKey: String
	let hmacMasterKey: String
	let versionMac: String
}

public enum MasterkeyFileError: Error, Equatable {
	case malformedMasterkeyFile(_ reason: String)
	case invalidPassphrase
	case keyDerivationFailed
	case keyWrapFailed(_ status: CCCryptorStatus)
}

public class MasterkeyFile {
	public static let defaultScryptCostParam = 1 << 15 // 2^15
	static let defaultScryptSaltSize = 8
	static let defaultScryptBlockSize = 8

	let content: Content
	public var version: Int {
		return content.version
	}

	init(content: Content) {
		self.content = content
	}

	// MARK: - Factory

	/**
	 Creates masterkey file with content provided from URL.

	 - Parameter url: The URL to the masterkey file that is formatted in JSON.
	 - Returns: New masterkey instance using the keys from the supplied `url`.
	 */
	public static func withContentFromURL(url: URL) throws -> MasterkeyFile {
		let data = try Data(contentsOf: url)
		return try withContentFromData(data: data)
	}

	/**
	 Creates masterkey file with content provided from JSON data.

	 - Parameter data: The JSON representation of the masterkey file.
	 - Returns: New masterkey instance using the keys from the supplied `data`.
	 */
	public static func withContentFromData(data: Data) throws -> MasterkeyFile {
		let decoded = try JSONDecoder().decode(Content.self, from: data)
		return MasterkeyFile(content: decoded)
	}

	// MARK: - Actions

	/**
	 Derives a KEK from the given passphrase and the params from this masterkey file using scrypt and unwraps the stored encryption and MAC keys.

	 - Parameter passphrase: The passphrase used during key derivation.
	 - Parameter pepper: An optional application-specific pepper added to the scrypt's salt. Defaults to empty byte array.
	 - Parameter expectedVaultVersion: An optional expected vault version.
	 - Returns: A masterkey with the unwrapped keys.
	 */
	public func unlock(passphrase: String, pepper: [UInt8] = [UInt8](), expectedVaultVersion: Int? = nil) throws -> Masterkey {
		// derive keys:
		let pw = [UInt8](passphrase.precomposedStringWithCanonicalMapping.utf8)
		let salt = [UInt8](Data(base64Encoded: content.scryptSalt)!)
		var kek = [UInt8](repeating: 0x00, count: kCCKeySizeAES256)
		let scryptResult = crypto_scrypt(pw, pw.count, salt + pepper, salt.count + pepper.count, UInt64(content.scryptCostParam), UInt32(content.scryptBlockSize), 1, &kek, kCCKeySizeAES256)
		guard scryptResult == 0 else {
			throw MasterkeyFileError.keyDerivationFailed
		}
		guard let wrappedMasterKey = Data(base64Encoded: content.primaryMasterKey) else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in primaryMasterKey")
		}
		let aesKey = try MasterkeyFile.unwrapKey([UInt8](wrappedMasterKey), kek: kek)
		guard let wrappedHmacKey = Data(base64Encoded: content.hmacMasterKey) else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in hmacMasterKey")
		}
		let macKey = try MasterkeyFile.unwrapKey([UInt8](wrappedHmacKey), kek: kek)

		// check MAC:
		if let expectedVaultVersion = expectedVaultVersion {
			try checkVaultVersion(expectedVaultVersion: expectedVaultVersion, macKey: macKey)
		}

		// construct key:
		return Masterkey.createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey)
	}

	private func checkVaultVersion(expectedVaultVersion: Int, macKey: [UInt8]) throws {
		guard let storedVersionMac = Data(base64Encoded: content.versionMac), storedVersionMac.count == CC_SHA256_DIGEST_LENGTH else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in versionMac")
		}
		var calculatedVersionMac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		let versionBytes = withUnsafeBytes(of: UInt32(version).bigEndian, Array.init)
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), macKey, macKey.count, versionBytes, versionBytes.count, &calculatedVersionMac)
		var diff: UInt8 = 0x00
		for i in 0 ..< calculatedVersionMac.count {
			diff |= calculatedVersionMac[i] ^ storedVersionMac[i]
		}
		if diff != 0x00 {
			throw MasterkeyFileError.malformedMasterkeyFile("incorrect version or versionMac")
		}
	}

	/**
	 Derives a KEK from the given passphrase and wraps the key material from `masterkey`.
	 Then serializes the encrypted keys as well as used key derivation parameters into a JSON representation that can be stored into a masterkey file.

	 - Parameter masterkey: The key to protect.
	 - Parameter vaultVersion: The vault version that should be stored in this masterkey file (for downwards compatibility).
	 - Parameter passphrase: The passphrase used during key derivation.
	 - Parameter pepper: An optional application-specific pepper added to the scrypt's salt. Defaults to empty byte array.
	 - Parameter scryptCostParam: The work factor for the key derivation function (scrypt). Defaults to 32768.
	 - Returns: A JSON representation of the encrypted masterkey with its key derivation parameters.
	 */
	public static func lock(masterkey: Masterkey, vaultVersion: Int, passphrase: String, pepper: [UInt8] = [UInt8](), scryptCostParam: Int = defaultScryptCostParam) throws -> Data {
		let content: Content = try lock(masterkey: masterkey, vaultVersion: vaultVersion, passphrase: passphrase, pepper: pepper, scryptCostParam: scryptCostParam)
		return try JSONEncoder().encode(content)
	}

	static func lock(masterkey: Masterkey, vaultVersion: Int, passphrase: String, pepper: [UInt8], scryptCostParam: Int, cryptoSupport: CryptoSupport = CryptoSupport()) throws -> Content {
		let pw = [UInt8](passphrase.precomposedStringWithCanonicalMapping.utf8)
		let salt = try cryptoSupport.createRandomBytes(size: defaultScryptSaltSize)
		var kek = [UInt8](repeating: 0x00, count: kCCKeySizeAES256)
		let scryptResult = crypto_scrypt(pw, pw.count, salt + pepper, salt.count + pepper.count, UInt64(scryptCostParam), UInt32(defaultScryptBlockSize), 1, &kek, kCCKeySizeAES256)
		guard scryptResult == 0 else {
			throw MasterkeyFileError.keyDerivationFailed
		}

		let wrappedMasterKey = try wrapKey(masterkey.aesMasterKey, kek: kek)
		let wrappedHmacKey = try wrapKey(masterkey.macMasterKey, kek: kek)

		var versionMac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		let versionBytes = withUnsafeBytes(of: UInt32(vaultVersion).bigEndian, Array.init)
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), masterkey.macMasterKey, masterkey.macMasterKey.count, versionBytes, versionBytes.count, &versionMac)

		return Content(
			version: vaultVersion,
			scryptSalt: Data(salt).base64EncodedString(),
			scryptCostParam: scryptCostParam,
			scryptBlockSize: defaultScryptBlockSize,
			primaryMasterKey: Data(wrappedMasterKey).base64EncodedString(),
			hmacMasterKey: Data(wrappedHmacKey).base64EncodedString(),
			versionMac: Data(versionMac).base64EncodedString()
		)
	}

	/**
	 Re-encrypts a masterkey with a new passphrase.

	 - Parameter masterkeyFileData: The original JSON representation of the masterkey.
	 - Parameter oldPassphrase: The old passphrase.
	 - Parameter newPassphrase: The new passphrase
	 - Parameter pepper: An optional application-specific pepper added to the scrypt's salt. Defaults to empty byte array.
	 - Parameter scryptCostParam: The work factor for the key derivation function (scrypt). Defaults to 32768.
	 - Returns: A JSON representation of the masterkey, now encrypted with `newPassphrase`.
	 */
	public static func changePassphrase(masterkeyFileData: Data, oldPassphrase: String, newPassphrase: String, pepper: [UInt8] = [UInt8](), scryptCostParam: Int = defaultScryptCostParam) throws -> Data {
		let content: Content = try changePassphrase(masterkeyFileData: masterkeyFileData, oldPassphrase: oldPassphrase, newPassphrase: newPassphrase, pepper: pepper, scryptCostParam: scryptCostParam)
		return try JSONEncoder().encode(content)
	}

	static func changePassphrase(masterkeyFileData: Data, oldPassphrase: String, newPassphrase: String, pepper: [UInt8], scryptCostParam: Int, cryptoSupport: CryptoSupport = CryptoSupport()) throws -> Content {
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: masterkeyFileData)
		let masterkey = try masterkeyFile.unlock(passphrase: oldPassphrase, pepper: pepper)
		return try MasterkeyFile.lock(masterkey: masterkey, vaultVersion: masterkeyFile.version, passphrase: newPassphrase, pepper: pepper, scryptCostParam: scryptCostParam, cryptoSupport: cryptoSupport)
	}

	// MARK: - RFC 3394 Key Wrapping

	static func wrapKey(_ rawKey: [UInt8], kek: [UInt8]) throws -> [UInt8] {
		var wrappedKeyLen = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), rawKey.count)
		var wrappedKey = [UInt8](repeating: 0x00, count: wrappedKeyLen)
		let status = CCSymmetricKeyWrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, rawKey, rawKey.count, &wrappedKey, &wrappedKeyLen)
		if status == kCCSuccess {
			return wrappedKey
		} else {
			throw MasterkeyFileError.keyWrapFailed(status)
		}
	}

	static func unwrapKey(_ wrappedKey: [UInt8], kek: [UInt8]) throws -> [UInt8] {
		var unwrappedKeyLen = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count)
		var unwrappedKey = [UInt8](repeating: 0x00, count: unwrappedKeyLen)
		let status = CCSymmetricKeyUnwrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, wrappedKey, wrappedKey.count, &unwrappedKey, &unwrappedKeyLen)
		if status == kCCSuccess {
			assert(unwrappedKeyLen == kCCKeySizeAES256)
			return unwrappedKey
		} else if status == kCCDecodeError {
			throw MasterkeyFileError.invalidPassphrase
		} else {
			throw MasterkeyFileError.keyWrapFailed(status)
		}
	}
}
