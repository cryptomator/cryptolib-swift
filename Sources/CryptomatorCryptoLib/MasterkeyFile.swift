//
//  MasterkeyFile.swift
//  CryptomatorCryptoLib
//
//  Created by Tobias Hagemann on 15.12.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation
import scrypt

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

public final class MasterkeyFile: Sendable {
	public static let defaultScryptCostParam = 1 << 15 // 2^15
	static let defaultScryptSaltSize = 8
	static let defaultScryptBlockSize = 8
	private static let wrappedKeySize = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), kCCKeySizeAES256)

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

	 - Parameter passphrase: The passphrase used during key derivation. The library cannot wipe the string.
	 - Parameter pepper: An optional application-specific pepper added to the scrypt's salt. Defaults to empty byte array. The bytes are copied and never retained.
	 - Returns: A masterkey with the unwrapped keys.
	 */
	public func unlock(passphrase: String, pepper: [UInt8] = [UInt8]()) throws -> Masterkey {
		let kek = try deriveSecretKey(passphrase: passphrase, pepper: pepper)
		return try unlock(kek: kek)
	}

	/**
	 Derives a KEK from the given passphrase and the params from this masterkey file using scrypt.

	 - Parameter passphrase: The passphrase used during key derivation. The library cannot wipe the string.
	 - Parameter pepper: An optional application-specific pepper added to the scrypt's salt. Defaults to empty byte array. The bytes are copied and never retained.
	 - Returns: A copy of the 256-bit key derived from passphrase using scrypt. The returned array belongs to the caller, and the library cannot wipe it.
	 */
	public func deriveKey(passphrase: String, pepper: [UInt8] = [UInt8]()) throws -> [UInt8] {
		return try deriveSecretKey(passphrase: passphrase, pepper: pepper).exportBytes()
	}

	private func deriveSecretKey(passphrase: String, pepper: [UInt8]) throws -> SecretBytes {
		guard let salt = Data(base64Encoded: content.scryptSalt) else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in scryptSalt")
		}
		guard let scryptCostParam = UInt64(exactly: content.scryptCostParam), MasterkeyFile.isValidScryptCostParam(scryptCostParam) else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid scryptCostParam")
		}
		guard let scryptBlockSize = UInt32(exactly: content.scryptBlockSize), scryptBlockSize > 0 else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid scryptBlockSize")
		}
		guard MasterkeyFile.isWithinScryptMemoryLimit(scryptCostParam: scryptCostParam, scryptBlockSize: scryptBlockSize) else {
			throw MasterkeyFileError.malformedMasterkeyFile("scrypt parameters exceed memory limit")
		}
		return try MasterkeyFile.scrypt(passphrase: passphrase, salt: [UInt8](salt), pepper: pepper, scryptCostParam: scryptCostParam, scryptBlockSize: scryptBlockSize)
	}

	/**
	  Unwraps the stored encryption and MAC keys with the given KEK.

	  - Parameter kek: The KEK for unwrapping the keys from this masterkey file. The bytes are copied and never retained, so wiping `kek` remains the caller's responsibility.
	  - Returns: A masterkey with the unwrapped keys.
	 */
	public func unlock(kek: [UInt8]) throws -> Masterkey {
		return try unlock(kek: SecretBytes(copying: kek))
	}

	private func unlock(kek: borrowing SecretBytes) throws -> Masterkey {
		guard let wrappedMasterKey = Data(base64Encoded: content.primaryMasterKey), wrappedMasterKey.count == MasterkeyFile.wrappedKeySize else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in primaryMasterKey")
		}
		let aesKey = try MasterkeyFile.unwrapKey([UInt8](wrappedMasterKey), kek: kek)
		guard let wrappedHmacKey = Data(base64Encoded: content.hmacMasterKey), wrappedHmacKey.count == MasterkeyFile.wrappedKeySize else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in hmacMasterKey")
		}
		let macKey = try MasterkeyFile.unwrapKey([UInt8](wrappedHmacKey), kek: kek)

		// check MAC:
		try checkVaultVersion(macKey: macKey)

		// construct key:
		return Masterkey.createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey)
	}

	private func checkVaultVersion(macKey: borrowing SecretBytes) throws {
		guard let storedVersionMac = Data(base64Encoded: content.versionMac), storedVersionMac.count == CC_SHA256_DIGEST_LENGTH else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid base64 data in versionMac")
		}
		guard let unsignedVersion = UInt32(exactly: version) else {
			throw MasterkeyFileError.malformedMasterkeyFile("invalid version")
		}
		let calculatedVersionMac = MasterkeyFile.versionMac(version: unsignedVersion, macKey: macKey)
		guard compareBytes(expected: calculatedVersionMac, actual: [UInt8](storedVersionMac)) else {
			throw MasterkeyFileError.malformedMasterkeyFile("incorrect version or versionMac")
		}
	}

	/**
	 Derives a KEK from the given passphrase and wraps the key material from `masterkey`.
	 Then serializes the encrypted keys as well as used key derivation parameters into a JSON representation that can be stored into a masterkey file.

	 - Parameter masterkey: The key to protect.
	 - Parameter vaultVersion: The vault version that should be stored in this masterkey file (for downwards compatibility).
	 - Parameter passphrase: The passphrase used during key derivation. The library cannot wipe the string.
	 - Parameter pepper: An optional application-specific pepper added to the scrypt's salt. Defaults to empty byte array. The bytes are copied and never retained.
	 - Parameter scryptCostParam: The work factor for the key derivation function (scrypt). Must be a power of 2 from 2 to 2^20. Defaults to 32768.
	 - Returns: A JSON representation of the encrypted masterkey with its key derivation parameters.
	 */
	public static func lock(masterkey: Masterkey, vaultVersion: Int, passphrase: String, pepper: [UInt8] = [UInt8](), scryptCostParam: Int = defaultScryptCostParam) throws -> Data {
		let content: Content = try lock(masterkey: masterkey, vaultVersion: vaultVersion, passphrase: passphrase, pepper: pepper, scryptCostParam: scryptCostParam)
		return try JSONEncoder().encode(content)
	}

	static func lock(masterkey: Masterkey, vaultVersion: Int, passphrase: String, pepper: [UInt8], scryptCostParam: Int, cryptoSupport: CryptoSupport = DefaultCryptoSupport()) throws -> Content {
		guard let unsignedVaultVersion = UInt32(exactly: vaultVersion) else {
			throw CryptoError.invalidParameter("vaultVersion must be in range 0...\(UInt32.max)")
		}
		guard let unsignedScryptCostParam = UInt64(exactly: scryptCostParam), isValidScryptCostParam(unsignedScryptCostParam) else {
			throw CryptoError.invalidParameter("scryptCostParam must be a power of 2 greater than 1")
		}
		guard isWithinScryptMemoryLimit(scryptCostParam: unsignedScryptCostParam, scryptBlockSize: UInt32(defaultScryptBlockSize)) else {
			throw CryptoError.invalidParameter("scryptCostParam exceeds memory limit")
		}
		let salt = try cryptoSupport.createRandomBytes(size: defaultScryptSaltSize)
		let kek = try scrypt(passphrase: passphrase, salt: salt, pepper: pepper, scryptCostParam: unsignedScryptCostParam, scryptBlockSize: UInt32(defaultScryptBlockSize))

		let wrappedMasterKey = try wrapKey(masterkey.aesMasterKey, kek: kek)
		let wrappedHmacKey = try wrapKey(masterkey.macMasterKey, kek: kek)
		let versionMac = MasterkeyFile.versionMac(version: unsignedVaultVersion, macKey: masterkey.macMasterKey)

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
	 - Parameter oldPassphrase: The old passphrase. The library cannot wipe the string.
	 - Parameter newPassphrase: The new passphrase. The library cannot wipe the string.
	 - Parameter pepper: An optional application-specific pepper added to the scrypt's salt. Defaults to empty byte array. The bytes are copied and never retained.
	 - Parameter scryptCostParam: The work factor for the key derivation function (scrypt). Must be a power of 2 from 2 to 2^20. Defaults to 32768.
	 - Returns: A JSON representation of the masterkey, now encrypted with `newPassphrase`.
	 */
	public static func changePassphrase(masterkeyFileData: Data, oldPassphrase: String, newPassphrase: String, pepper: [UInt8] = [UInt8](), scryptCostParam: Int = defaultScryptCostParam) throws -> Data {
		let content: Content = try changePassphrase(masterkeyFileData: masterkeyFileData, oldPassphrase: oldPassphrase, newPassphrase: newPassphrase, pepper: pepper, scryptCostParam: scryptCostParam)
		return try JSONEncoder().encode(content)
	}

	static func changePassphrase(masterkeyFileData: Data, oldPassphrase: String, newPassphrase: String, pepper: [UInt8], scryptCostParam: Int, cryptoSupport: CryptoSupport = DefaultCryptoSupport()) throws -> Content {
		let masterkeyFile = try MasterkeyFile.withContentFromData(data: masterkeyFileData)
		let masterkey = try masterkeyFile.unlock(passphrase: oldPassphrase, pepper: pepper)
		return try MasterkeyFile.lock(masterkey: masterkey, vaultVersion: masterkeyFile.version, passphrase: newPassphrase, pepper: pepper, scryptCostParam: scryptCostParam, cryptoSupport: cryptoSupport)
	}

	private static func isValidScryptCostParam(_ scryptCostParam: UInt64) -> Bool {
		return scryptCostParam > 1 && scryptCostParam.nonzeroBitCount == 1
	}

	/// Caps the `128 * r * (N + 3)` bytes that `crypto_scrypt` allocates at `Int32.max`, so an untrusted masterkey file cannot force huge allocations before the passphrase is checked.
	private static func isWithinScryptMemoryLimit(scryptCostParam: UInt64, scryptBlockSize: UInt32) -> Bool {
		return scryptCostParam + 3 <= UInt64(Int32.max) / 128 / UInt64(scryptBlockSize)
	}

	/**
	 Derives a KEK from the given passphrase using scrypt.

	 The `passphrase` string and its normalized copy cannot be wiped. The vendored scrypt core also leaves its stack scratch unwiped, for performance.
	 */
	private static func scrypt(passphrase: String, salt: [UInt8], pepper: [UInt8], scryptCostParam: UInt64, scryptBlockSize: UInt32) throws -> SecretBytes {
		let pw = SecretBytes(copying: passphrase.precomposedStringWithCanonicalMapping.utf8)
		var saltAndPepper = SecretBytes(count: salt.count + pepper.count)
		saltAndPepper.withUnsafeMutableBytes { saltAndPepperBytes in
			saltAndPepperBytes[..<salt.count].copyBytes(from: salt)
			saltAndPepperBytes[salt.count...].copyBytes(from: pepper)
		}
		var kek = SecretBytes(count: kCCKeySizeAES256)
		let scryptResult = pw.withUnsafeBytes { pwBytes in
			saltAndPepper.withUnsafeBytes { saltAndPepperBytes in
				kek.withUnsafeMutableBytes { kekBytes in
					crypto_scrypt(pwBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), pwBytes.count, saltAndPepperBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), saltAndPepperBytes.count, scryptCostParam, scryptBlockSize, 1, kekBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), kekBytes.count)
				}
			}
		}
		guard scryptResult == 0 else {
			throw MasterkeyFileError.keyDerivationFailed
		}
		return kek
	}

	private static func versionMac(version: UInt32, macKey: borrowing SecretBytes) -> [UInt8] {
		return hmacSha256(key: macKey, data: version.bigEndian.byteArray())
	}

	// MARK: - RFC 3394 Key Wrapping

	static func wrapKey(_ rawKey: borrowing SecretBytes, kek: borrowing SecretBytes) throws -> [UInt8] {
		var wrappedKeyLen = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), rawKey.count)
		var wrappedKey = [UInt8](repeating: 0x00, count: wrappedKeyLen)
		let status = kek.withUnsafeBytes { kekBytes in
			rawKey.withUnsafeBytes { rawKeyBytes in
				CCSymmetricKeyWrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kekBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), kekBytes.count, rawKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), rawKeyBytes.count, &wrappedKey, &wrappedKeyLen)
			}
		}
		if status == kCCSuccess {
			return wrappedKey
		} else {
			throw MasterkeyFileError.keyWrapFailed(status)
		}
	}

	static func unwrapKey(_ wrappedKey: [UInt8], kek: borrowing SecretBytes) throws -> SecretBytes {
		var unwrappedKeyLen = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count)
		var unwrappedKey = SecretBytes(count: unwrappedKeyLen)
		let status = kek.withUnsafeBytes { kekBytes in
			unwrappedKey.withUnsafeMutableBytes { unwrappedKeyBytes in
				CCSymmetricKeyUnwrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kekBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), kekBytes.count, wrappedKey, wrappedKey.count, unwrappedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), &unwrappedKeyLen)
			}
		}
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
