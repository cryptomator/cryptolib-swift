//
//  Masterkey.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

public final class Masterkey: Sendable {
	let aesMasterKey: SecretBytes
	let macMasterKey: SecretBytes

	/// A copy of the 32-byte `aesMasterKey` followed by the 32-byte `macMasterKey`. The returned array belongs to the caller, and the library cannot wipe it.
	public var rawKey: [UInt8] {
		var rawKey = [UInt8]()
		// reserve the full size, so that appending never reallocates and leaves key bytes behind in a freed buffer:
		rawKey.reserveCapacity(aesMasterKey.count + macMasterKey.count)
		aesMasterKey.withUnsafeBytes { rawKey.append(contentsOf: $0) }
		macMasterKey.withUnsafeBytes { rawKey.append(contentsOf: $0) }
		return rawKey
	}

	private init(aesMasterKey: consuming SecretBytes, macMasterKey: consuming SecretBytes) {
		self.aesMasterKey = aesMasterKey
		self.macMasterKey = macMasterKey
	}

	// MARK: - Factory

	/**
	 Creates new masterkey.

	 - Returns: New masterkey instance with secure random bytes.
	 */
	public static func createNew() throws -> Masterkey {
		let cryptoSupport = DefaultCryptoSupport()
		let aesMasterKey = try cryptoSupport.createRandomSecret(size: kCCKeySizeAES256)
		let macMasterKey = try cryptoSupport.createRandomSecret(size: kCCKeySizeAES256)
		return createFromRaw(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}

	/**
	 Creates masterkey from raw bytes.

	 - Parameter rawKey: The 32-byte `aesMasterKey` (used for encryption of file specific keys) followed by the 32-byte `macMasterKey` (used for file authentication). The bytes are copied and never retained, so wiping `rawKey` remains the caller's responsibility.
	 - Returns: New masterkey instance using the keys from the supplied raw bytes.
	 */
	public static func createFromRaw(rawKey: [UInt8]) throws -> Masterkey {
		guard rawKey.count == 2 * kCCKeySizeAES256 else {
			throw CryptoError.invalidParameter("rawKey must be \(2 * kCCKeySizeAES256) bytes")
		}
		let aesMasterKey = SecretBytes(copying: rawKey[0 ..< kCCKeySizeAES256])
		let macMasterKey = SecretBytes(copying: rawKey[kCCKeySizeAES256...])
		return createFromRaw(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}

	/**
	 Creates masterkey from raw bytes.

	 - Parameter aesMasterKey: Key used for encryption of file specific keys.
	 - Parameter macMasterKey: Key used for file authentication.
	 - Returns: New masterkey instance using the keys from the supplied raw bytes.
	 */
	static func createFromRaw(aesMasterKey: consuming SecretBytes, macMasterKey: consuming SecretBytes) -> Masterkey {
		assert(aesMasterKey.count == kCCKeySizeAES256)
		assert(macMasterKey.count == kCCKeySizeAES256)
		return Masterkey(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}
}
