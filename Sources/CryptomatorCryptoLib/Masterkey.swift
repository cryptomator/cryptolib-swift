//
//  Masterkey.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

public final class Masterkey: @unchecked Sendable {
	// `@unchecked Sendable` is safe because the key arrays are written only in `init` and in `deinit`, which has exclusive access.

	private(set) var aesMasterKey: [UInt8]
	private(set) var macMasterKey: [UInt8]
	public var rawKey: [UInt8] {
		return aesMasterKey + macMasterKey
	}

	private init(aesMasterKey: [UInt8], macMasterKey: [UInt8]) {
		self.aesMasterKey = aesMasterKey
		self.macMasterKey = macMasterKey
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

	 - Returns: New masterkey instance with secure random bytes.
	 */
	public static func createNew() throws -> Masterkey {
		let cryptoSupport = DefaultCryptoSupport()
		let aesMasterKey = try cryptoSupport.createRandomBytes(size: kCCKeySizeAES256)
		let macMasterKey = try cryptoSupport.createRandomBytes(size: kCCKeySizeAES256)
		return createFromRaw(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}

	/**
	 Creates masterkey from raw bytes.

	 - Parameter rawKey: The 32-byte `aesMasterKey` (used for encryption of file specific keys) followed by the 32-byte `macMasterKey` (used for file authentication).
	 - Returns: New masterkey instance using the keys from the supplied raw bytes.
	 */
	public static func createFromRaw(rawKey: [UInt8]) throws -> Masterkey {
		guard rawKey.count == 2 * kCCKeySizeAES256 else {
			throw CryptoError.invalidParameter("rawKey must be \(2 * kCCKeySizeAES256) bytes")
		}
		let aesMasterkey = Array(rawKey[0 ..< kCCKeySizeAES256])
		let macMasterKey = Array(rawKey[kCCKeySizeAES256...])
		return createFromRaw(aesMasterKey: aesMasterkey, macMasterKey: macMasterKey)
	}

	/**
	 Creates masterkey from raw bytes.

	 - Parameter aesMasterKey: Key used for encryption of file specific keys.
	 - Parameter macMasterKey: Key used for file authentication.
	 - Returns: New masterkey instance using the keys from the supplied raw bytes.
	 */
	static func createFromRaw(aesMasterKey: [UInt8], macMasterKey: [UInt8]) -> Masterkey {
		assert(aesMasterKey.count == kCCKeySizeAES256)
		assert(macMasterKey.count == kCCKeySizeAES256)
		return Masterkey(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}
}
