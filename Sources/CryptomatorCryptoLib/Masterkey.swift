//
//  Masterkey.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

public class Masterkey {
	private(set) var aesMasterKey: [UInt8]
	private(set) var macMasterKey: [UInt8]

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
		let cryptoSupport = CryptoSupport()
		let aesMasterKey = try cryptoSupport.createRandomBytes(size: kCCKeySizeAES256)
		let macMasterKey = try cryptoSupport.createRandomBytes(size: kCCKeySizeAES256)
		return createFromRaw(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}

	/**
	 Creates masterkey from raw bytes.

	 - Parameter aesMasterKey: Key used for encryption of file specific keys.
	 - Parameter macMasterKey: Key used for file authentication.
	 - Returns: New masterkey instance using the keys from the supplied raw bytes.
	 */
	public static func createFromRaw(aesMasterKey: [UInt8], macMasterKey: [UInt8]) -> Masterkey {
		assert(aesMasterKey.count == kCCKeySizeAES256)
		assert(macMasterKey.count == kCCKeySizeAES256)
		return Masterkey(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}
}
