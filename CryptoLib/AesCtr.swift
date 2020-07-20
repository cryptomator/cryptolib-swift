//
//  AesCtr.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 06.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

class AesCtr {
	/**
	 High-level AES-CTR wrapper around CommonCrypto primitives. Can be used for encryption and decryption (it is the same in CTR mode).

	 - Parameter key: 128 or 256 bit encryption key
	 - Parameter iv: 128 bit initialization vector (must not be reused!)
	 - Parameter data: data to be encrypted/decrypted
	 - Returns: encrypted/decrypted data
	 */
	static func compute(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
		assert(key.count == kCCKeySizeAES256 || key.count == kCCKeySizeAES128, "key expected to be 128 or 256 bit")
		assert(iv.count == kCCBlockSizeAES128, "iv expected to be 128 bit")

		var cryptor: CCCryptorRef?
		var status = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), iv, key, key.count, nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
		guard status == kCCSuccess, cryptor != nil else {
			throw CryptoError.invalidParameter("failed to initialize cryptor")
		}
		defer {
			CCCryptorRelease(cryptor)
		}

		let outlen = CCCryptorGetOutputLength(cryptor, data.count, true)
		var ciphertext = [UInt8](repeating: 0x00, count: outlen)

		var numEncryptedBytes: Int = 0
		status = CCCryptorUpdate(cryptor, data, data.count, &ciphertext, ciphertext.count, &numEncryptedBytes)
		guard status == kCCSuccess else {
			throw CryptoError.ccCryptorError(status)
		}

		status = CCCryptorFinal(cryptor, &ciphertext, ciphertext.count, &numEncryptedBytes)
		guard status == kCCSuccess else {
			throw CryptoError.ccCryptorError(status)
		}

		return ciphertext
	}
}
