//
//  AesCtr.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 06.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

class AesCtr {
	/**
	 High-level AES-CTR wrapper around CommonCrypto primitives. Can be used for encryption and decryption (it is the same in CTR mode).

	 Returns its output in an ordinary array, so it is meant for output that is not secret, like ciphertext or filenames.

	 - Parameter key: 128 or 256 bit encryption key
	 - Parameter iv: 128 bit initialization vector (must not be reused!)
	 - Parameter data: data to be encrypted/decrypted
	 - Returns: encrypted/decrypted data
	 */
	static func compute(key: borrowing SecretBytes, iv: [UInt8], data: some ContiguousBytes) throws -> [UInt8] {
		return try key.withUnsafeBytes { keyBytes in
			try data.withUnsafeBytes { dataBytes in
				try [UInt8](unsafeUninitializedCapacity: dataBytes.count) { output, initializedCount in
					try compute(key: keyBytes, iv: iv, data: dataBytes, into: UnsafeMutableRawBufferPointer(output))
					initializedCount = dataBytes.count
				}
			}
		}
	}

	/**
	 Writes into a caller-provided buffer, so that secret output, like a decrypted header payload, can go straight into memory the caller wipes.

	 - Parameter key: 128 or 256 bit encryption key
	 - Parameter iv: 128 bit initialization vector (must not be reused!)
	 - Parameter output: buffer of the same size as `data`
	 */
	static func compute(key: UnsafeRawBufferPointer, iv: [UInt8], data: UnsafeRawBufferPointer, into output: UnsafeMutableRawBufferPointer) throws {
		assert(key.count == kCCKeySizeAES256 || key.count == kCCKeySizeAES128, "key expected to be 128 or 256 bit")
		assert(iv.count == kCCBlockSizeAES128, "iv expected to be 128 bit")
		assert(output.count == data.count, "output expected to be as long as data")

		var cryptor: CCCryptorRef?
		var status = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), iv, key.baseAddress, key.count, nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
		guard status == kCCSuccess, cryptor != nil else {
			throw CryptoError.invalidParameter("failed to initialize cryptor")
		}
		defer {
			CCCryptorRelease(cryptor)
		}

		var numEncryptedBytes = 0
		status = CCCryptorUpdate(cryptor, data.baseAddress, data.count, output.baseAddress, output.count, &numEncryptedBytes)
		guard status == kCCSuccess else {
			throw CryptoError.ccCryptorError(status)
		}

		status = CCCryptorFinal(cryptor, output.baseAddress, output.count, &numEncryptedBytes)
		guard status == kCCSuccess else {
			throw CryptoError.ccCryptorError(status)
		}
	}
}
