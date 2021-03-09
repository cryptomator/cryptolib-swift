//
//  ContentCryptor.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 09.03.21.
//  Copyright © 2021 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

protocol ContentCryptor {
	var nonceLen: Int { get }
	var tagLen: Int { get }

	/**
	 Encrypts one single chunk of cleartext data.

	 - Parameter chunk: The cleartext to be encrypted.
	 - Parameter nonce: The nonce/IV to use.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption.
	 - Returns: Nonce/IV + ciphertext + MAC/tag, as a concatenated byte array
	 */
	func encrypt(_ chunk: [UInt8], key: [UInt8], nonce: [UInt8], ad: [UInt8]...) throws -> [UInt8]

	/**
	 Decrypts one single chunk of encrypted data.

	 - Parameter chunk: The nonce/IV + ciphertext + MAC/tag, as a concatenated byte array.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption.
	 - Returns: The original cleartext
	 */
	func decrypt(_ chunk: [UInt8], key: [UInt8], ad: [UInt8]...) throws -> [UInt8]
}

class CtrThenHmacContentCryptor: ContentCryptor {
	private let macKey: [UInt8]
	private let cryptoSupport: CryptoSupport

	var nonceLen: Int {
		return kCCBlockSizeAES128
	}

	var tagLen: Int {
		return Int(CC_SHA256_DIGEST_LENGTH)
	}

	init(macKey: [UInt8], cryptoSupport: CryptoSupport) {
		self.macKey = macKey
		self.cryptoSupport = cryptoSupport
	}

	func encrypt(_ chunk: [UInt8], key: [UInt8], nonce: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		let ciphertext = try AesCtr.compute(key: key, iv: nonce, data: chunk)
		let mac = computeHmac(ciphertext, nonce: nonce, ad: ad)
		return nonce + ciphertext + mac
	}

	func decrypt(_ chunk: [UInt8], key: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		assert(chunk.count >= nonceLen + tagLen, "ciphertext chunk must at least contain nonce + tag")

		// decompose chunk:
		let beginOfMAC = chunk.count - tagLen
		let chunkNonce = [UInt8](chunk[0 ..< nonceLen])
		let ciphertext = [UInt8](chunk[nonceLen ..< beginOfMAC])
		let expectedMAC = [UInt8](chunk[beginOfMAC...])

		// check MAC:
		let mac = computeHmac(ciphertext, nonce: chunkNonce, ad: ad)
		guard cryptoSupport.compareBytes(expected: expectedMAC, actual: mac) else {
			throw CryptoError.unauthenticCiphertext
		}

		// decrypt:
		return try AesCtr.compute(key: key, iv: chunkNonce, data: ciphertext)
	}

	private func computeHmac(_ ciphertext: [UInt8], nonce: [UInt8], ad: [[UInt8]]) -> [UInt8] {
		let data = ad.reduce([UInt8](), +) + nonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: tagLen)
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), macKey, macKey.count, data, data.count, &mac)
		return mac
	}
}
