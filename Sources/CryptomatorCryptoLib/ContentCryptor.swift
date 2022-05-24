//
//  ContentCryptor.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 09.03.21.
//  Copyright © 2021 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import CryptoKit
import Foundation

protocol ContentCryptor {
	var nonceLen: Int { get }
	var tagLen: Int { get }

	/**
	 Encrypts one single chunk of cleartext data.

	 - Parameter chunk: The cleartext to be encrypted.
	 - Parameter key: The encryption key.
	 - Parameter nonce: The nonce/IV to use.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption.
	 - Returns: Nonce/IV + ciphertext + MAC/tag, as a concatenated byte array.
	 */
	func encrypt(_ chunk: [UInt8], key: [UInt8], nonce: [UInt8], ad: [UInt8]) throws -> [UInt8]

	/**
	 Decrypts one single chunk of encrypted data.

	 - Parameter chunk: The nonce/IV + ciphertext + MAC/tag, as a concatenated byte array.
	 - Parameter key: The encryption key.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption.
	 - Returns: The original cleartext.
	 */
	func decrypt(_ chunk: [UInt8], key: [UInt8], ad: [UInt8]) throws -> [UInt8]

	/**
	 Constructs the associated data which will be authenticated during encryption/decryption of a single chunk

	 - Parameter chunkNumber: The index of the chunk (starting at 0), preventing swapping of chunks
	 - Parameter headerNonce: The nonce used in the file header, binding the chunk to this particular file.
	 - Returns: The combined associated data.
	 */
	func ad(chunkNumber: UInt64, headerNonce: [UInt8]) -> [UInt8]
}

extension ContentCryptor {
	func encryptHeader(_ header: [UInt8], key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
		return try encrypt(header, key: key, nonce: nonce, ad: [])
	}

	func decryptHeader(_ header: [UInt8], key: [UInt8]) throws -> [UInt8] {
		return try decrypt(header, key: key, ad: [])
	}

	func encryptChunk(_ chunk: [UInt8], chunkNumber: UInt64, chunkNonce: [UInt8], fileKey: [UInt8], headerNonce: [UInt8]) throws -> [UInt8] {
		let ad = ad(chunkNumber: chunkNumber, headerNonce: headerNonce)
		return try encrypt(chunk, key: fileKey, nonce: chunkNonce, ad: ad)
	}

	func decryptChunk(_ chunk: [UInt8], chunkNumber: UInt64, fileKey: [UInt8], headerNonce: [UInt8]) throws -> [UInt8] {
		let ad = ad(chunkNumber: chunkNumber, headerNonce: headerNonce)
		return try decrypt(chunk, key: fileKey, ad: ad)
	}
}

class GcmContentCryptor: ContentCryptor {
	let nonceLen = 12 // 96 bit
	let tagLen = 16 // 128 bit

	func ad(chunkNumber: UInt64, headerNonce: [UInt8]) -> [UInt8] {
		return chunkNumber.bigEndian.byteArray() + headerNonce
	}

	func encrypt(_ chunk: [UInt8], key keyBytes: [UInt8], nonce nonceBytes: [UInt8], ad: [UInt8]) throws -> [UInt8] {
		let key = SymmetricKey(data: keyBytes)
		let nonce = try AES.GCM.Nonce(data: nonceBytes)
		let encrypted = try AES.GCM.seal(chunk, using: key, nonce: nonce, authenticating: ad)

		return [UInt8](encrypted.nonce + encrypted.ciphertext + encrypted.tag)
	}

	func decrypt(_ chunk: [UInt8], key keyBytes: [UInt8], ad: [UInt8]) throws -> [UInt8] {
		assert(chunk.count >= nonceLen + tagLen, "ciphertext chunk must at least contain nonce + tag")

		let key = SymmetricKey(data: keyBytes)
		let encrypted = try AES.GCM.SealedBox(combined: chunk)
		let decrypted = try AES.GCM.open(encrypted, using: key, authenticating: ad)

		return [UInt8](decrypted)
	}
}

class CtrThenHmacContentCryptor: ContentCryptor {
	let nonceLen = kCCBlockSizeAES128
	let tagLen = Int(CC_SHA256_DIGEST_LENGTH)

	private let macKey: [UInt8]
	private let cryptoSupport: CryptoSupport

	init(macKey: [UInt8], cryptoSupport: CryptoSupport) {
		self.macKey = macKey
		self.cryptoSupport = cryptoSupport
	}

	func ad(chunkNumber: UInt64, headerNonce: [UInt8]) -> [UInt8] {
		return headerNonce + chunkNumber.bigEndian.byteArray()
	}

	func encrypt(_ chunk: [UInt8], key: [UInt8], nonce: [UInt8], ad: [UInt8]) throws -> [UInt8] {
		let ciphertext = try AesCtr.compute(key: key, iv: nonce, data: chunk)
		let mac = computeHmac(ciphertext, nonce: nonce, ad: ad)
		return nonce + ciphertext + mac
	}

	func decrypt(_ chunk: [UInt8], key: [UInt8], ad: [UInt8]) throws -> [UInt8] {
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

	private func computeHmac(_ ciphertext: [UInt8], nonce: [UInt8], ad: [UInt8]) -> [UInt8] {
		let data = ad + nonce + ciphertext
		var mac = [UInt8](repeating: 0x00, count: tagLen)
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), macKey, macKey.count, data, data.count, &mac)
		return mac
	}
}
