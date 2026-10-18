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

protocol ContentCryptor: Sendable {
	var nonceLen: Int { get }
	var tagLen: Int { get }

	/**
	 Encrypts one single chunk of cleartext data.

	 - Parameter plaintext: The cleartext to be encrypted.
	 - Parameter key: The encryption key.
	 - Parameter nonce: The nonce/IV to use.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption.
	 - Returns: Nonce/IV + ciphertext + MAC/tag, as a concatenated byte array.
	 */
	func encrypt(_ plaintext: UnsafeRawBufferPointer, key: borrowing SecretBytes, nonce: [UInt8], ad: [UInt8]) throws -> [UInt8]

	/**
	 Decrypts one single chunk of encrypted data.

	 - Parameter chunk: The nonce/IV + ciphertext + MAC/tag, as a concatenated byte array.
	 - Parameter key: The encryption key.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption.
	 - Parameter cleartext: The buffer for the original cleartext, sized to `chunk` without nonce/IV and MAC/tag. Nothing is written to it unless `chunk` is authentic.
	 */
	func decrypt(_ chunk: [UInt8], key: borrowing SecretBytes, ad: [UInt8], into cleartext: UnsafeMutableRawBufferPointer) throws

	/**
	 Constructs the associated data which will be authenticated during encryption/decryption of a single chunk

	 - Parameter chunkNumber: The index of the chunk (starting at 0), preventing swapping of chunks
	 - Parameter headerNonce: The nonce used in the file header, binding the chunk to this particular file.
	 - Returns: The combined associated data.
	 */
	func ad(chunkNumber: UInt64, headerNonce: [UInt8]) -> [UInt8]
}

extension ContentCryptor {
	func encryptHeader(_ payload: borrowing SecretBytes, key: borrowing SecretBytes, nonce: [UInt8]) throws -> [UInt8] {
		return try payload.withUnsafeBytes { try encrypt($0, key: key, nonce: nonce, ad: []) }
	}

	func decryptHeader(_ header: [UInt8], key: borrowing SecretBytes) throws -> SecretBytes {
		return try SecretBytes(count: cleartextLen(of: header)) { try decrypt(header, key: key, ad: [], into: $0) }
	}

	func encryptChunk(_ chunk: [UInt8], chunkNumber: UInt64, chunkNonce: [UInt8], fileKey: borrowing SecretBytes, headerNonce: [UInt8]) throws -> [UInt8] {
		let ad = ad(chunkNumber: chunkNumber, headerNonce: headerNonce)
		return try chunk.withUnsafeBytes { try encrypt($0, key: fileKey, nonce: chunkNonce, ad: ad) }
	}

	func decryptChunk(_ chunk: [UInt8], chunkNumber: UInt64, fileKey: borrowing SecretBytes, headerNonce: [UInt8]) throws -> [UInt8] {
		let cleartextLen = try cleartextLen(of: chunk)
		let ad = ad(chunkNumber: chunkNumber, headerNonce: headerNonce)
		return try [UInt8](unsafeUninitializedCapacity: cleartextLen) { cleartext, initializedCount in
			try decrypt(chunk, key: fileKey, ad: ad, into: UnsafeMutableRawBufferPointer(cleartext))
			initializedCount = cleartextLen
		}
	}

	private func cleartextLen(of chunk: [UInt8]) throws -> Int {
		guard chunk.count >= nonceLen + tagLen else {
			throw CryptoError.unauthenticCiphertext
		}
		return chunk.count - nonceLen - tagLen
	}
}

/// CryptoKit keeps its own copy of the key inside `SymmetricKey`, which the library cannot wipe. Decryption returns the cleartext in `Data` that CryptoKit allocates, which the library wipes best-effort after copying it out.
final class GcmContentCryptor: ContentCryptor {
	let nonceLen = 12 // 96 bit
	let tagLen = 16 // 128 bit

	func ad(chunkNumber: UInt64, headerNonce: [UInt8]) -> [UInt8] {
		return chunkNumber.bigEndian.byteArray() + headerNonce
	}

	func encrypt(_ plaintext: UnsafeRawBufferPointer, key keyBytes: borrowing SecretBytes, nonce nonceBytes: [UInt8], ad: [UInt8]) throws -> [UInt8] {
		let key = keyBytes.withUnsafeBytes { SymmetricKey(data: $0) }
		let nonce = try AES.GCM.Nonce(data: nonceBytes)
		let encrypted = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: ad)

		return [UInt8](encrypted.nonce + encrypted.ciphertext + encrypted.tag)
	}

	func decrypt(_ chunk: [UInt8], key keyBytes: borrowing SecretBytes, ad: [UInt8], into cleartext: UnsafeMutableRawBufferPointer) throws {
		guard chunk.count >= nonceLen + tagLen else {
			throw CryptoError.unauthenticCiphertext
		}

		let key = keyBytes.withUnsafeBytes { SymmetricKey(data: $0) }
		do {
			let encrypted = try AES.GCM.SealedBox(combined: chunk)
			var decrypted = try AES.GCM.open(encrypted, using: key, authenticating: ad)
			cleartext.copyBytes(from: decrypted)
			decrypted.withUnsafeMutableBytes(secureZero)
		} catch CryptoKitError.authenticationFailure {
			throw CryptoError.unauthenticCiphertext
		}
	}
}

final class CtrThenHmacContentCryptor: ContentCryptor {
	let nonceLen = kCCBlockSizeAES128
	let tagLen = Int(CC_SHA256_DIGEST_LENGTH)

	private let masterkey: Masterkey

	init(masterkey: Masterkey) {
		self.masterkey = masterkey
	}

	func ad(chunkNumber: UInt64, headerNonce: [UInt8]) -> [UInt8] {
		return headerNonce + chunkNumber.bigEndian.byteArray()
	}

	func encrypt(_ plaintext: UnsafeRawBufferPointer, key: borrowing SecretBytes, nonce: [UInt8], ad: [UInt8]) throws -> [UInt8] {
		let ciphertext = try AesCtr.compute(key: key, iv: nonce, data: plaintext)
		let mac = computeHmac(ciphertext, nonce: nonce, ad: ad)
		return nonce + ciphertext + mac
	}

	func decrypt(_ chunk: [UInt8], key: borrowing SecretBytes, ad: [UInt8], into cleartext: UnsafeMutableRawBufferPointer) throws {
		guard chunk.count >= nonceLen + tagLen else {
			throw CryptoError.unauthenticCiphertext
		}

		// decompose chunk:
		let beginOfMAC = chunk.count - tagLen
		let chunkNonce = [UInt8](chunk[0 ..< nonceLen])
		let ciphertext = [UInt8](chunk[nonceLen ..< beginOfMAC])
		let expectedMAC = [UInt8](chunk[beginOfMAC...])

		// check MAC:
		let mac = computeHmac(ciphertext, nonce: chunkNonce, ad: ad)
		guard compareBytes(expected: expectedMAC, actual: mac) else {
			throw CryptoError.unauthenticCiphertext
		}

		// decrypt:
		try key.withUnsafeBytes { keyBytes in
			try ciphertext.withUnsafeBytes { ciphertextBytes in
				try AesCtr.compute(key: keyBytes, iv: chunkNonce, data: ciphertextBytes, into: cleartext)
			}
		}
	}

	private func computeHmac(_ ciphertext: [UInt8], nonce: [UInt8], ad: [UInt8]) -> [UInt8] {
		return hmacSha256(key: masterkey.macMasterKey, data: ad + nonce + ciphertext)
	}
}
