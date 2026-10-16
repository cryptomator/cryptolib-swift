//
//  AesSiv.swift
//  CryptomatorCryptoLib
//
//  Created by Sebastian Stenzel on 29.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

class AesSiv {
	static let zero = [UInt8](repeating: 0x00, count: 16)
	static let dblConst: UInt8 = 0x87

	/**
	 Encrypts plaintext using SIV mode.

	 - Parameter aesKey: SIV mode requires two separate keys. You can use one long key, which is splitted in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter macKey: SIV mode requires two separate keys. You can use one long key, which is splitted in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter plaintext: Your plaintext, which shall be encrypted. It must not be longer than 2^32 - 16 bytes.
	 - Parameter ad: Associated data, which gets authenticated but not encrypted.
	 - Returns: IV + Ciphertext as a concatenated byte array.
	 */
	static func encrypt(aesKey: borrowing SecretBytes, macKey: borrowing SecretBytes, plaintext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		guard plaintext.count <= UInt32.max - 16 else {
			throw CryptoError.invalidParameter("plaintext must not be longer than 2^32 - 16 bytes")
		}
		let iv = try s2v(macKey: macKey, plaintext: plaintext, ad: ad)
		let ciphertext = try ctr(aesKey: aesKey, iv: iv, plaintext: plaintext)
		return iv + ciphertext
	}

	/**
	 Decrypts ciphertext using SIV mode.

	 - Parameter aesKey: SIV mode requires two separate keys. You can use one long key, which is splitted in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter macKey: SIV mode requires two separate keys. You can use one long key, which is splitted in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter ciphertext: Your ciphertext, which shall be decrypted. It must be at least 16 bytes.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption.
	 - Returns: Plaintext byte array.
	 */
	static func decrypt(aesKey: borrowing SecretBytes, macKey: borrowing SecretBytes, ciphertext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		guard ciphertext.count >= 16 else {
			throw CryptoError.invalidParameter("ciphertext must be at least 16 bytes")
		}
		let iv = Array(ciphertext[..<16])
		let actualCiphertext = Array(ciphertext[16...])
		let plaintext = try ctr(aesKey: aesKey, iv: iv, plaintext: actualCiphertext)
		let control = try s2v(macKey: macKey, plaintext: plaintext, ad: ad)
		guard compareBytes(expected: control, actual: iv) else {
			throw CryptoError.unauthenticCiphertext
		}
		return plaintext
	}

	// MARK: - Internal

	static func ctr(aesKey key: borrowing SecretBytes, iv: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
		// clear out the 31st and 63rd bit (see https://tools.ietf.org/html/rfc5297#section-2.5)
		var ctr = iv
		ctr[8] &= 0x7F
		ctr[12] &= 0x7F
		return try AesCtr.compute(key: key, iv: ctr, data: plaintext)
	}

	static func s2v(macKey: borrowing SecretBytes, plaintext: [UInt8], ad: [[UInt8]]) throws -> [UInt8] {
		// Maximum permitted AD length is the block size in bits - 2
		assert(ad.count <= 126, "too many ad")

		// RFC 5297 defines a n == 0 case here. Where n is the length of the input vector:
		// S1 = associatedData1, S2 = associatedData2, ... Sn = plaintext
		// Since this method is invoked only by encrypt/decrypt, we always have a plaintext.
		// Thus n > 0

		var d = try cmac(macKey: macKey, data: zero)
		for s in ad {
			d = try xor(dbl(d), cmac(macKey: macKey, data: s))
		}

		let t: [UInt8] = if plaintext.count >= 16 {
			xorend(plaintext, d)
		} else {
			xor(dbl(d), pad(plaintext))
		}

		return try cmac(macKey: macKey, data: t)
	}

	static func cmac(macKey key: borrowing SecretBytes, data: [UInt8]) throws -> [UInt8] {
		// subkey generation:
		var l = SecretBytes(count: 16)
		try zero.withUnsafeBytes { zeroBytes in
			try l.withUnsafeMutableBytes { try aes(key: key, plaintext: zeroBytes, into: $0) }
		}
		let k1 = dbl(l)
		let k2 = dbl(k1)

		// determine number of blocks:
		let n = (data.count + 15) / 16
		let lastBlockIdx: Int
		let lastBlockComplete: Bool
		if n == 0 {
			lastBlockIdx = 0
			lastBlockComplete = false
		} else {
			lastBlockIdx = n - 1
			lastBlockComplete = data.count % 16 == 0
		}

		// blocks 0..<n:
		var mac = SecretBytes(count: 16)
		var y = SecretBytes(count: 16)
		for i in 0 ..< lastBlockIdx {
			try data[(16 * i) ..< (16 * (i + 1))].withUnsafeBytes { try chain($0, key: key, mac: &mac, y: &y) }
		}

		// block n:
		let lastBlockData = Array(data[(16 * lastBlockIdx)...])
		let lastBlock = if lastBlockComplete {
			xor(lastBlockData, k1)
		} else {
			xor(pad(lastBlockData), k2)
		}
		try lastBlock.withUnsafeBytes { try chain($0, key: key, mac: &mac, y: &y) }

		return mac.exportBytes()
	}

	/// One CBC-MAC step, `mac = AES(key, mac ^ block)`, with `y` as scratch for the XOR.
	private static func chain(_ block: UnsafeRawBufferPointer, key: borrowing SecretBytes, mac: inout SecretBytes, y: inout SecretBytes) throws {
		mac.withUnsafeBytes { macBytes in
			y.withUnsafeMutableBytes { xor(macBytes, block, into: $0) }
		}
		try y.withUnsafeBytes { yBytes in
			try mac.withUnsafeMutableBytes { try aes(key: key, plaintext: yBytes, into: $0) }
		}
	}

	private static func aes(key: borrowing SecretBytes, plaintext: UnsafeRawBufferPointer, into ciphertext: UnsafeMutableRawBufferPointer) throws {
		assert(key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES192 || key.count == kCCKeySizeAES256)
		assert(plaintext.count == kCCBlockSizeAES128, "Attempt to run AES-ECB for plaintext != one single block")
		assert(ciphertext.count == kCCBlockSizeAES128, "Attempt to run AES-ECB for ciphertext != one single block")

		var ciphertextLen = 0
		let status = key.withUnsafeBytes { keyBytes in
			CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode), keyBytes.baseAddress, keyBytes.count, nil, plaintext.baseAddress, plaintext.count, ciphertext.baseAddress, ciphertext.count, &ciphertextLen)
		}

		guard status == kCCSuccess else {
			throw CryptoError.ccCryptorError(status)
		}
	}

	private static func shiftLeft(_ input: UnsafeRawBufferPointer, into output: UnsafeMutableRawBufferPointer) {
		var bit: UInt8 = 0
		for i in (0 ..< input.count).reversed() {
			let b = input[i] & 0xFF
			output[i] = (b << 1) | bit
			bit = (b >> 7) & 1
		}
	}

	private static func dbl(_ block: UnsafeRawBufferPointer, into result: UnsafeMutableRawBufferPointer) {
		shiftLeft(block, into: result)
		if block[0] & 0x80 != 0x00 {
			result[block.count - 1] ^= dblConst
		}
	}

	private static func dbl(_ block: [UInt8]) -> [UInt8] {
		var result = [UInt8](repeating: 0x00, count: block.count)
		block.withUnsafeBytes { blockBytes in
			result.withUnsafeMutableBytes { dbl(blockBytes, into: $0) }
		}
		return result
	}

	private static func dbl(_ block: borrowing SecretBytes) -> SecretBytes {
		var result = SecretBytes(count: block.count)
		block.withUnsafeBytes { blockBytes in
			result.withUnsafeMutableBytes { dbl(blockBytes, into: $0) }
		}
		return result
	}

	private static func xor(_ data1: UnsafeRawBufferPointer, _ data2: UnsafeRawBufferPointer, into result: UnsafeMutableRawBufferPointer) {
		assert(data1.count <= data2.count, "Length of first input must be <= length of second input.")
		for i in 0 ..< data1.count {
			result[i] = data1[i] ^ data2[i]
		}
	}

	private static func xor(_ data1: [UInt8], _ data2: [UInt8]) -> [UInt8] {
		var result = [UInt8](repeating: 0x00, count: data1.count)
		data1.withUnsafeBytes { data1Bytes in
			data2.withUnsafeBytes { data2Bytes in
				result.withUnsafeMutableBytes { xor(data1Bytes, data2Bytes, into: $0) }
			}
		}
		return result
	}

	private static func xor(_ data1: [UInt8], _ data2: borrowing SecretBytes) -> SecretBytes {
		var result = SecretBytes(count: data1.count)
		data1.withUnsafeBytes { data1Bytes in
			data2.withUnsafeBytes { data2Bytes in
				result.withUnsafeMutableBytes { xor(data1Bytes, data2Bytes, into: $0) }
			}
		}
		return result
	}

	private static func xorend(_ data1: [UInt8], _ data2: [UInt8]) -> [UInt8] {
		assert(data1.count >= data2.count, "Length of first input must be >= length of second input.")
		var result = data1
		let diff = data1.count - data2.count
		for i in 0 ..< data2.count {
			result[i + diff] = data1[i + diff] ^ data2[i]
		}
		return result
	}

	/// ISO/IEC 7816-4:2005 Padding: First bit 1, following bits 0
	private static func pad(_ data: [UInt8]) -> [UInt8] {
		var result = data
		if result.count < 16 {
			result.append(0x80)
		}
		while result.count < 16 {
			result.append(0x00)
		}
		return result
	}
}
