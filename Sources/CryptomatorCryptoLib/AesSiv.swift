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
	static let cryptoSupport = CryptoSupport()
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
	static func encrypt(aesKey: [UInt8], macKey: [UInt8], plaintext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
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
	static func decrypt(aesKey: [UInt8], macKey: [UInt8], ciphertext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		guard ciphertext.count >= 16 else {
			throw CryptoError.invalidParameter("ciphertext must be at least 16 bytes")
		}
		let iv = Array(ciphertext[..<16])
		let actualCiphertext = Array(ciphertext[16...])
		let plaintext = try ctr(aesKey: aesKey, iv: iv, plaintext: actualCiphertext)
		let control = try s2v(macKey: macKey, plaintext: plaintext, ad: ad)
		guard cryptoSupport.compareBytes(expected: control, actual: iv) else {
			throw CryptoError.unauthenticCiphertext
		}
		return plaintext
	}

	// MARK: - Internal

	static func ctr(aesKey key: [UInt8], iv: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
		// clear out the 31st and 63rd bit (see https://tools.ietf.org/html/rfc5297#section-2.5)
		var ctr = iv
		ctr[8] &= 0x7F
		ctr[12] &= 0x7F
		return try AesCtr.compute(key: key, iv: ctr, data: plaintext)
	}

	static func s2v(macKey: [UInt8], plaintext: [UInt8], ad: [[UInt8]]) throws -> [UInt8] {
		// Maximum permitted AD length is the block size in bits - 2
		assert(ad.count <= 126, "too many ad")

		// RFC 5297 defines a n == 0 case here. Where n is the length of the input vector:
		// S1 = associatedData1, S2 = associatedData2, ... Sn = plaintext
		// Since this method is invoked only by encrypt/decrypt, we always have a plaintext.
		// Thus n > 0

		var d = try cmac(macKey: macKey, data: zero)
		for s in ad {
			d = xor(dbl(d), try cmac(macKey: macKey, data: s))
		}

		let t: [UInt8]
		if plaintext.count >= 16 {
			t = xorend(plaintext, d)
		} else {
			t = xor(dbl(d), pad(plaintext))
		}

		return try cmac(macKey: macKey, data: t)
	}

	static func cmac(macKey key: [UInt8], data: [UInt8]) throws -> [UInt8] {
		// subkey generation:
		let l = try aes(key: key, plaintext: zero)
		let k1 = l[0] & 0x80 == 0x00 ? shiftLeft(l) : dbl(l)
		let k2 = k1[0] & 0x80 == 0x00 ? shiftLeft(k1) : dbl(k1)

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
		var mac = [UInt8](repeating: 0x00, count: 16)
		for i in 0 ..< lastBlockIdx {
			let block = Array(data[(16 * i) ..< (16 * (i + 1))])
			let y = xor(mac, block)
			mac = try aes(key: key, plaintext: y)
		}

		// block n:
		var lastBlock = Array(data[(16 * lastBlockIdx)...])
		if lastBlockComplete {
			lastBlock = xor(lastBlock, k1)
		} else {
			lastBlock = xor(pad(lastBlock), k2)
		}
		let y = xor(mac, lastBlock)
		mac = try aes(key: key, plaintext: y)

		return mac
	}

	private static func aes(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
		assert(key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES192 || key.count == kCCKeySizeAES256)
		assert(plaintext.count == kCCBlockSizeAES128, "Attempt to run AES-ECB for plaintext != one single block")

		var ciphertext = [UInt8](repeating: 0x00, count: kCCBlockSizeAES128)
		var ciphertextLen = 0
		let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode), key, key.count, nil, plaintext, plaintext.count, &ciphertext, kCCBlockSizeAES128, &ciphertextLen)

		guard status == kCCSuccess else {
			throw CryptoError.ccCryptorError(status)
		}

		return ciphertext
	}

	private static func shiftLeft(_ input: [UInt8]) -> [UInt8] {
		var output = [UInt8](repeating: 0x00, count: input.count)
		var bit: UInt8 = 0
		for i in (0 ..< input.count).reversed() {
			let b = input[i] & 0xFF
			output[i] = (b << 1) | bit
			bit = (b >> 7) & 1
		}
		return output
	}

	private static func dbl(_ block: [UInt8]) -> [UInt8] {
		var result = shiftLeft(block)
		if block[0] & 0x80 != 0x00 {
			result[block.count - 1] ^= dblConst
		}
		return result
	}

	private static func xor(_ data1: [UInt8], _ data2: [UInt8]) -> [UInt8] {
		assert(data1.count <= data2.count, "Length of first input must be <= length of second input.")
		var result = [UInt8](repeating: 0x00, count: data1.count)
		for i in 0 ..< data1.count {
			result[i] = data1[i] ^ data2[i]
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

	// ISO/IEC 7816-4:2005 Padding: First bit 1, following bits 0
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
