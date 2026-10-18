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

	 - Parameter aesKey: SIV mode requires two separate keys. You can use one long key, which is split in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter macKey: SIV mode requires two separate keys. You can use one long key, which is split in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter plaintext: Your plaintext, which shall be encrypted.
	 - Parameter ad: Associated data, which gets authenticated but not encrypted. It must not have more than 126 components.
	 - Returns: IV + Ciphertext as a concatenated byte array.
	 */
	static func encrypt(aesKey: borrowing SecretBytes, macKey: borrowing SecretBytes, plaintext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		let iv = try s2v(macKey: macKey, plaintext: plaintext, ad: ad)
		let ciphertext = try ctr(aesKey: aesKey, iv: iv, plaintext: plaintext)
		return iv + ciphertext
	}

	/**
	 Decrypts ciphertext using SIV mode.

	 - Parameter aesKey: SIV mode requires two separate keys. You can use one long key, which is split in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter macKey: SIV mode requires two separate keys. You can use one long key, which is split in half. See [RFC 5297 Section 2.2](https://tools.ietf.org/html/rfc5297#section-2.2).
	 - Parameter ciphertext: Your ciphertext, which shall be decrypted. It must be at least 16 bytes.
	 - Parameter ad: Associated data, which needs to be authenticated during decryption. It must not have more than 126 components.
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
		// Maximum permitted number of AD components is the block size in bits - 2
		let maxAdCount = 8 * kCCBlockSizeAES128 - 2
		guard ad.count <= maxAdCount else {
			throw CryptoError.invalidParameter("ad must not have more than \(maxAdCount) components")
		}

		// RFC 5297 S2V has a special case for n == 0, where n is the number of components S1 = AD1, ..., Sn = plaintext.
		// The plaintext is always the last component, so n > 0 and that case never applies.

		var cmac = try Cmac(key: macKey)
		var d = try cmac.mac(zero)
		for s in ad {
			d = try xor(dbl(d), cmac.mac(s))
		}

		let t: SecretBytes = if plaintext.count >= 16 {
			xorend(plaintext, d)
		} else {
			xorPadded(plaintext, dbl(d))
		}

		return try cmac.mac(t).exportBytes()
	}

	/// AES-CMAC that derives the subkeys once and runs every block of every MAC through one AES-ECB cryptor.
	struct Cmac: ~Copyable {
		private let cryptor: CCCryptorRef
		private let k1: SecretBytes
		private let k2: SecretBytes

		init(key: borrowing SecretBytes) throws {
			assert(key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES192 || key.count == kCCKeySizeAES256)

			var newCryptor: CCCryptorRef?
			let status = key.withUnsafeBytes { keyBytes in
				CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode), keyBytes.baseAddress, keyBytes.count, nil, &newCryptor)
			}
			guard status == kCCSuccess, let cryptor = newCryptor else {
				throw CryptoError.ccCryptorError(status)
			}
			var handedOff = false
			defer {
				if !handedOff {
					CCCryptorRelease(cryptor)
				}
			}

			// subkey generation:
			let l = try SecretBytes(count: 16) { lBytes in
				try zero.withUnsafeBytes { try Cmac.aes(cryptor: cryptor, plaintext: $0, into: lBytes) }
			}
			let k1 = dbl(l)
			let k2 = dbl(k1)

			// no `try` from here on, because a throw after full initialization would also run `deinit` and release the cryptor twice:
			self.cryptor = cryptor
			self.k1 = k1
			self.k2 = k2
			handedOff = true
		}

		deinit {
			CCCryptorRelease(cryptor)
		}

		mutating func mac(_ data: [UInt8]) throws -> SecretBytes {
			return try SecretBytes(count: 16) { macBytes in
				try data.withUnsafeBytes { try mac($0, into: macBytes) }
			}
		}

		mutating func mac(_ data: borrowing SecretBytes) throws -> SecretBytes {
			return try SecretBytes(count: 16) { macBytes in
				try data.withUnsafeBytes { try mac($0, into: macBytes) }
			}
		}

		/// `mac` must be zero-filled, because it serves as the CBC-MAC chaining state.
		private mutating func mac(_ data: UnsafeRawBufferPointer, into mac: UnsafeMutableRawBufferPointer) throws {
			assert(mac.count == kCCBlockSizeAES128 && mac.allSatisfy { $0 == 0x00 }, "mac expected to be one zero-filled block")

			// determine the last block, treating empty data as one incomplete block:
			let lastBlockIdx = data.isEmpty ? 0 : (data.count - 1) / 16
			let lastBlockComplete = !data.isEmpty && data.count % 16 == 0

			// all but the last block:
			var y = SecretBytes(count: 16)
			for i in 0 ..< lastBlockIdx {
				try chain(UnsafeRawBufferPointer(rebasing: data[(16 * i) ..< (16 * (i + 1))]), mac: mac, y: &y)
			}

			// last block:
			let lastBlockData = UnsafeRawBufferPointer(rebasing: data[(16 * lastBlockIdx)...])
			let lastBlock = SecretBytes(count: 16) { lastBlockBytes in
				if lastBlockComplete {
					k1.withUnsafeBytes { xor(lastBlockData, $0, into: lastBlockBytes) }
				} else {
					k2.withUnsafeBytes { xorPadded(lastBlockData, $0, into: lastBlockBytes) }
				}
			}
			try lastBlock.withUnsafeBytes { try chain($0, mac: mac, y: &y) }
		}

		/// One CBC-MAC step, `mac = AES(K, mac ^ block)`, with `y` as scratch for the XOR.
		private mutating func chain(_ block: UnsafeRawBufferPointer, mac: UnsafeMutableRawBufferPointer, y: inout SecretBytes) throws {
			y.withUnsafeMutableBytes { xor(UnsafeRawBufferPointer(mac), block, into: $0) }
			try y.withUnsafeBytes { try Cmac.aes(cryptor: cryptor, plaintext: $0, into: mac) }
		}

		/// `plaintext` and `ciphertext` must be separate buffers, because `CCCryptorUpdate` does not support in-place ECB. Without padding, ECB needs no `CCCryptorFinal`, so the cryptor stays usable for the next block.
		private static func aes(cryptor: CCCryptorRef, plaintext: UnsafeRawBufferPointer, into ciphertext: UnsafeMutableRawBufferPointer) throws {
			assert(plaintext.count == kCCBlockSizeAES128, "Attempt to run AES-ECB for plaintext != one single block")
			assert(ciphertext.count == kCCBlockSizeAES128, "Attempt to run AES-ECB for ciphertext != one single block")

			var ciphertextLen = 0
			let status = CCCryptorUpdate(cryptor, plaintext.baseAddress, plaintext.count, ciphertext.baseAddress, ciphertext.count, &ciphertextLen)

			guard status == kCCSuccess, ciphertextLen == kCCBlockSizeAES128 else {
				throw CryptoError.ccCryptorError(status)
			}
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
		// masked instead of branching on the secret top bit:
		let mask = 0 &- (block[0] >> 7)
		result[block.count - 1] ^= dblConst & mask
	}

	private static func dbl(_ block: borrowing SecretBytes) -> SecretBytes {
		return SecretBytes(count: block.count) { resultBytes in
			block.withUnsafeBytes { dbl($0, into: resultBytes) }
		}
	}

	private static func xor(_ data1: UnsafeRawBufferPointer, _ data2: UnsafeRawBufferPointer, into result: UnsafeMutableRawBufferPointer) {
		assert(data1.count <= data2.count, "Length of first input must be <= length of second input.")
		for i in 0 ..< data1.count {
			result[i] = data1[i] ^ data2[i]
		}
	}

	private static func xor(_ data1: borrowing SecretBytes, _ data2: borrowing SecretBytes) -> SecretBytes {
		return SecretBytes(count: data1.count) { resultBytes in
			data1.withUnsafeBytes { data1Bytes in
				data2.withUnsafeBytes { xor(data1Bytes, $0, into: resultBytes) }
			}
		}
	}

	private static func xorend(_ data1: [UInt8], _ data2: borrowing SecretBytes) -> SecretBytes {
		assert(data1.count >= data2.count, "Length of first input must be >= length of second input.")
		let diff = data1.count - data2.count
		return SecretBytes(count: data1.count) { resultBytes in
			resultBytes.copyBytes(from: data1)
			data2.withUnsafeBytes { data2Bytes in
				for i in 0 ..< data2Bytes.count {
					resultBytes[i + diff] ^= data2Bytes[i]
				}
			}
		}
	}

	/// ISO/IEC 7816-4:2005 Padding: First bit 1, following bits 0
	private static func pad(_ data: UnsafeRawBufferPointer, into result: UnsafeMutableRawBufferPointer) {
		assert(data.count < result.count, "Length of input must be < length of output.")
		result.copyBytes(from: data)
		result[data.count] = 0x80
		for i in (data.count + 1) ..< result.count {
			result[i] = 0x00
		}
	}

	/// `pad(data) ^ key`
	private static func xorPadded(_ data: UnsafeRawBufferPointer, _ key: UnsafeRawBufferPointer, into result: UnsafeMutableRawBufferPointer) {
		pad(data, into: result)
		for i in 0 ..< result.count {
			result[i] ^= key[i]
		}
	}

	private static func xorPadded(_ data: [UInt8], _ key: borrowing SecretBytes) -> SecretBytes {
		return SecretBytes(count: key.count) { resultBytes in
			data.withUnsafeBytes { dataBytes in
				key.withUnsafeBytes { xorPadded(dataBytes, $0, into: resultBytes) }
			}
		}
	}
}
