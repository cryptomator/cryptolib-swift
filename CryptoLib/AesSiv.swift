//
//  Siv.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 29.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation
import CryptoSwift
import CommonCrypto

enum AesSivError: Error {
	case invalidParameter(_ reason: String)
	case encryptionFailedWithStatus(_ status: CCCryptorStatus)
	case unauthenticCiphertext
}

public class AesSiv {
	
	static let zero = [UInt8](repeating: 0x00, count: 16)
	static let dblConst : UInt8 = 0x87
	
	public static func encrypt(aesKey: [UInt8], macKey: [UInt8], plaintext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		if (plaintext.count > UInt32.max - 16) {
			throw AesSivError.invalidParameter("ciphertext must be at least 16 bytes")
		}
		let iv = try s2v(macKey: macKey, plaintext: plaintext, ad: ad)
		let ciphertext = try aesCtr(aesKey: aesKey, iv: iv, plaintext: plaintext)
		return iv + ciphertext
	}
	
	static func decrypt(aesKey: [UInt8], macKey: [UInt8], ciphertext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		if (ciphertext.count < 16) {
			throw AesSivError.invalidParameter("ciphertext must be at least 16 bytes")
		}
		let iv = Array(ciphertext[..<16])
		let actualCiphertext = Array(ciphertext[16...])
		let plaintext = try aesCtr(aesKey: aesKey, iv: iv, plaintext: actualCiphertext)
		let control = try s2v(macKey: macKey, plaintext: plaintext, ad: ad);
		
		// time-constant comparison
		assert(iv.count == control.count)
		var diff: UInt8 = 0
		for i in 0..<iv.count {
			diff |= iv[i] ^ control[i]
		}
		
		guard diff == 0 else {
			throw AesSivError.unauthenticCiphertext
		}

		return plaintext
	}
	
	internal static func aesCtr(aesKey: [UInt8], iv: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
		assert(aesKey.count == kCCKeySizeAES256 || aesKey.count == kCCKeySizeAES128, "aesKey expected to be 128 or 256 bit")
		
		// clear out the 31st and 63rd bit (see https://tools.ietf.org/html/rfc5297#section-2.5)
		var ctr = iv
		ctr[8] &= 0x7F
		ctr[12] &= 0x7F
		
		var cryptor: CCCryptorRef?
		var status = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), ctr, aesKey, aesKey.count, nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
		guard status == kCCSuccess, cryptor != nil else {
			throw AesSivError.invalidParameter("failed to initialize cryptor")
		}
		defer {
			CCCryptorRelease(cryptor)
		}
		
		let outlen = CCCryptorGetOutputLength(cryptor, plaintext.count, true)
		var ciphertext = [UInt8](repeating: 0x00, count: outlen)
		
		var numEncryptedBytes: Int = 0
		status = CCCryptorUpdate(cryptor, plaintext, plaintext.count, &ciphertext, ciphertext.count, &numEncryptedBytes)
		guard status == kCCSuccess else {
			throw AesSivError.encryptionFailedWithStatus(status)
		}
		
		status = CCCryptorFinal(cryptor, &ciphertext, ciphertext.count, &numEncryptedBytes)
		guard status == kCCSuccess else {
			throw AesSivError.encryptionFailedWithStatus(status)
		}
		
		return ciphertext
	}
	
	internal static func s2v(macKey: [UInt8], plaintext: [UInt8], ad: [[UInt8]]) throws -> [UInt8] {
		// Maximum permitted AD length is the block size in bits - 2
		if (ad.count > 126) {
			throw AesSivError.invalidParameter("too many ad")
		}
		
		let mac = try CMAC.init(key: macKey)
		
		// RFC 5297 defines a n == 0 case here. Where n is the length of the input vector:
		// S1 = associatedData1, S2 = associatedData2, ... Sn = plaintext
		// Since this method is invoked only by encrypt/decrypt, we always have a plaintext.
		// Thus n > 0
		
		var d = try mac.authenticate(zero)
		for s in ad {
			d = xor(dbl(d), try mac.authenticate(s))
		}
		
		let t: [UInt8]
		if (plaintext.count >= 16) {
			t = xorend(plaintext, d)
		} else {
			t = xor(dbl(d), pad(plaintext))
		}
		
		return try mac.authenticate(t)
	}
	
	private static func shiftLeft(_ input: [UInt8]) -> [UInt8] {
		var output = [UInt8](repeating: 0x00, count: input.count)
		var bit: UInt8 = 0
		for i in (0..<input.count).reversed() {
			let b = input[i] & 0xff
			output[i] = (b << 1) | bit
			bit = (b >> 7) & 1
		}
		return output
	}
	
	private static func dbl(_ block: [UInt8]) -> [UInt8] {
		var result = shiftLeft(block)
		if (block[0] & 0x80 != 0x00) {
			result[block.count - 1] ^= dblConst
		}
		return result
	}
	
	private static func xor(_ data1: [UInt8], _ data2: [UInt8]) -> [UInt8] {
		assert(data1.count <= data2.count, "Length of first input must be <= length of second input.")
		var result = [UInt8](repeating: 0x00, count: data1.count)
		for i in 0..<data1.count {
			result[i] = data1[i] ^ data2[i]
		}
		return result
	}
	
	private static func xorend(_ data1: [UInt8], _ data2: [UInt8]) -> [UInt8] {
		assert(data1.count >= data2.count, "Length of first input must be >= length of second input.")
		var result = data1
		let diff = data1.count - data2.count
		for i in 0..<data2.count {
			result[i + diff] = data1[i + diff] ^ data2[i]
		}
		return result
	}
	
	// ISO/IEC 7816-4:2005 Padding: First bit 1, following bits 0
	private static func pad(_ data: [UInt8]) -> [UInt8] {
		var result = data
		if (result.count < 16) {
			result.append(0x80)
		}
		while (result.count < 16) {
			result.append(0x00)
		}
		return result
	}
	
}
