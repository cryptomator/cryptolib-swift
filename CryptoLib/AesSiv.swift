//
//  Siv.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 29.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation
import CryptoSwift

enum AesSivError: Error {
	case invalidParameter(_ reason: String)
}

public class AesSiv {
	
	static let zero = [UInt8](repeating: 0x00, count: 16)
	static let dblConst : UInt8 = 0x87
	
	internal static func s2v(macKey: [UInt8], plaintext: [UInt8], ad: [UInt8]...) throws -> [UInt8] {
		// Maximum permitted AD length is the block size in bits - 2
		if (ad.count > 126) {
			throw  AesSivError.invalidParameter("too many ad")
		}
		
		guard let mac = try? CMAC.init(key: macKey) else {
			throw AesSivError.invalidParameter("invalid macKey")
		}
		
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
	
	// ISO7816d4: First bit 1, following bits 0.
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
