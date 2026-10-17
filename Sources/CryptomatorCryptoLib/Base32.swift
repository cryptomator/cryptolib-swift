//
//  Base32.swift
//  CryptomatorCryptoLib
//
//  Created by Tobias Hagemann on 17.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation

private let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

public extension Data {
	/**
	 Decodes an RFC 4648 Base32 string with the same rules as Guava's `BaseEncoding.base32()`.

	 - Lowercase letters are rejected.
	 - Any number of trailing `=` is accepted.
	 - Unused trailing bits are ignored.
	 - Lengths that cannot end on a byte boundary (1, 3 or 6 characters past a multiple of 8, excluding padding) are rejected.
	 */
	init?(base32Encoded base32String: String) {
		var encoded = base32String.utf8[...]
		while encoded.last == UInt8(ascii: "=") {
			encoded = encoded.dropLast()
		}
		guard ![1, 3, 6].contains(encoded.count % 8) else {
			return nil
		}
		var bytes = [UInt8]()
		bytes.reserveCapacity(encoded.count * 5 / 8)
		var buffer: UInt32 = 0
		var bitCount = 0
		for character in encoded {
			let value: UInt8
			switch character {
			case UInt8(ascii: "A") ... UInt8(ascii: "Z"):
				value = character - UInt8(ascii: "A")
			case UInt8(ascii: "2") ... UInt8(ascii: "7"):
				value = character - UInt8(ascii: "2") + 26
			default:
				return nil
			}
			buffer = buffer << 5 | UInt32(value)
			bitCount += 5
			if bitCount >= 8 {
				bitCount -= 8
				bytes.append(UInt8(truncatingIfNeeded: buffer >> bitCount))
			}
		}
		self.init(bytes)
	}

	func base32EncodedString() -> String {
		var encoded = [Character]()
		encoded.reserveCapacity((count + 4) / 5 * 8)
		var buffer: UInt32 = 0
		var bitCount = 0
		for byte in self {
			buffer = buffer << 8 | UInt32(byte)
			bitCount += 8
			while bitCount >= 5 {
				bitCount -= 5
				encoded.append(base32Alphabet[Int(buffer >> bitCount & 0x1F)])
			}
		}
		if bitCount > 0 {
			encoded.append(base32Alphabet[Int(buffer << (5 - bitCount) & 0x1F)])
		}
		while !encoded.count.isMultiple(of: 8) {
			encoded.append("=")
		}
		return String(encoded)
	}
}
