//
//  Base64.swift
//  CryptomatorCryptoLib
//
//  Created by Tobias Hagemann on 17.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation

private struct Base64Alphabet {
	static let standard = Base64Alphabet(character62: UInt8(ascii: "+"), character63: UInt8(ascii: "/"))
	static let urlSafe = Base64Alphabet(character62: UInt8(ascii: "-"), character63: UInt8(ascii: "_"))

	let character62: UInt8
	let character63: UInt8
}

public extension Data {
	/**
	 Decodes an RFC 4648 Base64URL string with the same rules as Guava's `BaseEncoding.base64Url()`.

	 - Only the URL-safe alphabet is accepted, so `+` and `/` are rejected.
	 - Any number of trailing `=` is accepted.
	 - Unused trailing bits are ignored.
	 - Lengths that cannot end on a byte boundary (1 character past a multiple of 4, excluding padding) are rejected.
	 */
	init?(base64UrlEncoded base64String: String) {
		guard let bytes = decodeBase64(base64String, alphabet: .urlSafe) else {
			return nil
		}
		self.init(bytes)
	}

	func base64UrlEncodedString() -> String {
		return base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
	}
}

extension Data {
	/**
	 Decodes an RFC 4648 Base64 string with the same rules as Guava's `BaseEncoding.base64()`.

	 The rules are those of `init?(base64UrlEncoded:)`, with the standard alphabet's `+` and `/` in place of `-` and `_`.
	 */
	init?(guavaBase64Encoded base64String: String) {
		guard let bytes = decodeBase64(base64String, alphabet: .standard) else {
			return nil
		}
		self.init(bytes)
	}
}

private func decodeBase64(_ string: String, alphabet: Base64Alphabet) -> [UInt8]? {
	var encoded = string.utf8[...]
	while encoded.last == UInt8(ascii: "=") {
		encoded = encoded.dropLast()
	}
	guard encoded.count % 4 != 1 else {
		return nil
	}
	var bytes = [UInt8]()
	bytes.reserveCapacity(encoded.count * 3 / 4)
	var buffer: UInt32 = 0
	var bitCount = 0
	for character in encoded {
		let value: UInt8
		switch character {
		case UInt8(ascii: "A") ... UInt8(ascii: "Z"):
			value = character - UInt8(ascii: "A")
		case UInt8(ascii: "a") ... UInt8(ascii: "z"):
			value = character - UInt8(ascii: "a") + 26
		case UInt8(ascii: "0") ... UInt8(ascii: "9"):
			value = character - UInt8(ascii: "0") + 52
		case alphabet.character62:
			value = 62
		case alphabet.character63:
			value = 63
		default:
			return nil
		}
		buffer = buffer << 6 | UInt32(value)
		bitCount += 6
		if bitCount >= 8 {
			bitCount -= 8
			bytes.append(UInt8(truncatingIfNeeded: buffer >> bitCount))
		}
	}
	return bytes
}
