//
//  Base32Tests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 17.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation
import Testing
@testable import CryptomatorCryptoLib

struct Base32Tests {
	/// test vectors from https://www.rfc-editor.org/rfc/rfc4648#section-10
	static let vectors = [
		("", ""),
		("f", "MY======"),
		("fo", "MZXQ===="),
		("foo", "MZXW6==="),
		("foob", "MZXW6YQ="),
		("fooba", "MZXW6YTB"),
		("foobar", "MZXW6YTBOI======")
	]

	@Test(arguments: vectors) func encode(plaintext: String, encoded: String) {
		#expect(Data(plaintext.utf8).base32EncodedString() == encoded)
	}

	@Test(arguments: vectors) func decode(plaintext: String, encoded: String) {
		#expect(Data(base32Encoded: encoded) == Data(plaintext.utf8))
	}

	@Test func `decode every byte value`() {
		let data = Data(0 ... 255)
		#expect(Data(base32Encoded: data.base32EncodedString()) == data)
	}

	@Test(arguments: ["MZXW6", "MZXW6=", "MZXW6==========", "MZXW7==="]) func `decode lenient padding and trailing bits`(encoded: String) {
		#expect(Data(base32Encoded: encoded) == Data("foo".utf8))
	}

	@Test(arguments: ["=", "========"]) func `decode padding only`(encoded: String) {
		#expect(Data(base32Encoded: encoded) == Data())
	}

	@Test(arguments: [
		"mzxw6===",
		"MZXW1===",
		"MZXW8===",
		"MZXW9===",
		"MZXW@===",
		"MZXW[===",
		"MZXW\u{FF39}===",
		"MZ W6===",
		"MZX=6===",
		"M",
		"MZX",
		"MZXW6Y",
		"MZXW6YTBO",
		"M======="
	]) func `decode rejects invalid input`(encoded: String) {
		#expect(Data(base32Encoded: encoded) == nil)
	}
}
