//
//  Base64Tests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 17.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation
import Testing
@testable import CryptomatorCryptoLib

struct Base64Tests {
	/// test vectors from https://www.rfc-editor.org/rfc/rfc4648#section-10
	static let vectors = [
		("", ""),
		("f", "Zg=="),
		("fo", "Zm8="),
		("foo", "Zm9v"),
		("foob", "Zm9vYg=="),
		("fooba", "Zm9vYmE="),
		("foobar", "Zm9vYmFy")
	]

	@Test(arguments: vectors) func encode(plaintext: String, encoded: String) {
		#expect(Data(plaintext.utf8).base64UrlEncodedString() == encoded)
	}

	@Test(arguments: vectors) func decode(plaintext: String, encoded: String) {
		#expect(Data(base64UrlEncoded: encoded) == Data(plaintext.utf8))
		#expect(Data(guavaBase64Encoded: encoded) == Data(plaintext.utf8))
	}

	@Test func `encode and decode alphabet`() {
		let data = Data([0xFB, 0xFF])
		#expect(data.base64UrlEncodedString() == "-_8=")
		#expect(Data(base64UrlEncoded: "-_8=") == data)
		#expect(Data(guavaBase64Encoded: "+/8=") == data)
	}

	@Test(arguments: ["+/8=", "Zm+/", "Zm8/"]) func `decode url safe rejects standard alphabet`(encoded: String) {
		#expect(Data(base64UrlEncoded: encoded) == nil)
	}

	@Test(arguments: ["-_8=", "Zm-_", "Zm8_"]) func `decode standard rejects url safe alphabet`(encoded: String) {
		#expect(Data(guavaBase64Encoded: encoded) == nil)
	}

	@Test func `decode every byte value`() {
		let data = Data(0 ... 255)
		#expect(Data(base64UrlEncoded: data.base64UrlEncodedString()) == data)
		#expect(Data(guavaBase64Encoded: data.base64EncodedString()) == data)
	}

	@Test(arguments: [
		("Zm8", "fo"),
		("Zm8==", "fo"),
		("Zm9=", "fo"),
		("Zg", "f"),
		("Zg=", "f"),
		("Zg======", "f")
	]) func `decode lenient padding and trailing bits`(encoded: String, plaintext: String) {
		#expect(Data(base64UrlEncoded: encoded) == Data(plaintext.utf8))
		#expect(Data(guavaBase64Encoded: encoded) == Data(plaintext.utf8))
	}

	@Test(arguments: ["=", "==", "====", "========"]) func `decode padding only`(encoded: String) {
		#expect(Data(base64UrlEncoded: encoded) == Data())
		#expect(Data(guavaBase64Encoded: encoded) == Data())
	}

	@Test(arguments: [
		"Z",
		"Zm9vY",
		"Zm9vY===",
		"Zm 8",
		"Zm8\n",
		"Zm\n8=",
		"Zg==Zg==",
		"Z=g=",
		"Zm8.",
		"Zm8%",
		"Zm8@",
		"Zm8[",
		"Zm8`",
		"Zm8{",
		"Zm8:",
		"Zé8=",
		"\u{FF3A}m=="
	]) func `decode rejects invalid input`(encoded: String) {
		#expect(Data(base64UrlEncoded: encoded) == nil)
		#expect(Data(guavaBase64Encoded: encoded) == nil)
	}
}
