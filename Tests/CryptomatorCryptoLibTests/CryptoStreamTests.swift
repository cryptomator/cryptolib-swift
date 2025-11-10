//
//  CryptoStreamTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Julien Eyriès on 26/07/2022.
//  Copyright © 2022 Julien Eyriès. All rights reserved.
//

import XCTest
@testable import CryptomatorCryptoLib

class CryptoStreamTests: XCTestCase {
	var contentCryptor: ContentCryptor!
	var cryptor: Cryptor!
	var tmpDirURL: URL!

	override class var defaultTestSuite: XCTestSuite {
		// Return empty `XCTestSuite` so that no tests from this "abstract" `XCTestCase` is run.
		// Make sure to override this in subclasses so that the implemented test case can run.
		return XCTestSuite(name: "InterfaceTests Excluded")
	}

	func setUpWithError(masterkey: Masterkey, cryptoSupport: CryptoSupport, contentCryptor: ContentCryptor) throws {
		self.contentCryptor = contentCryptor
		cryptor = Cryptor(masterkey: masterkey, cryptoSupport: cryptoSupport, contentCryptor: contentCryptor)
		tmpDirURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
		try FileManager.default.createDirectory(at: tmpDirURL, withIntermediateDirectories: true)
	}

	override func tearDownWithError() throws {
		try FileManager.default.removeItem(at: tmpDirURL)
	}

	func testEncryptAndDecryptStream() throws {
		let cleartext = [UInt8]("hello world".data(using: .ascii)!)

		let encryptedStream = OutputStream.toMemory()
		try StreamTools.copyStream(inputStream: InputStream(data: Data(cleartext)),
		                           outputStream: cryptor.encryptOutputStream(wrapped: encryptedStream))

		guard let encryptedData = encryptedStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else { fatalError() }

		let decryptedStream = OutputStream.toMemory()
		try StreamTools.copyStream(inputStream: cryptor.decryptInputStream(wrapped: InputStream(data: encryptedData)),
		                           outputStream: decryptedStream)

		guard let decryptedData = decryptedStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else { fatalError() }

		let decrypted = [UInt8](decryptedData)
		XCTAssertEqual(cleartext, decrypted)
	}

	func testEncryptAndDecryptContentStream() throws {
		let originalData = Data(repeating: 0x0F, count: 65 * 1024)
		let originalURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		try originalData.write(to: originalURL)

		let ciphertextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)
		let cleartextURL = tmpDirURL.appendingPathComponent(UUID().uuidString, isDirectory: false)

		// encrypt content
		try StreamTools.copyStream(inputStream: InputStream(url: originalURL)!,
		                           outputStream: cryptor.encryptOutputStream(wrapped: OutputStream(url: ciphertextURL, append: false)!))

		// decrypt content
		try StreamTools.copyStream(inputStream: cryptor.decryptInputStream(wrapped: InputStream(url: ciphertextURL)!),
		                           outputStream: OutputStream(url: cleartextURL, append: false)!)

		let cleartextData = try Data(contentsOf: cleartextURL)
		XCTAssertEqual(originalData, cleartextData)
	}
}
