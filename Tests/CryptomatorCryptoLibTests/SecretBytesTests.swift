//
//  SecretBytesTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 16.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation
import Testing
@testable import CryptomatorCryptoLib

struct SecretBytesTests {
	@Test func `deinit wipes before deallocating`() {
		let recorder = DeallocationRecorder()
		do {
			var secret = SecretBytes(count: 32, deallocator: { recorder.deallocate($0) })
			secret.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0xAA) }
		}
		#expect(recorder.wipedDeallocations == [true])
	}

	@Test func `deinit wipes when a throw unwinds`() {
		let recorder = DeallocationRecorder()
		#expect(throws: CryptoError.ioError) { try createSecretAndThrow(recorder: recorder) }
		#expect(recorder.wipedDeallocations == [true])
	}

	@Test func `copying does not share source storage`() {
		let source = [UInt8](repeating: 0xAA, count: 32)
		let secret = SecretBytes(copying: source)
		let sharesStorage = source.withUnsafeBytes { sourceBytes in
			secret.withUnsafeBytes { $0.baseAddress == sourceBytes.baseAddress }
		}
		#expect(!sharesStorage)
	}

	private func createSecretAndThrow(recorder: DeallocationRecorder) throws {
		var secret = SecretBytes(count: 32, deallocator: { recorder.deallocate($0) })
		secret.withUnsafeMutableBytes { _ = $0.initializeMemory(as: UInt8.self, repeating: 0xAA) }
		throw CryptoError.ioError
	}
}

private final class DeallocationRecorder: @unchecked Sendable {
	// `@unchecked Sendable` is safe because `lock` guards `deallocations`.

	private let lock = NSLock()
	private var deallocations = [Bool]()

	/// One element per deallocation, telling whether the deallocated buffer was all zeros.
	var wipedDeallocations: [Bool] {
		lock.lock()
		defer { lock.unlock() }
		return deallocations
	}

	func deallocate(_ buffer: UnsafeMutableRawBufferPointer) {
		let isWiped = buffer.allSatisfy { $0 == 0x00 }
		lock.lock()
		defer { lock.unlock() }
		deallocations.append(isWiped)
		buffer.deallocate()
	}
}
