//
//  SecretBytes.swift
//  CryptomatorCryptoLib
//
//  Created by Tobias Hagemann on 16.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation

/**
 Overwrites a buffer with zeros in a way the compiler cannot optimize away.
 */
func secureZero(_ buffer: UnsafeMutableRawBufferPointer) {
	guard let baseAddress = buffer.baseAddress, !buffer.isEmpty else {
		return
	}
	_ = memset_s(baseAddress, buffer.count, 0, buffer.count)
}

/**
 The single owner of secret bytes, such as key material.

 The bytes are lent out through `borrowing` parameters and `withUnsafeBytes` instead of being copied. They are wiped before their memory is deallocated.
 */
struct SecretBytes: ~Copyable, @unchecked Sendable {
	// `@unchecked Sendable` is safe because the bytes are written only during construction, through `mutating` access, and in `deinit`, all of which need exclusive ownership. Lent pointers must not escape their closures, and the stored deallocator is `@Sendable`.

	private let storage: UnsafeMutableRawBufferPointer
	private let deallocator: @Sendable (UnsafeMutableRawBufferPointer) -> Void
	let count: Int

	/**
	 Creates zero-filled secret bytes.
	 */
	init(count: Int) {
		self.init(count: count, initializingWith: { _ in })
	}

	/**
	 Creates secret bytes that `body` fills in, starting from zeros. If `body` throws, the bytes are wiped and deallocated before the error propagates.

	 - Parameter deallocator: Receives the whole allocation after it has been wiped. The allocation may be larger than `count`. Lets tests observe the wipe.
	 */
	init<E: Error>(count: Int, deallocator: @escaping @Sendable (UnsafeMutableRawBufferPointer) -> Void = { $0.deallocate() }, initializingWith body: (UnsafeMutableRawBufferPointer) throws(E) -> Void) throws(E) {
		// at least one byte, so that C functions never receive a nil pointer, even for empty secrets:
		self.storage = .allocate(byteCount: max(count, 1), alignment: MemoryLayout<UInt8>.alignment)
		storage.initializeMemory(as: UInt8.self, repeating: 0x00)
		self.deallocator = deallocator
		self.count = count
		try withUnsafeMutableBytes(body)
	}

	/**
	 Creates secret bytes from a copy of `bytes`, without retaining them.
	 */
	init(copying bytes: some Collection<UInt8>) {
		self.init(count: bytes.count) { $0.copyBytes(from: bytes) }
	}

	deinit {
		secureZero(storage)
		deallocator(storage)
	}

	func withUnsafeBytes<R: ~Copyable, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
		return try body(UnsafeRawBufferPointer(rebasing: storage[0 ..< count]))
	}

	mutating func withUnsafeMutableBytes<R: ~Copyable, E: Error>(_ body: (UnsafeMutableRawBufferPointer) throws(E) -> R) throws(E) -> R {
		return try body(UnsafeMutableRawBufferPointer(rebasing: storage[0 ..< count]))
	}

	/**
	 Copies the bytes into an array that the caller owns. Use it only for bytes that leave the library or are not secret, since the array cannot be wiped.
	 */
	func exportBytes() -> [UInt8] {
		return withUnsafeBytes { [UInt8]($0) }
	}
}
