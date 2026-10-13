//
//  ScriptedInputStream.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 13.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation

final class ScriptedInputStream: InputStream {
	private let bytes: [UInt8]
	private let maxReadLength: Int
	private let failingReadIndex: Int?
	private let onRead: ((Int) -> Void)?
	private var offset = 0
	private var readIndex = 0
	private var status: Stream.Status = .notOpen
	private var error: Error?

	init(bytes: [UInt8], maxReadLength: Int = .max, failingReadIndex: Int? = nil, onRead: ((Int) -> Void)? = nil) {
		self.bytes = bytes
		self.maxReadLength = maxReadLength
		self.failingReadIndex = failingReadIndex
		self.onRead = onRead
		super.init(data: Data())
	}

	override func open() {
		status = .open
	}

	override func close() {
		status = .closed
	}

	override var hasBytesAvailable: Bool {
		return status == .open && offset < bytes.count
	}

	override var streamStatus: Stream.Status {
		return status
	}

	/// `streamError` is abstract on `NSStream`, so reading it without this override raises an Objective-C exception.
	override var streamError: Error? {
		return error
	}

	override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
		let index = readIndex
		readIndex += 1
		onRead?(index)
		if index == failingReadIndex {
			status = .error
			error = POSIXError(.EIO)
			return -1
		}
		let length = min(len, maxReadLength, bytes.count - offset)
		bytes.withUnsafeBufferPointer { buffer.update(from: $0.baseAddress! + offset, count: length) }
		offset += length
		return length
	}
}
