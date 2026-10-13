//
//  ScriptedOutputStream.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 13.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import Foundation

final class ScriptedOutputStream: OutputStream {
	private(set) var bytes: [UInt8] = []
	private let maxWriteLength: Int
	private var status: Stream.Status = .notOpen

	init(maxWriteLength: Int = .max) {
		self.maxWriteLength = maxWriteLength
		super.init(toMemory: ())
	}

	override func open() {
		status = .open
	}

	override func close() {
		status = .closed
	}

	override var hasSpaceAvailable: Bool {
		return status == .open
	}

	override var streamStatus: Stream.Status {
		return status
	}

	/// `streamError` is abstract on `NSStream`, so reading it without this override raises an Objective-C exception.
	override var streamError: Error? {
		return nil
	}

	override func write(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
		let length = min(len, maxWriteLength)
		bytes.append(contentsOf: UnsafeBufferPointer(start: buffer, count: length))
		return length
	}
}
