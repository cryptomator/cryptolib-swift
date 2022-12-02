//
//  StreamTools.swift
//
//  Created by Julien Eyriès on 27/07/2022.
//  Copyright © 2022 Julien Eyriès. All rights reserved.
//

import Foundation

enum StreamTools {
	static func copyStream(inputStream: InputStream, outputStream: OutputStream) throws {
		inputStream.schedule(in: .current, forMode: .default)
		inputStream.open()
		defer { inputStream.close() }

		outputStream.schedule(in: .current, forMode: .default)
		outputStream.open()
		defer { outputStream.close() }

		var buffer = [UInt8](repeating: 0x00, count: 4096)

		while true {
			let readLength = inputStream.read(&buffer, maxLength: buffer.count)
			if let error = inputStream.streamError {
				throw error
			}
			if readLength <= 0 {
				break
			}

			let writeLength = outputStream.writeFully(buffer, maxLength: readLength)
			if let error = outputStream.streamError {
				throw error
			}
			if writeLength <= 0 {
				break
			}
		}
	}
}

extension InputStream {
	func readFully(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
		var offset = 0
		while offset < len {
			let result = read(buffer + offset, maxLength: len - offset)
			if result < 0 {
				return result
			}
			if result == 0 {
				return offset
			}
			offset += result
		}
		return len
	}

	func readFullyIntoArray(maxLength len: Int) throws -> [UInt8] {
		var buffer = [UInt8](repeating: 0, count: len)
		let result = readFully(&buffer, maxLength: len)
		if result < 0 {
			throw streamError!
		}
		return Array(buffer.prefix(result))
	}
}

extension OutputStream {
	func writeFully(_ buffer: UnsafePointer<UInt8>, maxLength len: Int) -> Int {
		var offset = 0
		while offset < len {
			let result = write(buffer + offset, maxLength: len - offset)
			if result < 0 {
				return result
			}
			if result == 0 {
				return -1
			}
			offset += result
		}
		return len
	}

	func writeFullyFromArray(_ array: [UInt8]) throws {
		let result = writeFully(array, maxLength: array.count)
		if result != array.count {
			throw streamError!
		}
	}
}
