//
//  Cryptor.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation

public class Cryptor {
	
	private let masterKey: Masterkey
	
	public init(masterKey: Masterkey) {
		self.masterKey = masterKey;
	}
	
	// MARK: Path Encryption and Decryption:
	
	public func encryptFileName(cleartextName: String, directoryId: [UInt8]) -> String {
		return ""; // TODO
	}
	
	public func decryptFileName(ciphertextName: String, directoryId: [UInt8]) -> String {
		return ""; // TODO
	}
	
	// MARK: File Content Encryption and Decryption
	
	func encryptSingleChunk(chunkNumber: UInt64, nonce: [UInt8], cleartext: [UInt8], fileKey: [UInt8]) -> [UInt8] {
		return [UInt8](); // TODO
	}
	
	func decryptSingleChunk(chunkNumber: UInt64, nonce: [UInt8], ciphertext: [UInt8], fileKey: [UInt8]) -> [UInt8] {
		return [UInt8](); // TODO
	}
	
}
