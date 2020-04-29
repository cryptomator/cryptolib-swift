//
//  Cryptor.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation

extension Data {
	
	public init?(base64UrlEncoded base64String: String, options: Data.Base64DecodingOptions = []) {
		self.init(base64Encoded: base64String.replacingOccurrences(of: "_", with: "/").replacingOccurrences(of: "-", with: "+"), options: options)
	}
	
	public func base64UrlEncodedString(options: Data.Base64EncodingOptions = []) -> String {
		return self.base64EncodedString(options: options).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
	}
	
}

public class Cryptor {
	
	private let masterKey: Masterkey
	
	public init(masterKey: Masterkey) {
		self.masterKey = masterKey;
	}
	
	// MARK: Path Encryption and Decryption:
	
	public func encryptFileName(cleartextName: String, directoryId: Data) -> String? {
		let cleartext = [UInt8](cleartextName.precomposedStringWithCanonicalMapping.utf8)
		if let ciphertext = try? AesSiv.encrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, plaintext: cleartext, ad: directoryId.bytes) {
			return Data(ciphertext).base64UrlEncodedString()
		} else {
			return nil
		}
	}
	
	public func decryptFileName(ciphertextName: String, directoryId: Data) -> String? {
		guard let ciphertextData = Data(base64UrlEncoded: ciphertextName) else {
			debugPrint("can not decode base64 string", ciphertextName)
			return nil
		}
		
		if let cleartext = try? AesSiv.decrypt(aesKey: masterKey.aesMasterKey, macKey: masterKey.macMasterKey, ciphertext: ciphertextData.bytes, ad: directoryId.bytes) {
			return String(data: Data(cleartext), encoding: .utf8)
		} else {
			return nil
		}
	}
	
	// MARK: File Content Encryption and Decryption
	
	func encryptSingleChunk(chunkNumber: UInt64, nonce: [UInt8], cleartext: [UInt8], fileKey: [UInt8]) -> [UInt8] {
		return [UInt8](); // TODO
	}
	
	func decryptSingleChunk(chunkNumber: UInt64, nonce: [UInt8], ciphertext: [UInt8], fileKey: [UInt8]) -> [UInt8] {
		return [UInt8](); // TODO
	}
	
}
