//
//  Masterkey.swift
//  CryptoLib
//
//  Created by Sebastian Stenzel on 25.04.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import Foundation
import CryptoSwift
import CommonCrypto

struct MasterkeyJson: Codable {
    let scryptSalt: String
    let scryptCostParam: Int
    let scryptBlockSize: Int
    let primaryMasterKey: String
    let hmacMasterKey: String
    let versionMac: String
    let version: Int
}

public class Masterkey {

	private(set) var aesMasterKey: [UInt8]
	private(set) var macMasterKey: [UInt8]

	private init(aesMasterKey: [UInt8], macMasterKey: [UInt8]) {
		self.aesMasterKey = aesMasterKey
		self.macMasterKey = macMasterKey
	}
	
	deinit {
		for i in 0 ..< aesMasterKey.count {
			aesMasterKey[i] = 0
		}
		for i in 0 ..< macMasterKey.count {
			macMasterKey[i] = 0
		}
	}
	
	// MARK: -
	// MARK: Masterkey Factory Methods
	
	public static func createFromMasterkeyFile(file: URL, password: String, pepper: [UInt8] = [UInt8]()) -> Masterkey? {
		if let jsonData = try? Data(contentsOf: file) {
			return createFromMasterkeyFile(jsonData: jsonData, password: password)
		} else {
			return nil
		}
	}
	
	public static func createFromMasterkeyFile(jsonData: Data, password: String, pepper: [UInt8] = [UInt8]()) -> Masterkey? {
		let jsonDecoder = JSONDecoder()
		if let decoded = try? jsonDecoder.decode(MasterkeyJson.self, from: jsonData) {
			return createFromMasterkeyFile(jsonData: decoded, password: password, pepper: pepper);
		} else {
			return nil
		}
	}
	
	static func createFromMasterkeyFile(jsonData: MasterkeyJson, password: String, pepper: [UInt8]) -> Masterkey? {
		let pw = [UInt8](password.precomposedStringWithCanonicalMapping.utf8)
		let salt = [UInt8](Data(base64Encoded: jsonData.scryptSalt)!)
		let saltAndPepper = salt + pepper
		guard let kek = try? Scrypt(password: pw, salt: saltAndPepper, dkLen: kCCKeySizeAES256, N: jsonData.scryptCostParam, r: jsonData.scryptBlockSize, p: 1).calculate() else {
			debugPrint("scrypt failed")
			return nil;
		}
		
		let wrappedMasterKey = [UInt8](Data(base64Encoded: jsonData.primaryMasterKey)!)
		let unwrappedMasterKey = unwrapMasterKey(wrappedKey: wrappedMasterKey, kek: kek)
		
		let wrappedHmacKey = [UInt8](Data(base64Encoded: jsonData.hmacMasterKey)!)
		let unwrappedHmacKey = unwrapMasterKey(wrappedKey: wrappedHmacKey, kek: kek)
		
		if (unwrappedMasterKey != nil) && (unwrappedHmacKey != nil) {
			return createFromRaw(aesMasterKey: unwrappedMasterKey!, macMasterKey: unwrappedHmacKey!)
		} else {
			return nil
		}
	}
	
	internal static func createFromRaw(aesMasterKey: [UInt8], macMasterKey: [UInt8]) -> Masterkey {
		// TODO CMAC implementation doesn't support 256 bit keys yet -.-
		// assert(aesMasterKey.count == kCCKeySizeAES256)
		// assert(macMasterKey.count == kCCKeySizeAES256)
		return Masterkey(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}
	
	// MARK: -
	// MARK: RFC 3394 Key Wrapping
	
	static func wrapMasterKey(rawKey: [UInt8], kek: [UInt8]) -> [UInt8]? {
		assert(kek.count == kCCKeySizeAES256)
		var wrapepdKeyLen = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), rawKey.count)
		var wrapepdKey = [UInt8](repeating: 0x00, count: wrapepdKeyLen);
		let status = CCSymmetricKeyWrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, rawKey, rawKey.count, &wrapepdKey, &wrapepdKeyLen)
		if status == kCCSuccess {
			return wrapepdKey
		} else if status == kCCParamError {
			// wrong password
			return nil
		} else {
			debugPrint("unwrapping masterkey failed with status code ", status)
			return nil
		}
	}
	
	static func unwrapMasterKey(wrappedKey: [UInt8], kek: [UInt8]) -> [UInt8]? {
		assert(kek.count == kCCKeySizeAES256)
		var unwrapepdKeyLen = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count)
		var unwrapepdKey = [UInt8](repeating: 0x00, count: unwrapepdKeyLen);
		let status = CCSymmetricKeyUnwrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, wrappedKey, wrappedKey.count, &unwrapepdKey, &unwrapepdKeyLen)
		if status == kCCSuccess {
			assert(unwrapepdKeyLen == kCCKeySizeAES256)
			return unwrapepdKey
		} else if status == kCCParamError {
		   // wrong password
		   return nil
	   } else {
		   debugPrint("unwrapping masterkey failed with status code ", status)
		   return nil
	   }
	}

}
