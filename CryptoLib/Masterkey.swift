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

enum MasterkeyError: Error, Equatable {
	case malformedMasterkeyFile(_ reason: String)
	case invalidPassword
	case unwrapFailed(_ status: CCCryptorStatus)
	case wrapFailed(_ status: CCCryptorStatus)
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
	
	public static func createFromMasterkeyFile(file: URL, password: String, pepper: [UInt8] = [UInt8]())  throws -> Masterkey {
		let jsonData = try Data(contentsOf: file)
		return try createFromMasterkeyFile(jsonData: jsonData, password: password)

	}
	
	public static func createFromMasterkeyFile(jsonData: Data, password: String, pepper: [UInt8] = [UInt8]()) throws -> Masterkey {
		let jsonDecoder = JSONDecoder()
		let decoded = try jsonDecoder.decode(MasterkeyJson.self, from: jsonData)
		return try createFromMasterkeyFile(jsonData: decoded, password: password, pepper: pepper);
	}
	
	static func createFromMasterkeyFile(jsonData: MasterkeyJson, password: String, pepper: [UInt8]) throws -> Masterkey {
		let pw = [UInt8](password.precomposedStringWithCanonicalMapping.utf8)
		let salt = [UInt8](Data(base64Encoded: jsonData.scryptSalt)!)
		let saltAndPepper = salt + pepper
		let kek = try Scrypt(password: pw, salt: saltAndPepper, dkLen: kCCKeySizeAES256, N: jsonData.scryptCostParam, r: jsonData.scryptBlockSize, p: 1).calculate()
		
		guard let wrappedMasterKey = Data(base64Encoded: jsonData.primaryMasterKey) else {
			throw MasterkeyError.malformedMasterkeyFile("invalid base64 data in primaryMasterKey")
		}
		let aesKey = try unwrapMasterKey(wrappedKey: wrappedMasterKey.bytes, kek: kek)
		
		guard let wrappedHmacKey = Data(base64Encoded: jsonData.hmacMasterKey) else {
			throw MasterkeyError.malformedMasterkeyFile("invalid base64 data in hmacMasterKey")
		}
		let macKey = try unwrapMasterKey(wrappedKey: wrappedHmacKey.bytes, kek: kek)
		
		// time-constant version MAC check:
		guard let storedVersionMac = Data(base64Encoded: jsonData.versionMac), storedVersionMac.count == CC_SHA256_DIGEST_LENGTH else {
			throw MasterkeyError.malformedMasterkeyFile("invalid base64 data in versionMac")
		}
		var calculatedVersionMac = [UInt8](repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
		let versionBytes = withUnsafeBytes(of: UInt32(jsonData.version).bigEndian, Array.init)
		CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), macKey, macKey.count, versionBytes, versionBytes.count, &calculatedVersionMac)
		var diff : UInt8 = 0x00
		for i in 0..<calculatedVersionMac.count {
			diff |= calculatedVersionMac[i] ^ storedVersionMac[i]
		}
		if diff != 0x00 {
			throw MasterkeyError.malformedMasterkeyFile("incorrect version or versionMac")
		}
		
		return createFromRaw(aesMasterKey: aesKey, macMasterKey: macKey)
	}
	
	internal static func createFromRaw(aesMasterKey: [UInt8], macMasterKey: [UInt8]) -> Masterkey {
		assert(aesMasterKey.count == kCCKeySizeAES256)
		assert(macMasterKey.count == kCCKeySizeAES256)
		return Masterkey(aesMasterKey: aesMasterKey, macMasterKey: macMasterKey)
	}
	
	// MARK: -
	// MARK: RFC 3394 Key Wrapping
	
	static func wrapMasterKey(rawKey: [UInt8], kek: [UInt8]) throws -> [UInt8] {
		assert(kek.count == kCCKeySizeAES256)
		var wrapepdKeyLen = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), rawKey.count)
		var wrapepdKey = [UInt8](repeating: 0x00, count: wrapepdKeyLen);
		let status = CCSymmetricKeyWrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, rawKey, rawKey.count, &wrapepdKey, &wrapepdKeyLen)
		if status == kCCSuccess {
			return wrapepdKey
		} else {
			throw MasterkeyError.wrapFailed(status)
		}
	}
	
	static func unwrapMasterKey(wrappedKey: [UInt8], kek: [UInt8]) throws -> [UInt8] {
		assert(kek.count == kCCKeySizeAES256)
		var unwrapepdKeyLen = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrappedKey.count)
		var unwrapepdKey = [UInt8](repeating: 0x00, count: unwrapepdKeyLen);
		let status = CCSymmetricKeyUnwrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen, kek, kek.count, wrappedKey, wrappedKey.count, &unwrapepdKey, &unwrapepdKeyLen)
		if status == kCCSuccess {
			assert(unwrapepdKeyLen == kCCKeySizeAES256)
			return unwrapepdKey
		} else if status == kCCDecodeError {
			throw MasterkeyError.invalidPassword
	   } else {
			throw MasterkeyError.unwrapFailed(status)
	   }
	}

}
