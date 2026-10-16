//
//  CryptorTestSupport.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 15.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

@testable import CryptomatorCryptoLib

extension Masterkey {
	static let test = Masterkey.createFromRaw(aesMasterKey: SecretBytes(copying: [UInt8](repeating: 0x55, count: 32)), macMasterKey: SecretBytes(copying: [UInt8](repeating: 0x77, count: 32)))
}

extension CryptorScheme {
	func makeCryptor() -> Cryptor {
		return Cryptor(masterkey: .test, scheme: self, cryptoSupport: CryptoSupportMock())
	}
}
