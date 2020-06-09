//
//  CryptoError.swift
//  CryptoLib
//
//  Created by Tobias Hagemann on 09.06.20.
//  Copyright © 2020 Skymatic GmbH. All rights reserved.
//

import CommonCrypto
import Foundation

enum CryptoError: Error, Equatable {
	case invalidParameter(_ reason: String)
	case ccCryptorError(_ status: CCCryptorStatus)
	case unauthenticCiphertext
	case csprngError
	case ioError
}
