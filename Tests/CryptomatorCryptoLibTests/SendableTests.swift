//
//  SendableTests.swift
//  CryptomatorCryptoLibTests
//
//  Created by Tobias Hagemann on 13.10.26.
//  Copyright © 2026 Skymatic GmbH. All rights reserved.
//

import CryptomatorCryptoLib
import Foundation
import Testing

struct SendableTests {
	@Test func `public types are sendable`() {
		assertSendable(Cryptor.self)
		assertSendable(Masterkey.self)
		assertSendable(MasterkeyFile.self)
		assertSendable(CryptorScheme.self)
		assertSendable(FileNameEncoding.self)
	}
}

private func assertSendable(_: (some Sendable).Type) {}

/// Never invoked: compiles only if the content APIs can be awaited from an actor-isolated context.
@MainActor
private func awaitContentCryptoFromMainActor(cryptor: Cryptor, url: URL, progress: Progress) async throws {
	try await cryptor.encryptContent(from: url, to: url, progress: progress)
	try await cryptor.decryptContent(from: url, to: url, progress: progress)
}
